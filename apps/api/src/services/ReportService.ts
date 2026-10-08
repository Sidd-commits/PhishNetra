import { prisma } from '../db/prisma';
import {
  CreateReportRequest,
  ReportModerationRequest,
  CommunityReport,
  ReportStatus,
  ReportType
} from '@phishnetra/shared';

export class ReportService {
  /**
   * Submits a new threat or false positive report.
   */
  public async createReport(
    userId: string | null,
    userName: string | null,
    payload: CreateReportRequest
  ): Promise<CommunityReport> {
    let domain = payload.domain;
    if (!domain) {
      try {
        const parsed = new URL(payload.url.startsWith('http') ? payload.url : `http://${payload.url}`);
        domain = parsed.hostname.toLowerCase();
      } catch {
        domain = payload.url.toLowerCase();
      }
    }

    const report = await prisma.communityReport.create({
      data: {
        userId,
        userName: userName || 'Anonymous Reporter',
        domain,
        url: payload.url,
        reportType: payload.reportType,
        description: payload.description,
        evidenceDetails: payload.evidenceDetails || null,
        status: 'PENDING'
      }
    });

    return this.formatReport(report);
  }

  /**
   * Lists reports with filtering and pagination.
   */
  public async listReports(options: {
    status?: ReportStatus;
    reportType?: ReportType;
    domain?: string;
    limit?: number;
    offset?: number;
  }) {
    const { status, reportType, domain, limit = 50, offset = 0 } = options;

    const where: any = {};
    if (status) where.status = status;
    if (reportType) where.reportType = reportType;
    if (domain) where.domain = { contains: domain.toLowerCase() };

    const [reports, total] = await Promise.all([
      prisma.communityReport.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset
      }),
      prisma.communityReport.count({ where })
    ]);

    return {
      total,
      limit,
      offset,
      reports: reports.map((r: any) => this.formatReport(r))
    };
  }

  /**
   * Retrieves single report by ID.
   */
  public async getReport(id: string): Promise<CommunityReport | null> {
    const report = await prisma.communityReport.findUnique({
      where: { id }
    });

    if (!report) return null;
    return this.formatReport(report);
  }

  /**
   * Moderates a report (Approve / Reject / Resolve) - analyst / admin only.
   */
  public async moderateReport(
    id: string,
    moderatorName: string,
    payload: ReportModerationRequest
  ): Promise<CommunityReport> {
    const report = await prisma.communityReport.update({
      where: { id },
      data: {
        status: payload.status,
        moderatorNotes: payload.moderatorNotes || null,
        moderatedBy: moderatorName,
        updatedAt: new Date()
      }
    });

    return this.formatReport(report);
  }

  /**
   * Retrieves approved reports aggregate for domain risk adjustment.
   */
  public async getDomainCommunitySignals(domain: string) {
    const cleanDomain = domain.toLowerCase();
    const approvedReports = await prisma.communityReport.findMany({
      where: {
        domain: { contains: cleanDomain },
        status: 'APPROVED'
      },
      take: 20
    });

    const phishingCount = approvedReports.filter((r: any) => r.reportType === 'PHISHING' || r.reportType === 'CREDENTIAL_HARVEST').length;
    const falsePositiveCount = approvedReports.filter((r: any) => r.reportType === 'FALSE_POSITIVE').length;

    return {
      totalApproved: approvedReports.length,
      phishingCount,
      falsePositiveCount,
      hasConfirmedPhishing: phishingCount > 0,
      reports: approvedReports.map((r: any) => this.formatReport(r))
    };
  }

  private formatReport(r: any): CommunityReport {
    return {
      id: r.id,
      userId: r.userId,
      userName: r.userName,
      domain: r.domain,
      url: r.url,
      reportType: r.reportType as ReportType,
      description: r.description,
      evidenceDetails: r.evidenceDetails,
      status: r.status as ReportStatus,
      moderatorNotes: r.moderatorNotes,
      moderatedBy: r.moderatedBy,
      createdAt: r.createdAt.toISOString ? r.createdAt.toISOString() : String(r.createdAt),
      updatedAt: r.updatedAt.toISOString ? r.updatedAt.toISOString() : String(r.updatedAt)
    };
  }
}

export const reportService = new ReportService();
