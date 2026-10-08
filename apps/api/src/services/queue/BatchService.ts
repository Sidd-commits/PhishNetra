import { prisma } from '../../db/prisma';
import { BatchJobResponse, BatchJobRequest, BatchItemResult, RiskLevel, ThreatVerdict } from '@phishnetra/shared';
import { analysisQueue } from './AsyncAnalysisQueue';
import { BatchItemTask } from './types';

export class BatchService {
  /**
   * Parses various raw URL input formats (array, newline-delimited, CSV).
   */
  public parseUrls(input: string[] | string): string[] {
    let rawList: string[] = [];

    if (Array.isArray(input)) {
      rawList = input;
    } else if (typeof input === 'string') {
      // Split by newlines, commas, or semicolons
      rawList = input.split(/[\r\n,;]+/);
    }

    const cleaned = rawList
      .map((u) => u.trim())
      .filter((u) => u.length > 0 && !u.startsWith('#') && u.toLowerCase() !== 'url');

    // Deduplicate while preserving order
    return Array.from(new Set(cleaned));
  }

  /**
   * Creates a new Batch Job, records initial items in the DB, and enqueues tasks.
   */
  public async createBatchJob(
    userId: string | null,
    payload: BatchJobRequest
  ): Promise<BatchJobResponse> {
    const urls = this.parseUrls(payload.urls);

    if (urls.length === 0) {
      throw new Error('No valid URLs provided in batch submission.');
    }

    if (urls.length > 500) {
      throw new Error('Batch submissions are capped at 500 URLs per request.');
    }

    // 1. Create BatchJob in DB
    const batchJob = await prisma.batchJob.create({
      data: {
        userId,
        status: 'QUEUED',
        totalUrls: urls.length,
        processedUrls: 0,
        includePageAnalysis: payload.includePageAnalysis || false
      }
    });

    // 2. Create BatchItem rows in DB
    const itemRecords = await Promise.all(
      urls.map((url) =>
        prisma.batchItem.create({
          data: {
            batchJobId: batchJob.id,
            url,
            status: 'QUEUED'
          }
        })
      )
    );

    // 3. Prepare worker tasks
    const tasks: BatchItemTask[] = itemRecords.map((item: any) => ({
      itemId: item.id,
      batchJobId: batchJob.id,
      url: item.url,
      includePageAnalysis: payload.includePageAnalysis || false
    }));

    // 4. Enqueue into async worker pool
    analysisQueue.enqueueBatch(tasks);

    return this.formatBatchResponse(batchJob, itemRecords);
  }

  /**
   * Retrieves full status and item breakdown for a batch job.
   */
  public async getBatchJob(jobId: string): Promise<BatchJobResponse | null> {
    const job = await prisma.batchJob.findUnique({
      where: { id: jobId },
      include: {
        items: {
          orderBy: { createdAt: 'asc' }
        }
      }
    });

    if (!job) return null;

    return this.formatBatchResponse(job, job.items);
  }

  /**
   * Lists batch jobs with pagination.
   */
  public async listBatchJobs(userId?: string, limit = 20, offset = 0) {
    const where = userId ? { userId } : {};

    const [jobs, total] = await Promise.all([
      prisma.batchJob.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: limit,
        skip: offset,
        include: {
          items: {
            take: 5
          }
        }
      }),
      prisma.batchJob.count({ where })
    ]);

    return {
      total,
      limit,
      offset,
      jobs: jobs.map((job: any) => this.formatBatchResponse(job, job.items))
    };
  }

  /**
   * Cancels a pending batch job.
   */
  public async cancelBatchJob(jobId: string): Promise<boolean> {
    const job = await prisma.batchJob.findUnique({
      where: { id: jobId }
    });

    if (!job) return false;

    // Remove from queue
    analysisQueue.cancelBatchJob(jobId);

    // Mark pending items as FAILED with cancelled notice
    await prisma.batchItem.updateMany({
      where: {
        batchJobId: jobId,
        status: { in: ['QUEUED', 'RUNNING'] }
      },
      data: {
        status: 'FAILED',
        errorMessage: 'Cancelled by user/analyst'
      }
    });

    await prisma.batchJob.update({
      where: { id: jobId },
      data: {
        status: 'CANCELLED',
        completedAt: new Date()
      }
    });

    return true;
  }

  /**
   * Exports batch items to CSV or JSON string format.
   */
  public async exportBatchJob(jobId: string, format: 'csv' | 'json'): Promise<{ contentType: string; data: string; filename: string }> {
    const job = await this.getBatchJob(jobId);
    if (!job) {
      throw new Error('Batch job not found');
    }

    if (format === 'json') {
      return {
        contentType: 'application/json',
        data: JSON.stringify(job, null, 2),
        filename: `phishnetra_batch_${jobId.slice(0, 8)}.json`
      };
    }

    // CSV format
    const headers = ['URL', 'Status', 'Verdict', 'Risk Score', 'Confidence', 'Analysis ID', 'Error'];
    const rows = (job.items || []).map((item) => [
      `"${item.url.replace(/"/g, '""')}"`,
      item.status,
      item.verdict || 'N/A',
      item.riskScore !== null && item.riskScore !== undefined ? item.riskScore : 'N/A',
      item.confidence !== null && item.confidence !== undefined ? item.confidence : 'N/A',
      item.analysisId || 'N/A',
      `"${(item.errorMessage || '').replace(/"/g, '""')}"`
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');

    return {
      contentType: 'text/csv',
      data: csvContent,
      filename: `phishnetra_batch_${jobId.slice(0, 8)}.csv`
    };
  }

  private formatBatchResponse(job: any, items?: any[]): BatchJobResponse {
    const total = job.totalUrls || (items ? items.length : 0);
    const processed = job.processedUrls || 0;
    const progressPercent = total > 0 ? Number(((processed / total) * 100).toFixed(1)) : 100;

    const formattedItems: BatchItemResult[] = (items || []).map((item) => {
      let riskLevel: RiskLevel | null = null;
      if (typeof item.riskScore === 'number') {
        if (item.riskScore >= 80) riskLevel = 'CRITICAL';
        else if (item.riskScore >= 60) riskLevel = 'HIGH';
        else if (item.riskScore >= 30) riskLevel = 'MEDIUM';
        else riskLevel = 'LOW';
      }

      return {
        id: item.id,
        batchJobId: item.batchJobId,
        url: item.url,
        normalizedUrl: item.normalizedUrl,
        status: item.status as any,
        riskScore: item.riskScore,
        verdict: item.verdict as ThreatVerdict,
        riskLevel,
        confidence: item.confidence,
        errorMessage: item.errorMessage,
        analysisId: item.analysisId,
        createdAt: item.createdAt.toISOString ? item.createdAt.toISOString() : String(item.createdAt),
        updatedAt: item.updatedAt?.toISOString ? item.updatedAt.toISOString() : undefined
      };
    });

    return {
      id: job.id,
      userId: job.userId,
      status: job.status as any,
      totalUrls: total,
      processedUrls: processed,
      safeCount: job.safeCount || 0,
      suspiciousCount: job.suspiciousCount || 0,
      phishingCount: job.phishingCount || 0,
      failedCount: job.failedCount || 0,
      avgRiskScore: job.avgRiskScore || 0,
      progressPercent,
      includePageAnalysis: job.includePageAnalysis || false,
      createdAt: job.createdAt.toISOString ? job.createdAt.toISOString() : String(job.createdAt),
      updatedAt: job.updatedAt.toISOString ? job.updatedAt.toISOString() : String(job.updatedAt),
      completedAt: job.completedAt ? (job.completedAt.toISOString ? job.completedAt.toISOString() : String(job.completedAt)) : null,
      items: formattedItems
    };
  }
}

export const batchService = new BatchService();
