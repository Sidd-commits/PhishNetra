import crypto from 'crypto';
import {
  TakedownNotice,
  CreateTakedownRequest,
  TakedownNoticeType,
  TakedownStatus
} from '@phishnetra/shared';
import { auditLogService } from '../audit/AuditLogService';

export class TakedownService {
  private notices: Map<string, TakedownNotice> = new Map();

  constructor() {
    this.seedInitialNotices();
  }

  private seedInitialNotices(): void {
    const seed1: TakedownNotice = {
      id: 'tkd_101',
      targetUrl: 'https://login.microsoftonline.com-auth-verify.security-update.internal/auth/login',
      targetDomain: 'security-update.internal',
      targetBrand: 'Microsoft',
      noticeType: 'RFC2142_ABUSE_NOTICE',
      status: 'DISPATCHED',
      recipientEmail: 'abuse@registrar-security.net',
      recipientEntity: 'Security Registrar Abuse Desk (RFC 2142)',
      subject: '[URGENT - RFC 2142] Active Phishing & Credential Harvesting Domain: security-update.internal',
      bodyText: this.buildNoticeBody(
        'security-update.internal',
        'https://login.microsoftonline.com-auth-verify.security-update.internal/auth/login',
        'Microsoft',
        'RFC2142_ABUSE_NOTICE',
        'TKD-MSFT-883921'
      ),
      evidenceSummary: [
        'Layer 8 Brand Impersonation: Microsoft visual credentials clone',
        'Layer 7 Cross-Origin POST to external harvest endpoint',
        'Zero-Trust Override: Intercepted in <45ms'
      ],
      trackingNumber: 'TKD-MSFT-883921',
      submittedBy: 'sec-analyst@enterprise.internal',
      dispatchedAt: new Date(Date.now() - 3600000).toISOString(),
      resolvedAt: null,
      createdAt: new Date(Date.now() - 7200000).toISOString(),
      updatedAt: new Date(Date.now() - 3600000).toISOString()
    };

    const seed2: TakedownNotice = {
      id: 'tkd_102',
      targetUrl: 'https://xn--paypl-qqa.com/invoice/pay?ref=urgent_transfer',
      targetDomain: 'xn--paypl-qqa.com',
      targetBrand: 'PayPal',
      noticeType: 'TRADEMARK_INFRINGEMENT',
      status: 'DOMAIN_SUSPENDED',
      recipientEmail: 'abuse@domain-registrar-network.com',
      recipientEntity: 'Registrar Legal & Compliance Office',
      subject: '[FORMAL NOTICE] Immediate Suspension of Infringing Punycode Homoglyph: xn--paypl-qqa.com',
      bodyText: this.buildNoticeBody(
        'xn--paypl-qqa.com',
        'https://xn--paypl-qqa.com/invoice/pay?ref=urgent_transfer',
        'PayPal',
        'TRADEMARK_INFRINGEMENT',
        'TKD-PYPL-449102'
      ),
      evidenceSummary: [
        'Unicode Cyrillic Homoglyph confusable character substitution',
        'Unauthorized PayPal brand asset reproduction',
        'Fraudulent wire transfer and invoice phishing lure'
      ],
      trackingNumber: 'TKD-PYPL-449102',
      submittedBy: 'soc-lead@enterprise.internal',
      dispatchedAt: new Date(Date.now() - 86400000).toISOString(),
      resolvedAt: new Date(Date.now() - 12000000).toISOString(),
      createdAt: new Date(Date.now() - 90000000).toISOString(),
      updatedAt: new Date(Date.now() - 12000000).toISOString()
    };

    this.notices.set(seed1.id, seed1);
    this.notices.set(seed2.id, seed2);
  }

  public async listNotices(status?: string): Promise<TakedownNotice[]> {
    const list = Array.from(this.notices.values());
    if (status && status.trim()) {
      return list.filter(n => n.status === status);
    }
    return list.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  public async getNoticeById(id: string): Promise<TakedownNotice | null> {
    return this.notices.get(id) || null;
  }

  public async createTakedownNotice(
    req: CreateTakedownRequest,
    actor = 'soc_analyst'
  ): Promise<TakedownNotice> {
    const id = `tkd_${Date.now()}`;
    const domain = this.extractDomain(req.targetUrl);
    const brand = req.targetBrand || 'Target Organization';
    const trackingNumber = `TKD-${brand.slice(0, 4).toUpperCase()}-${Math.floor(100000 + Math.random() * 900000)}`;
    const recipientEmail = `abuse@${domain}`;
    const recipientEntity = `${domain} Registrar Abuse Operations`;

    const bodyText = this.buildNoticeBody(
      domain,
      req.targetUrl,
      brand,
      req.noticeType,
      trackingNumber,
      req.customNotes
    );

    const evidenceSummary = [
      `Multi-layer Zero-Trust signal verified on ${new Date().toISOString().split('T')[0]}`,
      `Brand consistency violation against ${brand}`,
      `Immediate BIND9 RPZ sinkhole & firewall mitigation requested`
    ];

    const notice: TakedownNotice = {
      id,
      targetUrl: req.targetUrl,
      targetDomain: domain,
      targetBrand: req.targetBrand || null,
      noticeType: req.noticeType,
      status: req.autoDispatch ? 'DISPATCHED' : 'DRAFTED',
      recipientEmail,
      recipientEntity,
      subject: `[ABUSE COMPLAINT - ${req.noticeType}] Phishing Domain Notification: ${domain}`,
      bodyText,
      evidenceSummary,
      trackingNumber,
      submittedBy: actor,
      dispatchedAt: req.autoDispatch ? new Date().toISOString() : null,
      resolvedAt: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    this.notices.set(id, notice);

    auditLogService.log({
      actor,
      action: 'TAKEDOWN_NOTICE_CREATED',
      category: 'SECURITY',
      severity: 'WARNING',
      target: domain,
      details: `Generated legal takedown notice ${trackingNumber} (${req.noticeType}) targeting ${domain}`
    });

    return notice;
  }

  public async updateNoticeStatus(
    id: string,
    status: TakedownStatus,
    actor = 'soc_analyst'
  ): Promise<TakedownNotice | null> {
    const notice = this.notices.get(id);
    if (!notice) return null;

    notice.status = status;
    notice.updatedAt = new Date().toISOString();
    if (status === 'DISPATCHED' && !notice.dispatchedAt) {
      notice.dispatchedAt = new Date().toISOString();
    }
    if (status === 'DOMAIN_SUSPENDED' || status === 'REJECTED') {
      notice.resolvedAt = new Date().toISOString();
    }

    this.notices.set(id, notice);

    auditLogService.log({
      actor,
      action: 'TAKEDOWN_STATUS_UPDATED',
      category: 'SECURITY',
      severity: 'INFO',
      target: notice.targetDomain,
      details: `Updated takedown notice ${notice.trackingNumber} status to ${status}`
    });

    return notice;
  }

  private extractDomain(urlStr: string): string {
    try {
      const parsed = new URL(urlStr.startsWith('http') ? urlStr : `http://${urlStr}`);
      return parsed.hostname;
    } catch {
      return urlStr.split('/')[0];
    }
  }

  private buildNoticeBody(
    domain: string,
    url: string,
    brand: string,
    noticeType: TakedownNoticeType,
    trackingNumber: string,
    notes?: string
  ): string {
    return `ATTN: Registrar Abuse Contact / Network Operations Center
RFC 2142 Abuse Mailbox & Legal Compliance Department

Tracking Number: ${trackingNumber}
Notice Type: ${noticeType}
Date: ${new Date().toUTCString()}

Dear Abuse Team,

This automated notice is transmitted by the PhishNetra Zero-Trust Threat Intelligence Platform on behalf of authorized security operations personnel.

We have detected active, high-confidence credential theft and phishing operations hosted under your authority on the following asset:

Target Domain: ${domain}
Infringing URL: ${url}
Targeted Entity / Brand: ${brand}

FORENSIC EVIDENCE & VIOLATION SUMMARY:
1. The specified hostname is actively imitating the brand identity and authentication portals of ${brand}.
2. Credential harvesting forms have been identified transmitting sensitive user authentication tokens to unauthorized external hosts.
3. This domain operates in direct violation of ICANN Registrar Accreditation Agreements, the Anti-Phishing Working Group (APWG) guidelines, and applicable international cybersecurity laws.

REQUESTED REMEDIATION ACTIONS:
- Immediate DNS suspension (ClientHold / ServerHold status) of the domain ${domain}.
- Null-routing / sinkholing of upstream nameserver and A/AAAA records.
- Notification to the domain registrant regarding terms-of-service violations.

${notes ? `ADDITIONAL ANALYST NOTES:\n${notes}\n` : ''}
Please confirm receipt of this notice and provide ticket confirmation referencing Tracking Number ${trackingNumber}.

Sincerely,
PhishNetra Autonomous SOC & Legal Operations Hub
Zero-Trust Threat Mitigation Network`;
  }
}

export const takedownService = new TakedownService();
