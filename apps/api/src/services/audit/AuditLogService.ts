import {
  AuditLogEntry,
  AuditLogCategory,
  AuditLogSeverity
} from '@phishnetra/shared';

export interface AuditLogQueryFilters {
  category?: AuditLogCategory;
  severity?: AuditLogSeverity;
  actor?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export class AuditLogService {
  private logs: AuditLogEntry[] = [];

  constructor() {
    this.seedDefaultAuditLogs();
  }

  private seedDefaultAuditLogs() {
    const defaultLogs: AuditLogEntry[] = [
      {
        id: 'audit_001',
        timestamp: new Date(Date.now() - 3600000 * 5).toISOString(),
        actor: 'admin@phishnetra.internal',
        action: 'USER_LOGIN_SUCCESS',
        category: 'AUTH',
        severity: 'INFO',
        target: 'admin@phishnetra.internal',
        details: 'SOC Admin authenticated successfully from IP 192.168.1.50',
        ipAddress: '192.168.1.50'
      },
      {
        id: 'audit_002',
        timestamp: new Date(Date.now() - 3600000 * 3).toISOString(),
        actor: 'analyst@phishnetra.internal',
        action: 'REMEDIATION_DNS_SINKHOLE_GENERATED',
        category: 'REMEDIATION',
        severity: 'WARNING',
        target: 'paypal-security-alert-update.com',
        details: 'Generated BIND9 RPZ Sinkhole entry for confirmed phishing domain',
        ipAddress: '10.0.4.12'
      },
      {
        id: 'audit_003',
        timestamp: new Date(Date.now() - 3600000 * 2).toISOString(),
        actor: 'system',
        action: 'THREAT_FEED_SYNC_COMPLETED',
        category: 'THREAT_FEED',
        severity: 'INFO',
        target: 'URLHAUS',
        details: 'Synchronized 240 active malicious phishing URLs into Threat Graph',
        ipAddress: '127.0.0.1'
      },
      {
        id: 'audit_004',
        timestamp: new Date(Date.now() - 3600000 * 1).toISOString(),
        actor: 'admin@phishnetra.internal',
        action: 'RISK_ENGINE_CALIBRATED',
        category: 'CONFIG',
        severity: 'INFO',
        target: 'LayerWeights',
        details: 'Updated LayerWeights (URL: 0.15, ML: 0.15, REPUTATION: 0.20, CONTENT: 0.15)',
        ipAddress: '192.168.1.50'
      }
    ];

    this.logs.push(...defaultLogs);
  }

  public log(entry: {
    actor: string;
    action: string;
    category: AuditLogCategory;
    severity?: AuditLogSeverity;
    target?: string | null;
    details: string;
    ipAddress?: string | null;
  }): AuditLogEntry {
    const newLog: AuditLogEntry = {
      id: `audit_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      actor: entry.actor,
      action: entry.action,
      category: entry.category,
      severity: entry.severity || 'INFO',
      target: entry.target || null,
      details: entry.details,
      ipAddress: entry.ipAddress || '127.0.0.1'
    };

    this.logs.unshift(newLog);

    // Keep log buffer bounded to latest 2000 entries
    if (this.logs.length > 2000) {
      this.logs.length = 2000;
    }

    return newLog;
  }

  public getLogs(filters: AuditLogQueryFilters = {}): { total: number; logs: AuditLogEntry[] } {
    let filtered = [...this.logs];

    if (filters.category) {
      filtered = filtered.filter(l => l.category === filters.category);
    }
    if (filters.severity) {
      filtered = filtered.filter(l => l.severity === filters.severity);
    }
    if (filters.actor) {
      const actorLower = filters.actor.toLowerCase();
      filtered = filtered.filter(l => l.actor.toLowerCase().includes(actorLower));
    }
    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      filtered = filtered.filter(
        l =>
          l.action.toLowerCase().includes(searchLower) ||
          l.details.toLowerCase().includes(searchLower) ||
          (l.target && l.target.toLowerCase().includes(searchLower))
      );
    }

    const total = filtered.length;
    const offset = filters.offset || 0;
    const limit = filters.limit || 50;
    const paged = filtered.slice(offset, offset + limit);

    return { total, logs: paged };
  }

  public exportCsv(filters: AuditLogQueryFilters = {}): string {
    const { logs } = this.getLogs({ ...filters, limit: 1000, offset: 0 });
    const headers = ['ID', 'Timestamp', 'Actor', 'Action', 'Category', 'Severity', 'Target', 'Details', 'IP Address'];
    const rows = logs.map(l => [
      l.id,
      `"${l.timestamp}"`,
      `"${l.actor}"`,
      `"${l.action}"`,
      l.category,
      l.severity,
      `"${(l.target || '').replace(/"/g, '""')}"`,
      `"${l.details.replace(/"/g, '""')}"`,
      l.ipAddress || ''
    ]);

    return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  }
}

export const auditLogService = new AuditLogService();
