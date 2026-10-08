import { ThreatVerdict, RiskLevel } from '@phishnetra/shared';
import { prisma } from '../../db/prisma';

export class PrometheusMetricsService {
  private startTime: number = Date.now();
  private requestCounts: Map<string, number> = new Map();
  private scanCounts: Map<string, number> = new Map();
  private cacheHits: number = 0;
  private cacheMisses: number = 0;
  private totalScanDurationMs: number = 0;
  private totalScans: number = 0;

  public recordRequest(method: string, path: string, status: number): void {
    const sanitizedPath = this.sanitizePath(path);
    const key = `${method.toUpperCase()}|${sanitizedPath}|${status}`;
    this.requestCounts.set(key, (this.requestCounts.get(key) || 0) + 1);
  }

  public recordScan(verdict: ThreatVerdict, riskLevel: RiskLevel, durationMs: number): void {
    const key = `${verdict}|${riskLevel}`;
    this.scanCounts.set(key, (this.scanCounts.get(key) || 0) + 1);
    this.totalScanDurationMs += durationMs;
    this.totalScans += 1;
  }

  public recordCacheHit(): void {
    this.cacheHits += 1;
  }

  public recordCacheMiss(): void {
    this.cacheMisses += 1;
  }

  public async generatePrometheusMetrics(): Promise<string> {
    const uptimeSec = Math.floor((Date.now() - this.startTime) / 1000);
    const mem = process.memoryUsage();

    let analysisCount = 0;
    try {
      analysisCount = await prisma.analysis.count();
    } catch {
      // ignore
    }

    const lines: string[] = [
      '# HELP phishnetra_uptime_seconds Total seconds the PhishNetra API process has been running',
      '# TYPE phishnetra_uptime_seconds gauge',
      `phishnetra_uptime_seconds ${uptimeSec}`,
      '',
      '# HELP phishnetra_process_memory_bytes Process memory usage metrics',
      '# TYPE phishnetra_process_memory_bytes gauge',
      `phishnetra_process_memory_bytes{type="heapUsed"} ${mem.heapUsed}`,
      `phishnetra_process_memory_bytes{type="heapTotal"} ${mem.heapTotal}`,
      `phishnetra_process_memory_bytes{type="rss"} ${mem.rss}`,
      '',
      '# HELP phishnetra_http_requests_total Total HTTP requests handled by endpoint and status',
      '# TYPE phishnetra_http_requests_total counter'
    ];

    if (this.requestCounts.size === 0) {
      lines.push('phishnetra_http_requests_total{method="GET",path="/api/health",status="200"} 1');
    } else {
      for (const [key, count] of this.requestCounts.entries()) {
        const [method, path, status] = key.split('|');
        lines.push(`phishnetra_http_requests_total{method="${method}",path="${path}",status="${status}"} ${count}`);
      }
    }

    lines.push(
      '',
      '# HELP phishnetra_scans_total Total multi-layer phishing scans processed',
      '# TYPE phishnetra_scans_total counter',
      `phishnetra_scans_total ${this.totalScans || analysisCount}`,
      '',
      '# HELP phishnetra_scan_verdicts_total Multi-layer scan results by verdict and risk level',
      '# TYPE phishnetra_scan_verdicts_total counter'
    );

    if (this.scanCounts.size === 0) {
      lines.push('phishnetra_scan_verdicts_total{verdict="SAFE",risk_level="LOW"} 0');
      lines.push('phishnetra_scan_verdicts_total{verdict="SUSPICIOUS",risk_level="MEDIUM"} 0');
      lines.push('phishnetra_scan_verdicts_total{verdict="PHISHING",risk_level="CRITICAL"} 0');
    } else {
      for (const [key, count] of this.scanCounts.entries()) {
        const [verdict, riskLevel] = key.split('|');
        lines.push(`phishnetra_scan_verdicts_total{verdict="${verdict}",risk_level="${riskLevel}"} ${count}`);
      }
    }

    const avgLatencyMs = this.totalScans > 0 ? (this.totalScanDurationMs / this.totalScans).toFixed(2) : '0';
    lines.push(
      '',
      '# HELP phishnetra_scan_duration_ms_avg Average multi-layer scan execution time in milliseconds',
      '# TYPE phishnetra_scan_duration_ms_avg gauge',
      `phishnetra_scan_duration_ms_avg ${avgLatencyMs}`,
      '',
      '# HELP phishnetra_cache_requests_total Multi-tier memory and Redis cache operations',
      '# TYPE phishnetra_cache_requests_total counter',
      `phishnetra_cache_requests_total{result="hit"} ${this.cacheHits}`,
      `phishnetra_cache_requests_total{result="miss"} ${this.cacheMisses}`,
      ''
    );

    return lines.join('\n');
  }

  private sanitizePath(path: string): string {
    return path
      .replace(/\/analysis\/[a-zA-Z0-9_-]+/g, '/analysis/:id')
      .replace(/\/domains\/[a-zA-Z0-9_.-]+/g, '/domains/:domain')
      .replace(/\/cases\/[a-zA-Z0-9_-]+/g, '/cases/:id')
      .split('?')[0];
  }
}

export const metricsService = new PrometheusMetricsService();
