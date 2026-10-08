import { batchService } from '../src/services/queue/BatchService';
import { analysisQueue } from '../src/services/queue/AsyncAnalysisQueue';

describe('Async Batch Processing & Worker Queue Suite', () => {
  it('should parse and deduplicate various raw input URL formats', () => {
    // Array
    const arr = batchService.parseUrls(['https://example1.com', 'https://example2.com', 'https://example1.com']);
    expect(arr).toEqual(['https://example1.com', 'https://example2.com']);

    // Newline-separated
    const multiline = `
      https://a.com
      https://b.com
      # Comment line
      url
      https://c.com
    `;
    const parsedMulti = batchService.parseUrls(multiline);
    expect(parsedMulti).toEqual(['https://a.com', 'https://b.com', 'https://c.com']);

    // CSV format
    const csv = 'https://site1.com,https://site2.com;https://site3.com';
    const parsedCsv = batchService.parseUrls(csv);
    expect(parsedCsv).toEqual(['https://site1.com', 'https://site2.com', 'https://site3.com']);
  });

  it('should create a batch job, enqueue tasks, and calculate progress', async () => {
    const urls = ['https://safe-domain-alpha.com', 'https://safe-domain-beta.com'];
    const job = await batchService.createBatchJob(null, {
      urls,
      includePageAnalysis: false
    });

    expect(job).toBeDefined();
    expect(job.id).toBeDefined();
    expect(job.totalUrls).toBe(2);
    expect(job.status).toBe('QUEUED');
    expect(job.items?.length).toBe(2);

    // Fetch by ID
    const fetched = await batchService.getBatchJob(job.id);
    expect(fetched).toBeDefined();
    expect(fetched?.id).toBe(job.id);
  });

  it('should export batch job results to CSV and JSON formats', async () => {
    const job = await batchService.createBatchJob(null, {
      urls: ['https://export-test1.com', 'https://export-test2.com']
    });

    // Export CSV
    const csvExport = await batchService.exportBatchJob(job.id, 'csv');
    expect(csvExport.contentType).toBe('text/csv');
    expect(csvExport.data).toContain('URL,Status,Verdict');
    expect(csvExport.data).toContain('https://export-test1.com');

    // Export JSON
    const jsonExport = await batchService.exportBatchJob(job.id, 'json');
    expect(jsonExport.contentType).toBe('application/json');
    const parsed = JSON.parse(jsonExport.data);
    expect(parsed.id).toBe(job.id);
  });

  it('should expose operational queue metrics', () => {
    const metrics = analysisQueue.getMetrics();
    expect(metrics).toBeDefined();
    expect(typeof metrics.waiting).toBe('number');
    expect(typeof metrics.active).toBe('number');
    expect(metrics.workerConcurrency).toBe(5);
  });
});
