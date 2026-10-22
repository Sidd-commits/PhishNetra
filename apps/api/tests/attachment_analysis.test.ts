import request from 'supertest';
import { createApp } from '../src/app';
import { attachmentAnalysisService } from '../src/services/ingestion/AttachmentAnalysisService';

const app = createApp();

jest.setTimeout(30000);

describe('Attachment Link Analysis & Ingestion Test Suite', () => {
  describe('AttachmentAnalysisService Unit Tests', () => {
    it('should extract URLs from HTML attachments including href, form action, and meta refresh', async () => {
      const htmlContent = `
        <!DOCTYPE html>
        <html>
          <head>
            <meta http-equiv="refresh" content="5;url=https://redirect-portal.com/login">
          </head>
          <body>
            <h1>Account Verification Required</h1>
            <a href="http://secure-update-paypal-verification.com/login">Verify Account Now</a>
            <form action="http://harvest-credentials.org/submit" method="POST">
              <input type="password" name="pwd" />
            </form>
          </body>
        </html>
      `;

      const result = await attachmentAnalysisService.analyzeAttachment({
        filename: 'statement.html',
        rawText: htmlContent,
        maxUrlsToAnalyze: 10
      });

      expect(result.detectedFormat).toBe('HTML');
      expect(result.totalUrlsExtracted).toBeGreaterThanOrEqual(3);
      expect(result.processingStatus).toMatch(/SUCCESS|THREATS_DETECTED|NO_SUSPICIOUS_URLS_FOUND/);
      expect(result.disclaimer).toContain('embedded hyperlinks');
    });

    it('should extract URLs from PDF stream dictionaries and annotations', async () => {
      const pdfMockStream = `
        %PDF-1.4
        1 0 obj
        << /Type /Catalog /Pages 2 0 R >>
        endobj
        2 0 obj
        << /Type /Action /S /URI /URI (http://malicious-pdf-phish.ru/reset-password) >>
        endobj
        3 0 obj
        << /Type /Annot /Subtype /Link /A << /S /URI /URI (https://corporate-payroll-update.com/download) >> >>
        endobj
        %%EOF
      `;

      const base64Pdf = Buffer.from(pdfMockStream, 'utf-8').toString('base64');

      const result = await attachmentAnalysisService.analyzeAttachment({
        filename: 'Invoice_OCT_2026.pdf',
        contentBase64: base64Pdf,
        maxUrlsToAnalyze: 10
      });

      expect(result.detectedFormat).toBe('PDF');
      expect(result.totalUrlsExtracted).toBeGreaterThanOrEqual(2);
      expect(result.uniqueUrlsExtracted).toBeGreaterThanOrEqual(2);
      expect(result.evidenceReasons.length).toBeGreaterThan(0);
    });

    it('should extract URLs from DOCX relationship XML targets', async () => {
      const docxRelsXml = `
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="http://deceptive-microsoft365-login.net/auth" TargetMode="External"/>
          <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://legitimate-service.org/docs" TargetMode="External"/>
        </Relationships>
      `;

      const base64Docx = Buffer.from(docxRelsXml, 'utf-8').toString('base64');

      const result = await attachmentAnalysisService.analyzeAttachment({
        filename: 'SecurityPolicy.docx',
        contentBase64: base64Docx,
        maxUrlsToAnalyze: 10
      });

      expect(result.detectedFormat).toBe('DOCX');
      expect(result.totalUrlsExtracted).toBeGreaterThanOrEqual(2);
      expect(result.analyzedUrls.length).toBeGreaterThan(0);
    });

    it('should extract standard and defanged URLs from plain text files', async () => {
      const textContent = `
        Dear Customer,
        Please review suspicious transaction:
        hxxp://phishing-bank-portal[.]com/login
        Or check our portal at https://verified-safe-portal.com/help
      `;

      const result = await attachmentAnalysisService.analyzeAttachment({
        filename: 'alert.txt',
        rawText: textContent,
        maxUrlsToAnalyze: 10
      });

      expect(result.detectedFormat).toBe('TXT');
      expect(result.totalUrlsExtracted).toBeGreaterThanOrEqual(2);
      // Verify defanged hxxp was properly normalized to http
      const urlsExtracted = result.analyzedUrls.map(u => u.url);
      expect(urlsExtracted.some(u => u.startsWith('http://phishing-bank-portal.com'))).toBe(true);
    });

    it('should deduplicate repeated identical URLs in an attachment', async () => {
      const repeatedContent = `
        <a href="http://repeated-link.com/dest">Link 1</a>
        <a href="http://repeated-link.com/dest">Link 2</a>
        <a href="http://repeated-link.com/dest">Link 3</a>
      `;

      const result = await attachmentAnalysisService.analyzeAttachment({
        filename: 'newsletter.html',
        rawText: repeatedContent,
        maxUrlsToAnalyze: 10
      });

      expect(result.uniqueUrlsExtracted).toBe(1);
      expect(result.analyzedUrls.length).toBe(1);
    });

    it('should report NO_SUSPICIOUS_URLS_FOUND when attachment has zero embedded links', async () => {
      const cleanText = 'This is an internal memo with strictly internal operational guidance and no external links.';

      const result = await attachmentAnalysisService.analyzeAttachment({
        filename: 'memo.txt',
        rawText: cleanText,
        maxUrlsToAnalyze: 10
      });

      expect(result.processingStatus).toBe('NO_SUSPICIOUS_URLS_FOUND');
      expect(result.totalUrlsExtracted).toBe(0);
      expect(result.uniqueUrlsExtracted).toBe(0);
      expect(result.overallVerdict).toBe('SAFE');
      expect(result.overallRiskScore).toBe(0);
    });

    it('should safely flag unsupported file extensions as UNABLE_TO_ANALYZE without crashing', async () => {
      const result = await attachmentAnalysisService.analyzeAttachment({
        filename: 'payload.exe',
        rawText: 'binary bytes',
        maxUrlsToAnalyze: 10
      });

      expect(result.processingStatus).toBe('UNABLE_TO_ANALYZE');
      expect(result.detectedFormat).toBe('UNKNOWN');
      expect(result.warningNotes.length).toBeGreaterThan(0);
    });

    it('should safely reject oversized attachment contents exceeding 10MB limit with UNABLE_TO_ANALYZE', async () => {
      const hugeBase64 = Buffer.alloc(11 * 1024 * 1024).toString('base64');

      const result = await attachmentAnalysisService.analyzeAttachment({
        filename: 'huge_document.pdf',
        contentBase64: hugeBase64,
        maxUrlsToAnalyze: 10
      });

      expect(result.processingStatus).toBe('UNABLE_TO_ANALYZE');
      expect(result.detectedFormat).toBe('UNKNOWN');
      expect(result.evidenceReasons[0]).toContain('exceeds maximum processing limit of 10MB');
    });
  });

  describe('POST /api/ingest/attachment Endpoint Integration', () => {
    it('should successfully analyze an attachment via API route and return structured verdict', async () => {
      const res = await request(app)
        .post('/api/ingest/attachment')
        .send({
          filename: 'quarantine_sample.html',
          rawText: 'Click here: <a href="http://payroll-portal-login.com">Payroll</a>',
          maxUrlsToAnalyze: 5
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('analysisId');
      expect(res.body.data).toHaveProperty('detectedFormat', 'HTML');
      expect(res.body.data).toHaveProperty('processingStatus');
      expect(res.body.data.uniqueUrlsExtracted).toBe(1);
      expect(Array.isArray(res.body.data.analyzedUrls)).toBe(true);
      expect(res.body.data).toHaveProperty('disclaimer');
    });

    it('should reject requests missing required filename or content with 400 Validation Error', async () => {
      const res = await request(app)
        .post('/api/ingest/attachment')
        .send({
          filename: '',
          maxUrlsToAnalyze: 5
        });

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('error', 'Validation Error');
    });
  });
});
