import {
  EmailAnalysisRequest,
  EmailAnalysisResult,
  EmailHeaderIntelligence,
  ExtractedIOC,
  RawIOCExtractionResult,
  ThreatVerdict,
  RiskLevel
} from '@phishnetra/shared';
import { analysisService } from '../AnalysisService';

export class EmailIngestionService {
  /**
   * Parses arbitrary raw text (threat reports, tickets, logs) and extracts all IOCs.
   */
  public extractRawIOCs(rawText: string): RawIOCExtractionResult {
    // Normalization / refanging
    const refanged = rawText
      .replace(/hxxp/gi, 'http')
      .replace(/\[\.\]/g, '.')
      .replace(/\[:\/\/\]/g, '://');

    // RegEx patterns
    const urlPattern = /https?:\/\/[^\s"'<>]+/gi;
    const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
    const md5Pattern = /\b[a-fA-F0-9]{32}\b/g;
    const sha256Pattern = /\b[a-fA-F0-9]{64}\b/g;

    const urls = Array.from(new Set(refanged.match(urlPattern) || []));
    const rawIps = Array.from(new Set(refanged.match(ipPattern) || []));
    const emails = Array.from(new Set(refanged.match(emailPattern) || []));
    const md5s = Array.from(new Set(refanged.match(md5Pattern) || []));
    const sha256s = Array.from(new Set(refanged.match(sha256Pattern) || []));

    // Filter valid IPv4 (0-255)
    const validIps = rawIps.filter(ip => {
      const parts = ip.split('.');
      return parts.every(p => parseInt(p, 10) >= 0 && parseInt(p, 10) <= 255);
    });

    // Extract unique domains from URLs
    const domains = Array.from(
      new Set(
        urls.map(u => {
          try {
            return new URL(u).hostname;
          } catch {
            return null;
          }
        }).filter(Boolean) as string[]
      )
    );

    const hashes = Array.from(new Set([...md5s, ...sha256s]));
    const total = urls.length + domains.length + validIps.length + emails.length + hashes.length;

    return {
      totalExtracted: total,
      urls,
      domains,
      ips: validIps,
      emails,
      hashes
    };
  }

  /**
   * End-to-end email analysis: parses headers, verifies SPF/DKIM/DMARC spoofing,
   * extracts URLs, and runs multi-layer threat scans.
   */
  public async analyzeEmail(req: EmailAnalysisRequest): Promise<EmailAnalysisResult> {
    const raw = req.rawEmlText;
    const analysisId = `eml_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const analyzedAt = new Date().toISOString();

    // 1. Header Extraction
    const headers = this.parseHeaders(raw);

    // 2. Extract IOCs from Body
    const extracted = this.extractRawIOCs(raw);
    const iocItems: ExtractedIOC[] = [];

    for (const u of extracted.urls) {
      iocItems.push({
        type: 'URL',
        value: u,
        context: 'Embedded Link in Email Body',
        isMalicious: false
      });
    }
    for (const d of extracted.domains) {
      iocItems.push({
        type: 'DOMAIN',
        value: d,
        context: 'Destination Domain',
        isMalicious: false
      });
    }
    for (const ip of extracted.ips) {
      iocItems.push({
        type: 'IP',
        value: ip,
        context: 'Originating or Referenced IP',
        isMalicious: false
      });
    }
    for (const h of extracted.hashes) {
      iocItems.push({
        type: h.length === 32 ? 'HASH_MD5' : 'HASH_SHA256',
        value: h,
        context: 'Attachment Hash',
        isMalicious: false
      });
    }

    // 3. Scan Extracted URLs if enabled
    let maxUrlRisk = 0;
    const analyzedUrlSummaries = [];
    const reasons: string[] = [];

    if (req.evaluateExtractedUrls && extracted.urls.length > 0) {
      for (const urlToScan of extracted.urls.slice(0, 5)) {
        try {
          const scanRes = await analysisService.analyze(urlToScan, undefined, false);
          analyzedUrlSummaries.push({
            id: scanRes.analysisId,
            url: scanRes.url,
            verdict: scanRes.verdict,
            riskScore: scanRes.riskScore,
            riskLevel: scanRes.riskLevel,
            confidence: scanRes.confidence,
            createdAt: scanRes.createdAt
          });

          if (scanRes.riskScore > maxUrlRisk) {
            maxUrlRisk = scanRes.riskScore;
          }

          if (scanRes.verdict === 'PHISHING') {
            reasons.push(`Embedded link '${urlToScan}' confirmed malicious phishing threat (${scanRes.riskScore}/100)`);
            const matched = iocItems.find(i => i.value === urlToScan);
            if (matched) {
              matched.isMalicious = true;
              matched.riskScore = scanRes.riskScore;
            }
          }
        } catch {
          // ignore scan error
        }
      }
    }

    // 4. Header Spoof Risk Scoring
    let headerRisk = 0;
    if (headers.isSpoofed) {
      headerRisk += 35;
      reasons.push(`Domain spoofing detected: Sender '${headers.from}' mismatches Return-Path or failed authentication`);
    }
    if (headers.spfStatus === 'FAIL') {
      headerRisk += 25;
      reasons.push('Sender Policy Framework (SPF) validation failed (spf=fail)');
    }
    if (headers.dmarcStatus === 'FAIL') {
      headerRisk += 25;
      reasons.push('Domain-based Message Authentication (DMARC) alignment failed (dmarc=fail)');
    }

    // 5. Synthesize Composite Score
    let compositeScore = Math.min(100, Math.max(headerRisk, maxUrlRisk));
    if (headerRisk >= 35 && maxUrlRisk >= 50) {
      compositeScore = Math.min(100, compositeScore + 20);
    }

    let verdict: ThreatVerdict = 'SAFE';
    let riskLevel: RiskLevel = 'LOW';

    if (compositeScore >= 75) {
      verdict = 'PHISHING';
      riskLevel = 'CRITICAL';
    } else if (compositeScore >= 45) {
      verdict = 'SUSPICIOUS';
      riskLevel = 'MEDIUM';
    }

    if (reasons.length === 0) {
      reasons.push('No malicious links or header spoofing anomalies identified.');
    }

    return {
      analysisId,
      headers,
      totalUrlsExtracted: extracted.urls.length,
      totalIocsExtracted: iocItems.length,
      extractedIocs: iocItems,
      analyzedUrls: analyzedUrlSummaries,
      phishingScore: Math.round(compositeScore),
      verdict,
      riskLevel,
      evidenceReasons: reasons,
      analyzedAt
    };
  }

  private parseHeaders(raw: string): EmailHeaderIntelligence {
    const fromMatch = raw.match(/^From:\s*(.+)$/im);
    const subjectMatch = raw.match(/^Subject:\s*(.+)$/im);
    const replyToMatch = raw.match(/^Reply-To:\s*(.+)$/im);
    const returnPathMatch = raw.match(/^Return-Path:\s*(.+)$/im);
    const dateMatch = raw.match(/^Date:\s*(.+)$/im);

    const from = fromMatch ? fromMatch[1].trim() : 'unknown@sender.com';
    const subject = subjectMatch ? subjectMatch[1].trim() : '(No Subject)';
    const replyTo = replyToMatch ? replyToMatch[1].trim() : null;
    const returnPath = returnPathMatch ? returnPathMatch[1].trim() : null;
    const date = dateMatch ? dateMatch[1].trim() : new Date().toUTCString();

    let spf: 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL' | 'NONE' = 'NONE';
    let dkim: 'PASS' | 'FAIL' | 'NONE' = 'NONE';
    let dmarc: 'PASS' | 'FAIL' | 'NONE' = 'NONE';

    if (/spf=pass/i.test(raw)) spf = 'PASS';
    else if (/spf=fail/i.test(raw)) spf = 'FAIL';
    else if (/spf=softfail/i.test(raw)) spf = 'SOFTFAIL';

    if (/dkim=pass/i.test(raw)) dkim = 'PASS';
    else if (/dkim=fail/i.test(raw)) dkim = 'FAIL';

    if (/dmarc=pass/i.test(raw)) dmarc = 'PASS';
    else if (/dmarc=fail/i.test(raw)) dmarc = 'FAIL';

    // Domain mismatch check between From and Return-Path / Reply-To
    let isSpoofed = false;
    const extractDomain = (addr: string) => {
      const match = addr.match(/@([a-zA-Z0-9.-]+)/);
      return match ? match[1].toLowerCase() : '';
    };

    const fromDomain = extractDomain(from);
    if (returnPath) {
      const returnDomain = extractDomain(returnPath);
      if (fromDomain && returnDomain && fromDomain !== returnDomain) {
        isSpoofed = true;
      }
    }

    if (spf === 'FAIL' || dmarc === 'FAIL') {
      isSpoofed = true;
    }

    return {
      from,
      replyTo,
      returnPath,
      subject,
      date,
      spfStatus: spf,
      dkimStatus: dkim,
      dmarcStatus: dmarc,
      isSpoofed,
      sendingIp: null
    };
  }
}

export const emailIngestionService = new EmailIngestionService();
