/**
 * PhishNetra - Email Attachment URL Extraction & Threat Analysis Service
 * Module: apps.api.src.services.ingestion.AttachmentAnalysisService
 * Purpose: Safe, non-executing extraction and evaluation of embedded URLs in PDF, HTML, TXT, DOCX, and EML attachments.
 */

import crypto from 'crypto';
import {
  AttachmentAnalysisRequest,
  AttachmentAnalysisResult,
  ThreatVerdict,
  RiskLevel
} from '@phishnetra/shared';
import { analysisService } from '../AnalysisService';

export class AttachmentAnalysisService {
  private readonly MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB strict limit
  private readonly MAX_URLS_TO_ANALYZE = 20;

  /**
   * Main entrypoint: validates file, extracts URLs, runs multi-layer threat analysis, and synthesizes report.
   */
  public async analyzeAttachment(req: AttachmentAnalysisRequest): Promise<AttachmentAnalysisResult> {
    const analysisId = `att_${crypto.randomUUID().slice(0, 12)}`;
    const analyzedAt = new Date().toISOString();
    const filename = (req.filename || 'attachment.bin').trim();
    const warningNotes: string[] = [];
    const evidenceReasons: string[] = [];

    // 1. Resolve raw Buffer and validate size
    let fileBuffer: Buffer;
    if (req.contentBase64) {
      try {
        fileBuffer = Buffer.from(req.contentBase64, 'base64');
      } catch (err: any) {
        return this.createUnableToAnalyzeResult(
          analysisId,
          filename,
          'UNKNOWN',
          0,
          `Failed to decode Base64 attachment payload: ${err.message}`,
          analyzedAt
        );
      }
    } else if (req.rawText) {
      fileBuffer = Buffer.from(req.rawText, 'utf-8');
    } else {
      return this.createUnableToAnalyzeResult(
        analysisId,
        filename,
        'UNKNOWN',
        0,
        'No attachment content provided (neither contentBase64 nor rawText was supplied).',
        analyzedAt
      );
    }

    const fileSizeBytes = fileBuffer.length;
    if (fileSizeBytes > this.MAX_FILE_SIZE) {
      return this.createUnableToAnalyzeResult(
        analysisId,
        filename,
        'UNKNOWN',
        fileSizeBytes,
        `File exceeds maximum processing limit of 10MB (Received: ${(fileSizeBytes / (1024 * 1024)).toFixed(2)} MB).`,
        analyzedAt
      );
    }

    // 2. Detect Format & Magic Bytes
    const detectedFormat = this.detectFormat(filename, fileBuffer, req.fileMimeType);

    if (detectedFormat === 'UNKNOWN') {
      return this.createUnableToAnalyzeResult(
        analysisId,
        filename,
        'UNKNOWN',
        fileSizeBytes,
        `Unsupported or unparseable file format. Supported formats are PDF, HTML, TXT, DOCX, and EML.`,
        analyzedAt
      );
    }

    // 3. Extract Embedded and Plain Text URLs
    let rawUrls: string[] = [];
    try {
      switch (detectedFormat) {
        case 'PDF':
          rawUrls = this.extractUrlsFromPdf(fileBuffer);
          break;
        case 'HTML':
          rawUrls = this.extractUrlsFromHtml(fileBuffer);
          break;
        case 'DOCX':
          rawUrls = this.extractUrlsFromDocx(fileBuffer);
          break;
        case 'EML':
        case 'TXT':
        default:
          rawUrls = this.extractUrlsFromPlainText(fileBuffer.toString('utf-8'));
          break;
      }
    } catch (parseErr: any) {
      return this.createUnableToAnalyzeResult(
        analysisId,
        filename,
        detectedFormat,
        fileSizeBytes,
        `Attachment parsing error: ${parseErr.message}`,
        analyzedAt
      );
    }

    // 4. Normalize & Deduplicate Extracted URLs
    const sanitizedUrls = this.sanitizeAndDeduplicateUrls(rawUrls);
    const totalExtracted = rawUrls.length;
    const uniqueExtracted = sanitizedUrls.length;

    // 5. Handle zero URLs extracted
    if (uniqueExtracted === 0) {
      evidenceReasons.push(
        `Inspected ${detectedFormat} attachment (${(fileSizeBytes / 1024).toFixed(1)} KB); zero embedded hyperlinks or actionable URLs were detected.`
      );
      return {
        analysisId,
        filename,
        detectedFormat,
        fileSizeBytes,
        processingStatus: 'NO_SUSPICIOUS_URLS_FOUND',
        totalUrlsExtracted: 0,
        uniqueUrlsExtracted: 0,
        analyzedUrls: [],
        suspiciousOrMaliciousUrls: [],
        unreachableUrls: [],
        overallVerdict: 'SAFE',
        overallRiskScore: 0,
        overallRiskLevel: 'LOW',
        evidenceReasons,
        warningNotes,
        disclaimer:
          'Security Note: This analysis inspected the attachment for embedded URLs and destination risks. It does not certify that binary or macro content is benign.',
        analyzedAt
      };
    }

    // 6. Analyze Extracted URLs through Shared Zero-Trust Pipeline
    const limit = Math.min(req.maxUrlsToAnalyze || 15, this.MAX_URLS_TO_ANALYZE);
    const urlsToScan = sanitizedUrls.slice(0, limit);
    if (sanitizedUrls.length > limit) {
      warningNotes.push(
        `Attachment contains ${sanitizedUrls.length} unique URLs. Truncated real-time inspection to top ${limit} targets to preserve system throughput.`
      );
    }

    const analyzedUrlSummaries = [];
    const suspiciousOrMaliciousUrls: string[] = [];
    const unreachableUrls: string[] = [];
    let maxRiskScore = 0;

    for (const targetUrl of urlsToScan) {
      try {
        const scanRes = await analysisService.analyze(targetUrl, undefined, false);
        analyzedUrlSummaries.push({
          id: scanRes.analysisId,
          url: scanRes.url,
          verdict: scanRes.verdict,
          riskScore: scanRes.riskScore,
          riskLevel: scanRes.riskLevel,
          confidence: scanRes.confidence,
          createdAt: scanRes.createdAt
        });

        if (scanRes.riskScore > maxRiskScore) {
          maxRiskScore = scanRes.riskScore;
        }

        if (scanRes.verdict === 'PHISHING' || scanRes.verdict === 'SUSPICIOUS') {
          suspiciousOrMaliciousUrls.push(targetUrl);
          evidenceReasons.push(
            `Extracted URL '${targetUrl}' identified as ${scanRes.verdict} (Risk: ${scanRes.riskScore}/100, Confidence: ${(scanRes.confidence * 100).toFixed(0)}%).`
          );
        }
      } catch (scanErr: any) {
        unreachableUrls.push(targetUrl);
        warningNotes.push(`Could not complete deep inspection on extracted target '${targetUrl}': ${scanErr.message}`);
      }
    }

    // 7. Calculate Overall Verdict
    let overallVerdict: ThreatVerdict = 'SAFE';
    let overallRiskLevel: RiskLevel = 'LOW';
    let processingStatus: 'SUCCESS' | 'NO_SUSPICIOUS_URLS_FOUND' | 'THREATS_DETECTED' | 'UNABLE_TO_ANALYZE' = 'SUCCESS';

    if (suspiciousOrMaliciousUrls.length > 0) {
      processingStatus = 'THREATS_DETECTED';
      if (maxRiskScore >= 75) {
        overallVerdict = 'PHISHING';
        overallRiskLevel = 'CRITICAL';
      } else {
        overallVerdict = 'SUSPICIOUS';
        overallRiskLevel = 'HIGH';
      }
    } else {
      processingStatus = 'NO_SUSPICIOUS_URLS_FOUND';
      overallVerdict = 'SAFE';
      overallRiskLevel = 'LOW';
      evidenceReasons.push(
        `All ${analyzedUrlSummaries.length} analyzed embedded URLs were evaluated as benign with no phishing signals.`
      );
    }

    return {
      analysisId,
      filename,
      detectedFormat,
      fileSizeBytes,
      processingStatus,
      totalUrlsExtracted: totalExtracted,
      uniqueUrlsExtracted: uniqueExtracted,
      analyzedUrls: analyzedUrlSummaries,
      suspiciousOrMaliciousUrls,
      unreachableUrls,
      overallVerdict,
      overallRiskScore: maxRiskScore,
      overallRiskLevel,
      evidenceReasons,
      warningNotes,
      disclaimer:
        'Security Note: This analysis evaluated embedded hyperlinks and target destination indicators. It does not constitute a full operating-system sandbox or local binary malware scan.',
      analyzedAt
    };
  }

  /**
   * Safe Format Detection using file extension, MIME type, and binary magic bytes.
   */
  private detectFormat(
    filename: string,
    buffer: Buffer,
    mimeType?: string
  ): 'PDF' | 'HTML' | 'TXT' | 'DOCX' | 'EML' | 'UNKNOWN' {
    const ext = filename.split('.').pop()?.toLowerCase() || '';

    // Check PDF Magic Bytes '%PDF-'
    if (buffer.length >= 4 && buffer.slice(0, 4).toString('ascii') === '%PDF') {
      return 'PDF';
    }

    // Check PK Zip Header for DOCX
    if (buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04) {
      if (ext === 'docx' || ext === 'docm' || (mimeType && mimeType.includes('wordprocessingml'))) {
        return 'DOCX';
      }
    }

    // Check HTML
    const leadingText = buffer.slice(0, 512).toString('utf-8').toLowerCase();
    if (
      ext === 'html' ||
      ext === 'htm' ||
      leadingText.includes('<!doctype html') ||
      leadingText.includes('<html') ||
      leadingText.includes('<head') ||
      leadingText.includes('<body')
    ) {
      return 'HTML';
    }

    // Check EML
    if (
      ext === 'eml' ||
      ext === 'msg' ||
      (/^From:\s/im.test(leadingText) && /^Subject:\s/im.test(leadingText))
    ) {
      return 'EML';
    }

    // Check Plain Text
    if (ext === 'txt' || ext === 'log' || ext === 'csv' || (mimeType && mimeType.startsWith('text/'))) {
      return 'TXT';
    }

    // If extension matches common types, fallback
    if (ext === 'pdf') return 'PDF';
    if (ext === 'docx') return 'DOCX';

    // If extension is an explicit unsupported executable/binary, do not treat as text
    const unsupportedBinaryExts = ['exe', 'dll', 'bin', 'so', 'dylib', 'bat', 'cmd', 'ps1', 'vbs', 'scr', 'iso', 'apk', 'msi', 'elf', 'com', 'pif'];
    if (unsupportedBinaryExts.includes(ext)) {
      return 'UNKNOWN';
    }

    // If buffer is valid printable ASCII / UTF-8 text and has a text extension or no extension
    if ((['txt', 'log', 'csv', ''].includes(ext) || (mimeType && mimeType.startsWith('text/'))) && this.isPrintableText(buffer.slice(0, 1024))) {
      return 'TXT';
    }

    return 'UNKNOWN';
  }

  /**
   * Extracts embedded hyperlinks from PDF files without executing any code.
   * Parses PDF URI action dictionaries and plain text streams.
   */
  private extractUrlsFromPdf(buffer: Buffer): string[] {
    const urls: string[] = [];
    const content = buffer.toString('latin1');

    // 1. Extract from PDF URI Action Dictionaries (/Type /Action /S /URI /URI (http...))
    // Standard PDF syntax: /URI (https://phishing-domain.com/login)
    const uriDictRegex = /\/URI\s*\(([^)]+)\)/gi;
    let match: RegExpExecArray | null;
    while ((match = uriDictRegex.exec(content)) !== null) {
      if (match[1]) {
        urls.push(match[1].trim());
      }
    }

    // 2. Extract from Hex-Encoded PDF URIs: /URI <68747470...>
    const hexUriRegex = /\/URI\s*<([0-9a-fA-F]+)>/gi;
    while ((match = hexUriRegex.exec(content)) !== null) {
      try {
        const decoded = Buffer.from(match[1], 'hex').toString('utf-8');
        if (/^https?:\/\//i.test(decoded)) {
          urls.push(decoded.trim());
        }
      } catch {
        // ignore decoding errors
      }
    }

    // 3. Extract plain text URLs from streams
    const textUrls = this.extractUrlsFromPlainText(content);
    urls.push(...textUrls);

    return urls;
  }

  /**
   * Extracts URLs from HTML documents (anchor tags, forms, meta refresh, scripts).
   */
  private extractUrlsFromHtml(buffer: Buffer): string[] {
    const html = buffer.toString('utf-8');
    const urls: string[] = [];

    // Anchor tags: <a href="http...">
    const hrefRegex = /<a\s+[^>]*href=["']([^"']+)["']/gi;
    let match: RegExpExecArray | null;
    while ((match = hrefRegex.exec(html)) !== null) {
      if (match[1] && /^https?:\/\//i.test(match[1])) {
        urls.push(match[1].trim());
      }
    }

    // Form actions: <form action="http...">
    const formRegex = /<form\s+[^>]*action=["']([^"']+)["']/gi;
    while ((match = formRegex.exec(html)) !== null) {
      if (match[1] && /^https?:\/\//i.test(match[1])) {
        urls.push(match[1].trim());
      }
    }

    // Meta refresh: <meta http-equiv="refresh" content="...url=http...">
    const metaRegex = /<meta\s+[^>]*url=([^"'\s>]+)/gi;
    while ((match = metaRegex.exec(html)) !== null) {
      if (match[1] && /^https?:\/\//i.test(match[1])) {
        urls.push(match[1].trim());
      }
    }

    // Also extract raw text URLs
    urls.push(...this.extractUrlsFromPlainText(html));

    return urls;
  }

  /**
   * Extracts hyperlinks from DOCX archives by inspecting relationship files and text streams.
   */
  private extractUrlsFromDocx(buffer: Buffer): string[] {
    const urls: string[] = [];
    const content = buffer.toString('latin1');

    // Target="http..." in word/_rels/document.xml.rels
    const targetRegex = /Target=["'](https?:\/\/[^"'\s<>]+)["']/gi;
    let match: RegExpExecArray | null;
    while ((match = targetRegex.exec(content)) !== null) {
      if (match[1]) {
        urls.push(match[1].trim());
      }
    }

    // Also extract standard text URLs
    urls.push(...this.extractUrlsFromPlainText(content));

    return urls;
  }

  /**
   * Extracts URLs from plain text, supporting defanged indicators (hxxp://, [.], etc.).
   */
  private extractUrlsFromPlainText(text: string): string[] {
    // Refanging
    const refanged = text
      .replace(/hxxps?:\/\//gi, match => (match.toLowerCase().startsWith('hxxps') ? 'https://' : 'http://'))
      .replace(/\[\.\]/g, '.')
      .replace(/\[:\/\/\]/g, '://')
      .replace(/h\*\*p/gi, 'http');

    const urlRegex = /\bhttps?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+/gi;
    const matches = refanged.match(urlRegex) || [];
    return matches.map(u => u.trim());
  }

  /**
   * Cleans, validates, and deduplicates URL strings.
   */
  private sanitizeAndDeduplicateUrls(rawUrls: string[]): string[] {
    const unique = new Set<string>();

    for (let u of rawUrls) {
      // Strip trailing punctuation common in text
      u = u.replace(/[),;.\s"'>]+$/, '');

      try {
        const parsed = new URL(u);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
          unique.add(parsed.href);
        }
      } catch {
        // Skip invalid URLs
      }
    }

    return Array.from(unique);
  }

  private isPrintableText(buf: Buffer): boolean {
    for (let i = 0; i < buf.length; i++) {
      const byte = buf[i];
      // Allow whitespace and printable ASCII
      if (byte === 9 || byte === 10 || byte === 13) continue;
      if (byte < 32 || byte > 126) return false;
    }
    return true;
  }

  private createUnableToAnalyzeResult(
    analysisId: string,
    filename: string,
    detectedFormat: 'PDF' | 'HTML' | 'TXT' | 'DOCX' | 'EML' | 'UNKNOWN',
    fileSizeBytes: number,
    reason: string,
    analyzedAt: string
  ): AttachmentAnalysisResult {
    return {
      analysisId,
      filename,
      detectedFormat,
      fileSizeBytes,
      processingStatus: 'UNABLE_TO_ANALYZE',
      totalUrlsExtracted: 0,
      uniqueUrlsExtracted: 0,
      analyzedUrls: [],
      suspiciousOrMaliciousUrls: [],
      unreachableUrls: [],
      overallVerdict: 'SUSPICIOUS',
      overallRiskScore: 60,
      overallRiskLevel: 'HIGH',
      evidenceReasons: [reason],
      warningNotes: [
        'Security Notice: Could not parse or extract hyperlinks from this attachment. The file should be treated as untrusted and not opened outside an isolated sandbox.'
      ],
      disclaimer:
        'Security Note: Inability to parse an attachment does not mean the file is safe; malformed or password-protected files frequently hide evasive exploit payloads.',
      analyzedAt
    };
  }
}

export const attachmentAnalysisService = new AttachmentAnalysisService();
