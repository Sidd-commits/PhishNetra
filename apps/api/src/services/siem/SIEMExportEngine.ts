import {
  AnalysisResponse,
  ThreatCampaign,
  SIEMFormat,
  SIEMExportResult
} from '@phishnetra/shared';

export class SIEMExportEngine {
  /**
   * Formats threat intelligence analyses and campaigns into standard SIEM/SOAR log formats.
   */
  public exportEvents(
    format: SIEMFormat,
    analyses: AnalysisResponse[],
    campaigns: ThreatCampaign[] = []
  ): SIEMExportResult {
    const timestamp = new Date().toISOString();

    switch (format) {
      case 'CEF':
        return this.formatCEF(analyses, campaigns, timestamp);
      case 'LEEF':
        return this.formatLEEF(analyses, campaigns, timestamp);
      case 'SYSLOG_RFC5424':
        return this.formatSyslog(analyses, campaigns, timestamp);
      case 'SENTINEL_JSON':
        return this.formatSentinel(analyses, campaigns, timestamp);
      case 'SPLUNK_HEC':
        return this.formatSplunkHEC(analyses, campaigns, timestamp);
      default:
        return this.formatCEF(analyses, campaigns, timestamp);
    }
  }

  private formatCEF(analyses: AnalysisResponse[], campaigns: ThreatCampaign[], timestamp: string): SIEMExportResult {
    const lines: string[] = [];

    // Format individual threat analyses
    for (const ana of analyses) {
      const severity = ana.verdict === 'PHISHING' ? 9 : (ana.verdict === 'SUSPICIOUS' ? 6 : 2);
      const domain = ana.layers?.domain?.registrableDomain || 'unknown';
      const ip = ana.layers?.dns?.resolvedIps?.[0] || '';
      const action = ana.verdict === 'PHISHING' ? 'BLOCKED' : 'ALERTED';

      const cefLine =
        `CEF:0|PhishNetra|ZeroTrustThreatEngine|1.0|PHISHNETRA_SCAN_${ana.verdict}|${ana.verdict} URL Detected|${severity}|` +
        `msg=${this.escapeCEF(ana.summary || 'Threat scan evaluated')} ` +
        `request=${ana.url} ` +
        `dhost=${domain} ` +
        (ip ? `dst=${ip} ` : '') +
        `cs1Label=Verdict cs1=${ana.verdict} ` +
        `cn1Label=RiskScore cn1=${ana.riskScore} ` +
        `cs2Label=RiskLevel cs2=${ana.riskLevel} ` +
        `cs3Label=Confidence cs3=${(ana.confidence * 100).toFixed(1)}% ` +
        `act=${action} ` +
        `externalId=${ana.analysisId} ` +
        `rt=${Date.parse(ana.createdAt || timestamp)}`;

      lines.push(cefLine);
    }

    // Format campaigns
    for (const cmp of campaigns) {
      const severity = cmp.riskLevel === 'CRITICAL' ? 10 : (cmp.riskLevel === 'HIGH' ? 8 : 5);
      const cefLine =
        `CEF:0|PhishNetra|ZeroTrustThreatEngine|1.0|CAMPAIGN_CLUSTER|Threat Campaign Clustered|${severity}|` +
        `msg=${this.escapeCEF(cmp.name + ': ' + cmp.description)} ` +
        `cs1Label=CampaignName cs1=${this.escapeCEF(cmp.name)} ` +
        `cs2Label=TargetBrands cs2=${this.escapeCEF(cmp.targetedBrands.join(','))} ` +
        `cn1Label=DomainCount cn1=${cmp.domainCount} ` +
        `cn2Label=IPCount cn2=${cmp.ipCount} ` +
        `act=CORRELATED ` +
        `externalId=${cmp.id} ` +
        `rt=${Date.parse(cmp.lastSeen || timestamp)}`;

      lines.push(cefLine);
    }

    return {
      format: 'CEF',
      generatedAt: timestamp,
      eventCount: lines.length,
      formattedOutput: lines.join('\n'),
      contentType: 'text/plain; charset=utf-8'
    };
  }

  private formatLEEF(analyses: AnalysisResponse[], campaigns: ThreatCampaign[], timestamp: string): SIEMExportResult {
    const lines: string[] = [];

    for (const ana of analyses) {
      const severity = ana.verdict === 'PHISHING' ? 9 : (ana.verdict === 'SUSPICIOUS' ? 6 : 2);
      const domain = ana.layers?.domain?.registrableDomain || 'unknown';
      const ip = ana.layers?.dns?.resolvedIps?.[0] || '';

      const leefLine =
        `LEEF:2.0|PhishNetra|ThreatMitigation|1.0|${ana.verdict}|\t` +
        `devTimeFormat=yyyy-MM-dd'T'HH:mm:ss.SSSZ\t` +
        `devTime=${ana.createdAt || timestamp}\t` +
        `url=${ana.url}\t` +
        `domain=${domain}\t` +
        (ip ? `dstIp=${ip}\t` : '') +
        `verdict=${ana.verdict}\t` +
        `riskScore=${ana.riskScore}\t` +
        `riskLevel=${ana.riskLevel}\t` +
        `confidence=${ana.confidence}\t` +
        `sev=${severity}\t` +
        `analysisId=${ana.analysisId}`;

      lines.push(leefLine);
    }

    for (const cmp of campaigns) {
      const severity = cmp.riskLevel === 'CRITICAL' ? 10 : 7;
      const leefLine =
        `LEEF:2.0|PhishNetra|ThreatMitigation|1.0|CAMPAIGN_CLUSTER|\t` +
        `devTimeFormat=yyyy-MM-dd'T'HH:mm:ss.SSSZ\t` +
        `devTime=${cmp.lastSeen || timestamp}\t` +
        `campaignId=${cmp.id}\t` +
        `campaignName=${cmp.name}\t` +
        `targetBrands=${cmp.targetedBrands.join(',')}\t` +
        `domainCount=${cmp.domainCount}\t` +
        `ipCount=${cmp.ipCount}\t` +
        `sev=${severity}`;

      lines.push(leefLine);
    }

    return {
      format: 'LEEF',
      generatedAt: timestamp,
      eventCount: lines.length,
      formattedOutput: lines.join('\n'),
      contentType: 'text/plain; charset=utf-8'
    };
  }

  private formatSyslog(analyses: AnalysisResponse[], campaigns: ThreatCampaign[], timestamp: string): SIEMExportResult {
    const lines: string[] = [];

    for (const ana of analyses) {
      const pri = ana.verdict === 'PHISHING' ? 131 : (ana.verdict === 'SUSPICIOUS' ? 132 : 134);
      const jsonPayload = JSON.stringify({
        event: 'PHISHNETRA_THREAT_SCAN',
        analysisId: ana.analysisId,
        url: ana.url,
        verdict: ana.verdict,
        riskScore: ana.riskScore,
        riskLevel: ana.riskLevel,
        confidence: ana.confidence,
        summary: ana.summary,
        evidenceCount: ana.evidence?.length || 0,
        domain: ana.layers?.domain?.registrableDomain,
        resolvedIps: ana.layers?.dns?.resolvedIps || []
      });

      lines.push(`<${pri}>1 ${timestamp} phishnetra-soc phishnetra-core - - - ${jsonPayload}`);
    }

    for (const cmp of campaigns) {
      const jsonPayload = JSON.stringify({
        event: 'PHISHNETRA_CAMPAIGN_CLUSTER',
        campaignId: cmp.id,
        name: cmp.name,
        targetBrands: cmp.targetedBrands,
        domainCount: cmp.domainCount,
        ipCount: cmp.ipCount,
        riskLevel: cmp.riskLevel,
        severityScore: cmp.severityScore
      });

      lines.push(`<131>1 ${timestamp} phishnetra-soc phishnetra-campaign - - - ${jsonPayload}`);
    }

    return {
      format: 'SYSLOG_RFC5424',
      generatedAt: timestamp,
      eventCount: lines.length,
      formattedOutput: lines.join('\n'),
      contentType: 'text/plain; charset=utf-8'
    };
  }

  private formatSentinel(analyses: AnalysisResponse[], campaigns: ThreatCampaign[], timestamp: string): SIEMExportResult {
    const events: any[] = [];

    for (const ana of analyses) {
      events.push({
        TimeGenerated: ana.createdAt || timestamp,
        EventVendor: 'PhishNetra',
        EventProduct: 'ZeroTrust Threat Mitigation Platform',
        EventSchemaVersion: '1.0',
        EventType: 'PhishingDetection',
        ThreatName: `${ana.verdict} URL Scan`,
        DestinationUrl: ana.url,
        DestinationDomain: ana.layers?.domain?.registrableDomain || '',
        DestinationIp: ana.layers?.dns?.resolvedIps?.[0] || '',
        MaliciousScore: ana.riskScore,
        ConfidenceScore: ana.confidence,
        RiskLevel: ana.riskLevel,
        Verdict: ana.verdict,
        ActionTaken: ana.verdict === 'PHISHING' ? 'Blocked' : 'Monitored',
        AnalysisId: ana.analysisId,
        EvidenceList: ana.evidence?.map(e => (e as any).title || e.description || e.featureKey) || [],
        Summary: ana.summary
      });
    }

    for (const cmp of campaigns) {
      events.push({
        TimeGenerated: cmp.lastSeen || timestamp,
        EventVendor: 'PhishNetra',
        EventProduct: 'ZeroTrust Threat Mitigation Platform',
        EventType: 'CampaignClustering',
        ThreatName: `Threat Campaign: ${cmp.name}`,
        CampaignId: cmp.id,
        TargetedBrands: cmp.targetedBrands,
        DomainCount: cmp.domainCount,
        IpCount: cmp.ipCount,
        RiskLevel: cmp.riskLevel,
        SeverityScore: cmp.severityScore,
        Description: cmp.description
      });
    }

    return {
      format: 'SENTINEL_JSON',
      generatedAt: timestamp,
      eventCount: events.length,
      formattedOutput: JSON.stringify(events, null, 2),
      contentType: 'application/json'
    };
  }

  private formatSplunkHEC(analyses: AnalysisResponse[], campaigns: ThreatCampaign[], timestamp: string): SIEMExportResult {
    const hecEvents: any[] = [];

    for (const ana of analyses) {
      hecEvents.push({
        time: Math.floor(Date.parse(ana.createdAt || timestamp) / 1000),
        host: 'phishnetra-sensor-01',
        source: 'phishnetra:threat:engine',
        sourcetype: 'phishnetra:url:alert',
        event: {
          analysisId: ana.analysisId,
          url: ana.url,
          verdict: ana.verdict,
          riskScore: ana.riskScore,
          riskLevel: ana.riskLevel,
          confidence: ana.confidence,
          summary: ana.summary,
          domain: ana.layers?.domain?.registrableDomain,
          dnsIps: ana.layers?.dns?.resolvedIps || [],
          evidenceCount: ana.evidence?.length || 0
        }
      });
    }

    for (const cmp of campaigns) {
      hecEvents.push({
        time: Math.floor(Date.parse(cmp.lastSeen || timestamp) / 1000),
        host: 'phishnetra-cluster-01',
        source: 'phishnetra:threat:campaigns',
        sourcetype: 'phishnetra:campaign:alert',
        event: {
          campaignId: cmp.id,
          name: cmp.name,
          targetedBrands: cmp.targetedBrands,
          domainCount: cmp.domainCount,
          ipCount: cmp.ipCount,
          riskLevel: cmp.riskLevel,
          severityScore: cmp.severityScore,
          description: cmp.description
        }
      });
    }

    return {
      format: 'SPLUNK_HEC',
      generatedAt: timestamp,
      eventCount: hecEvents.length,
      formattedOutput: hecEvents.map(e => JSON.stringify(e)).join('\n'),
      contentType: 'application/json'
    };
  }

  private escapeCEF(str: string): string {
    return str.replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\|/g, '\\|');
  }
}

export const siemExportEngine = new SIEMExportEngine();
