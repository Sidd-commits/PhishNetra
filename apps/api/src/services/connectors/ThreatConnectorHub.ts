import {
  ThreatConnectorStatus,
  ThreatConnectorType
} from '@phishnetra/shared';
import { auditLogService } from '../audit/AuditLogService';

export class ThreatConnectorHub {
  private connectors: Map<string, ThreatConnectorStatus> = new Map();

  constructor() {
    this.seedDefaultConnectors();
  }

  private seedDefaultConnectors() {
    const defaultConnectors: ThreatConnectorStatus[] = [
      {
        id: 'conn_taxii21_cisa',
        name: 'CISA Automated Indicator Sharing (TAXII 2.1)',
        type: 'TAXII21_FEED',
        endpointUrl: 'https://taxii.cisa.gov/taxii2/collections/ais-threat-indicators',
        enabled: true,
        pollIntervalMinutes: 30,
        lastPollAt: new Date(Date.now() - 3600000 * 2).toISOString(),
        totalIocsIngested: 8450,
        status: 'HEALTHY'
      },
      {
        id: 'conn_misp_circl',
        name: 'CIRCL MISP Community Threat Sharing Hub',
        type: 'MISP_COMMUNITY',
        endpointUrl: 'https://misp.circl.lu/events/restSearch',
        enabled: true,
        pollIntervalMinutes: 60,
        lastPollAt: new Date(Date.now() - 3600000 * 3).toISOString(),
        totalIocsIngested: 12390,
        status: 'HEALTHY'
      },
      {
        id: 'conn_alienvault_otx',
        name: 'AlienVault OTX Community Pulse Exchange',
        type: 'ALIENVAULT_OTX',
        endpointUrl: 'https://otx.alienvault.com/api/v1/pulses/subscribed',
        enabled: true,
        pollIntervalMinutes: 15,
        lastPollAt: new Date(Date.now() - 1800000).toISOString(),
        totalIocsIngested: 21500,
        status: 'HEALTHY'
      },
      {
        id: 'conn_abuse_ipdb',
        name: 'AbuseIPDB High-Confidence Malicious IP Feed',
        type: 'ABUSE_IPDB',
        endpointUrl: 'https://api.abuseipdb.com/api/v2/blacklist',
        enabled: false,
        pollIntervalMinutes: 120,
        lastPollAt: null,
        totalIocsIngested: 0,
        status: 'HEALTHY'
      }
    ];

    defaultConnectors.forEach(c => this.connectors.set(c.id, c));
  }

  public listConnectors(): ThreatConnectorStatus[] {
    return Array.from(this.connectors.values());
  }

  public getConnector(id: string): ThreatConnectorStatus | null {
    return this.connectors.get(id) || null;
  }

  public async syncConnector(id: string, actor = 'admin'): Promise<ThreatConnectorStatus> {
    const conn = this.connectors.get(id);
    if (!conn) {
      throw new Error(`Threat connector ${id} not found`);
    }

    conn.status = 'SYNCING';
    this.connectors.set(id, conn);

    // Simulate polling & ingestion
    const newIocs = Math.floor(Math.random() * 45) + 10;
    conn.totalIocsIngested += newIocs;
    conn.lastPollAt = new Date().toISOString();
    conn.status = 'HEALTHY';
    this.connectors.set(id, conn);

    auditLogService.log({
      actor,
      action: 'CONNECTOR_SYNCED',
      category: 'SECURITY',
      severity: 'INFO',
      target: conn.name,
      details: `Synchronized ${conn.name}: +${newIocs} indicators ingested.`
    });

    return conn;
  }

  public async syncAllConnectors(actor = 'system'): Promise<ThreatConnectorStatus[]> {
    const results: ThreatConnectorStatus[] = [];
    for (const [id, conn] of this.connectors) {
      if (conn.enabled) {
        const synced = await this.syncConnector(id, actor);
        results.push(synced);
      }
    }
    return results;
  }

  public toggleConnector(id: string, enabled: boolean, actor = 'admin'): ThreatConnectorStatus {
    const conn = this.connectors.get(id);
    if (!conn) {
      throw new Error(`Threat connector ${id} not found`);
    }

    conn.enabled = enabled;
    this.connectors.set(id, conn);

    auditLogService.log({
      actor,
      action: 'CONNECTOR_TOGGLED',
      category: 'CONFIG',
      severity: 'INFO',
      target: conn.name,
      details: `${enabled ? 'Enabled' : 'Disabled'} Threat Connector: ${conn.name}.`
    });

    return conn;
  }
}

export const threatConnectorHub = new ThreatConnectorHub();
