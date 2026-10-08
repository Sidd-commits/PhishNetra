import {
  SOCCase,
  CreateCaseRequest,
  UpdateCaseRequest,
  RemediationType,
  RemediationResult,
  CaseTimelineEvent
} from '@phishnetra/shared';

export class CaseManagementService {
  private cases: Map<string, SOCCase> = new Map();

  constructor() {
    this.seedDefaultCases();
  }

  private seedDefaultCases() {
    const case1: SOCCase = {
      id: 'CASE-2026-0819',
      title: 'Active Credential Harvesting Campaign Targeting Chase Banking Customers',
      description: 'Multiple deceptive subdomains detected impersonating Chase login portals with cross-origin credential posting to rogue IP infrastructure.',
      status: 'INVESTIGATING',
      severity: 'CRITICAL',
      assignedAnalyst: 'Alex Morgan (Tier 2 SOC)',
      targetUrl: 'http://192.168.1.100/admin/chase-login.php',
      targetDomain: 'secure-chase-update.top',
      linkedAnalysisId: 'ana_sample_01',
      linkedCampaignId: 'cmp_sample_01',
      iocs: {
        domains: ['secure-chase-update.top', 'chase-security-verify.xyz', 'auth-chase-online.live'],
        ips: ['192.168.1.100', '198.51.100.42'],
        urls: ['http://192.168.1.100/admin/chase-login.php'],
        hashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']
      },
      timeline: [
        {
          id: 'tl_1',
          timestamp: new Date(Date.now() - 3600000 * 4).toISOString(),
          actor: 'PhishNetra Real-Time Sensor',
          action: 'AUTOMATED_INGESTION',
          details: 'High-confidence brand domain mismatch flagged on secure-chase-update.top.'
        },
        {
          id: 'tl_2',
          timestamp: new Date(Date.now() - 3600000 * 2).toISOString(),
          actor: 'Alex Morgan',
          action: 'ASSIGNMENT_UPDATED',
          details: 'Case escalated to Tier 2 incident response. Threat campaign cluster correlated.'
        }
      ],
      notes: [
        {
          id: 'note_1',
          author: 'Alex Morgan',
          text: 'Threat actors are using obfuscated JavaScript eval routines to evade naive signature inspection. Sinkhole rules prepared.',
          timestamp: new Date(Date.now() - 3600000).toISOString()
        }
      ],
      remediationActions: [],
      createdAt: new Date(Date.now() - 3600000 * 4).toISOString(),
      updatedAt: new Date(Date.now() - 3600000).toISOString(),
      closedAt: null
    };

    this.cases.set(case1.id, case1);
  }

  public listCases(filters?: { status?: string; severity?: string }): SOCCase[] {
    let list = Array.from(this.cases.values());
    if (filters?.status && filters.status !== 'ALL') {
      list = list.filter(c => c.status === filters.status);
    }
    if (filters?.severity && filters.severity !== 'ALL') {
      list = list.filter(c => c.severity === filters.severity);
    }
    return list.sort((a, b) => Date.parse(b.updatedAt) - Date.parse(a.updatedAt));
  }

  public getCase(id: string): SOCCase | undefined {
    return this.cases.get(id);
  }

  public createCase(req: CreateCaseRequest): SOCCase {
    const caseNumber = Math.floor(1000 + Math.random() * 9000);
    const id = `CASE-${new Date().getFullYear()}-${caseNumber}`;
    const now = new Date().toISOString();

    const newCase: SOCCase = {
      id,
      title: req.title,
      description: req.description,
      status: 'OPEN',
      severity: req.severity || 'HIGH',
      assignedAnalyst: req.assignedAnalyst || 'Unassigned',
      targetUrl: req.targetUrl || null,
      targetDomain: req.targetDomain || null,
      linkedAnalysisId: req.linkedAnalysisId || null,
      linkedCampaignId: req.linkedCampaignId || null,
      iocs: {
        domains: req.targetDomain ? [req.targetDomain] : [],
        ips: [],
        urls: req.targetUrl ? [req.targetUrl] : [],
        hashes: []
      },
      timeline: [
        {
          id: `tl_${Date.now()}`,
          timestamp: now,
          actor: 'SOC Analyst Console',
          action: 'CASE_CREATED',
          details: `Case opened with ${req.severity} severity.`
        }
      ],
      notes: [],
      remediationActions: [],
      createdAt: now,
      updatedAt: now,
      closedAt: null
    };

    this.cases.set(id, newCase);
    return newCase;
  }

  public updateCase(id: string, req: UpdateCaseRequest): SOCCase {
    const existing = this.cases.get(id);
    if (!existing) {
      throw new Error(`Case '${id}' not found`);
    }

    const now = new Date().toISOString();

    if (req.status && req.status !== existing.status) {
      existing.timeline.push({
        id: `tl_${Date.now()}`,
        timestamp: now,
        actor: 'SOC Analyst',
        action: 'STATUS_CHANGED',
        details: `Status transition from ${existing.status} -> ${req.status}`
      });
      existing.status = req.status;
      if (req.status === 'RESOLVED' || req.status === 'FALSE_POSITIVE') {
        existing.closedAt = now;
      }
    }

    if (req.severity) {
      existing.severity = req.severity;
    }

    if (req.assignedAnalyst) {
      existing.assignedAnalyst = req.assignedAnalyst;
    }

    if (req.note) {
      existing.notes.push({
        id: `note_${Date.now()}`,
        author: req.assignedAnalyst || 'SOC Analyst',
        text: req.note,
        timestamp: now
      });
    }

    existing.updatedAt = now;
    this.cases.set(id, existing);
    return existing;
  }

  public addNote(id: string, author: string, text: string): SOCCase {
    const existing = this.cases.get(id);
    if (!existing) {
      throw new Error(`Case '${id}' not found`);
    }

    const now = new Date().toISOString();
    existing.notes.push({
      id: `note_${Date.now()}`,
      author,
      text,
      timestamp: now
    });
    existing.updatedAt = now;
    return existing;
  }

  public executeRemediation(caseId: string, actionType: RemediationType): RemediationResult {
    const c = this.cases.get(caseId);
    if (!c) {
      throw new Error(`Case '${caseId}' not found`);
    }

    const now = new Date().toISOString();
    const domain = c.targetDomain || c.iocs.domains[0] || 'malicious-domain.xyz';
    const ip = c.iocs.ips[0] || '198.51.100.25';

    let artifact = '';
    let instructions = '';

    switch (actionType) {
      case 'DNS_SINKHOLE':
        artifact = `# PhishNetra Response Policy Zone (RPZ) Sinkhole Rule\n# Case: ${c.id}\n${domain} CNAME sinkhole.phishnetra.internal.\n*.${domain} CNAME sinkhole.phishnetra.internal.`;
        instructions = 'Apply this DNS RPZ record to internal recursive DNS resolvers (BIND9, Unbound, PowerDNS) to safely divert employee queries.';
        break;

      case 'FIREWALL_BLOCK':
        artifact = `# Linux iptables drop rules\niptables -A OUTPUT -d ${ip} -j DROP\niptables -A FORWARD -d ${ip} -j DROP\n\n# Suricata / Snort IDS Rule\ndrop http any any -> [${ip}] any (msg:"PhishNetra - Blocked Malicious Phishing Domain ${domain}"; flow:to_server; content:"${domain}"; http_header; sid:9000101; rev:1;)`;
        instructions = 'Deploy these firewall block and perimeter IDS/IPS signatures across perimeter gateways.';
        break;

      case 'TAKEDOWN_NOTICE':
        artifact = `ATTN: Abuse Department & Domain Host Security\n\nSUBJECT: URGENT: Cease and Desist / Malicious Phishing Infrastructure Takedown Notice [Ref: ${c.id}]\n\nWe have identified active malicious phishing activity hosted on your infrastructure:\n- Malicious Domain: ${domain}\n- Associated Target URL: ${c.targetUrl || 'N/A'}\n- Target IP: ${ip}\n- Target Brand Impersonated: Chase Financial\n\nEvidence confirms active credential theft violating ICANN and registrar terms of service.\nPlease suspend domain resolution and preserve log telemetry immediately.\n\nPhishNetra Incident Response & Threat Mitigation Office`;
        instructions = 'Send this formal abuse notice to the registrar abuse contact (via RDAP/Whois) and hosting provider CERT.';
        break;

      case 'DOMAIN_REGISTRAR_REPORT':
        artifact = `ICANN Abuse Report Submission\nDomain: ${domain}\nCategory: Phishing & Credential Harvest\nEvidence Ref: ${c.id}\nReporter: PhishNetra Zero-Trust Threat Intelligence Platform`;
        instructions = 'Submit through ICANN / Global Registrar Abuse Portal for expedited domain lock.';
        break;

      case 'EDR_ISOLATE':
        artifact = `EDR Network Containment Policy\nScope: All endpoints communicating with ${domain} (${ip})\nAction: BLOCK_AND_ISOLATE\nRule ID: EDR-${c.id}`;
        instructions = 'Execute via CrowdStrike Falcon / Microsoft Defender for Endpoint API to isolate affected hosts.';
        break;
    }

    const result: RemediationResult = {
      actionType,
      target: domain,
      generatedArtifact: artifact,
      instructions,
      executedAt: now,
      status: 'GENERATED'
    };

    c.remediationActions.push(result);
    c.timeline.push({
      id: `tl_${Date.now()}`,
      timestamp: now,
      actor: 'SOC Analyst Console',
      action: 'REMEDIATION_ACTION_GENERATED',
      details: `Generated ${actionType} remediation defense artifacts for ${domain}.`
    });
    c.updatedAt = now;

    return result;
  }
}

export const caseManagementService = new CaseManagementService();
