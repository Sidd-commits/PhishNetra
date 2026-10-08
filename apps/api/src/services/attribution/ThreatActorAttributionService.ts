import {
  ThreatActorProfile,
  AttributionMatchResult,
  AttributionMatchItem
} from '@phishnetra/shared';
import crypto from 'crypto';
import { auditLogService } from '../audit/AuditLogService';

export class ThreatActorAttributionService {
  private threatActors: ThreatActorProfile[] = [
    {
      actorId: 'SCATTERED_SPIDER',
      actorName: 'Scattered Spider (UNC3944)',
      aliases: ['UNC3944', 'Octo Tempest', '0ktapus', 'Scatter Swine'],
      originCountry: 'Transnational (US/UK/Global)',
      primaryTargets: ['Identity Providers (Okta/Azure AD)', 'Telecoms', 'Cloud Infrastructure', 'Gaming'],
      mitreAttckTTPs: ['T1566.002', 'T1583.001', 'T1621', 'T1110.003', 'T1078.004'],
      infrastructurePatterns: {
        asns: ['AS13335', 'AS14061', 'AS16276'],
        tlds: ['.sso', '.live', '.vip', '.help', '.support'],
        registries: ['Namecheap', 'Porkbun', 'Cloudflare']
      },
      knownSignatures: [
        'Evilginx reverse proxy for Okta SSO',
        'SMS phishing helpdesk lures (smishing)',
        'MFA push notification fatigue',
        'SIM swapping telecom escalation'
      ]
    },
    {
      actorId: 'APT28',
      actorName: 'APT28 (Fancy Bear)',
      aliases: ['Fancy Bear', 'Pawn Storm', 'Sofacy', 'Sednit', 'Forest Blizzard'],
      originCountry: 'Russia (GRU 85th GTsSS)',
      primaryTargets: ['Government', 'Defense Industrial Base', 'Diplomatic Missions', 'NATO'],
      mitreAttckTTPs: ['T1566.002', 'T1583.008', 'T1071.001', 'T1059.001', 'T1528'],
      infrastructurePatterns: {
        asns: ['AS200019', 'AS49981', 'AS9009'],
        tlds: ['.com', '.org', '.net', '.info'],
        registries: ['Njalla', 'Tucows', 'Hostinger']
      },
      knownSignatures: [
        'OAuth Device Authorization Grant abuse',
        'Round-robin DNS dynamic C2 proxies',
        'Spoofed Webmail/RoundCube portals'
      ]
    },
    {
      actorId: 'APT29',
      actorName: 'APT29 (Midnight Blizzard)',
      aliases: ['Midnight Blizzard', 'Nobelium', 'Cozy Bear', 'The Dukes'],
      originCountry: 'Russia (SVR)',
      primaryTargets: ['Cloud Identity Tenants', 'Foreign Ministries', 'IT Service Providers'],
      mitreAttckTTPs: ['T1078.004', 'T1566.002', 'T1538', 'T1586.002', 'T1098.002'],
      infrastructurePatterns: {
        asns: ['AS16509', 'AS8075', 'AS24940'],
        tlds: ['.cloud', '.azure', '.com', '.ms'],
        registries: ['GoDaddy', 'MarkMonitor', 'Amazon']
      },
      knownSignatures: [
        'Multi-tenant Azure App Registration consent theft',
        'Password spraying on non-MFA administrative accounts',
        'Residential proxy residential IP routing'
      ]
    },
    {
      actorId: 'LAZARUS_GROUP',
      actorName: 'Lazarus Group (Hidden Cobra)',
      aliases: ['Hidden Cobra', 'Labyrinth Chollima', 'Zinc', 'APT38'],
      originCountry: 'North Korea (RGB)',
      primaryTargets: ['Cryptocurrency Exchanges', 'Fintech', 'Aerospace', 'Defense'],
      mitreAttckTTPs: ['T1566.001', 'T1204.002', 'T1027', 'T1105', 'T1140'],
      infrastructurePatterns: {
        asns: ['AS9009', 'AS4134', 'AS4837'],
        tlds: ['.link', '.xyz', '.top', '.space'],
        registries: ['Public Domain Registry', 'NameSilo', 'Epik']
      },
      knownSignatures: [
        'LinkedIn recruiter lure PDFs with embedded macro payloads',
        'Malicious open-source npm/PyPI supply chain poisoning',
        'Targeted Web3 browser wallet seed phrase extractors'
      ]
    },
    {
      actorId: 'FIN7',
      actorName: 'FIN7 (Sangria Tempest)',
      aliases: ['Sangria Tempest', 'Carbanak', 'Navigator Group'],
      originCountry: 'Eastern Europe',
      primaryTargets: ['Hospitality', 'Retail Point-of-Sale', 'Restaurants', 'Finance'],
      mitreAttckTTPs: ['T1566.002', 'T1059.003', 'T1055', 'T1082', 'T1132.001'],
      infrastructurePatterns: {
        asns: ['AS48008', 'AS204957', 'AS51167'],
        tlds: ['.site', '.biz', '.cc', '.online'],
        registries: ['Reg.ru', 'Hostinger', 'Internet.bs']
      },
      knownSignatures: [
        'Spoofed supplier food order invoices',
        'Obfuscated PowerShell memory injectors (LNK files)',
        'Point-of-sale memory scraper backdoors'
      ]
    }
  ];

  public listThreatActors(): ThreatActorProfile[] {
    return this.threatActors;
  }

  public getThreatActor(actorId: string): ThreatActorProfile | null {
    return this.threatActors.find(a => a.actorId.toUpperCase() === actorId.toUpperCase()) || null;
  }

  public matchThreatActor(params: {
    targetDomain: string;
    ttps?: string[];
    asn?: string;
  }): AttributionMatchResult {
    const queryId = `attr-${crypto.randomUUID()}`;
    const analyzedAt = new Date().toISOString();
    const domainLower = params.targetDomain.toLowerCase();

    const matches: AttributionMatchItem[] = this.threatActors.map(actor => {
      let confidence = 20; // baseline heuristic
      const matchedTTPs: string[] = [];
      const matchedInfra: string[] = [];

      // 1. TTP Overlap Evaluation
      if (params.ttps && params.ttps.length > 0) {
        for (const ttp of params.ttps) {
          if (actor.mitreAttckTTPs.includes(ttp)) {
            matchedTTPs.push(ttp);
            confidence += 15;
          }
        }
      } else {
        // Assume default phishing delivery TTP match
        matchedTTPs.push('T1566.002');
        confidence += 10;
      }

      // 2. ASN Infrastructure Matching
      if (params.asn && actor.infrastructurePatterns.asns.includes(params.asn)) {
        matchedInfra.push(`ASN Match: ${params.asn}`);
        confidence += 25;
      }

      // 3. TLD / Domain Heuristic Matching
      for (const tld of actor.infrastructurePatterns.tlds) {
        if (domainLower.endsWith(tld)) {
          matchedInfra.push(`TLD Pattern: ${tld}`);
          confidence += 15;
          break;
        }
      }

      // 4. Keyword / Brand Target Matching
      if (
        (domainLower.includes('okta') || domainLower.includes('sso') || domainLower.includes('duo')) &&
        actor.actorId === 'SCATTERED_SPIDER'
      ) {
        matchedInfra.push('High-affinity Okta/Identity lure matching Scattered Spider campaign profile');
        confidence += 30;
      } else if (
        (domainLower.includes('microsoft') || domainLower.includes('azure') || domainLower.includes('tenant')) &&
        actor.actorId === 'APT29'
      ) {
        matchedInfra.push('Cloud tenant identity harvesting matching Midnight Blizzard profile');
        confidence += 25;
      } else if (
        (domainLower.includes('crypto') || domainLower.includes('wallet') || domainLower.includes('coin')) &&
        actor.actorId === 'LAZARUS_GROUP'
      ) {
        matchedInfra.push('Cryptocurrency financial lure pattern matching Lazarus Group profile');
        confidence += 30;
      }

      confidence = Math.min(96, Math.max(15, confidence));

      return {
        actorId: actor.actorId,
        actorName: actor.actorName,
        attributionConfidence: confidence,
        matchedTTPs,
        matchedInfrastructure: matchedInfra,
        adversaryDiamondModel: {
          adversary: `${actor.actorName} (${actor.originCountry})`,
          capability: actor.knownSignatures[0] || 'Phishing / Credential Harvest Proxy',
          infrastructure: matchedInfra.join(', ') || 'Dynamic cloud hosting and anonymized DNS',
          victimology: actor.primaryTargets.join(', ')
        }
      };
    });

    // Sort by confidence descending
    matches.sort((a, b) => b.attributionConfidence - a.attributionConfidence);

    // Build MITRE Heatmap
    const mitreHeatmap: Record<string, number> = {};
    for (const match of matches) {
      for (const ttp of match.matchedTTPs) {
        mitreHeatmap[ttp] = (mitreHeatmap[ttp] || 0) + 1;
      }
    }

    const topMatch = matches[0];
    const attributionVerdict = topMatch && topMatch.attributionConfidence >= 65
      ? `High-confidence attribution to ${topMatch.actorName} (${topMatch.attributionConfidence}% confidence).`
      : `Moderate correlation to ${topMatch?.actorName || 'Untracked Actor'} based on TTP and infrastructure similarity.`;

    auditLogService.log({
      actor: 'SYSTEM',
      action: 'THREAT_ACTOR_ATTRIBUTION_PERFORMED',
      details: JSON.stringify({
        queryId,
        targetDomain: params.targetDomain,
        topActor: topMatch?.actorName,
        confidence: topMatch?.attributionConfidence
      }),
      category: 'ANALYSIS',
      severity: 'INFO'
    });

    return {
      queryId,
      analyzedAt,
      targetDomain: params.targetDomain,
      topMatches: matches,
      attributionVerdict,
      mitreHeatmap
    };
  }
}

export const threatActorAttributionService = new ThreatActorAttributionService();
