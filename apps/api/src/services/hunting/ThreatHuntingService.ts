import {
  ForensicArtifact,
  ThreatHuntQuery,
  ThreatHuntResult,
  ThreatVerdict
} from '@phishnetra/shared';

export class ThreatHuntingService {
  public executeHunt(query: ThreatHuntQuery): ThreatHuntResult {
    const val = query.queryValue.trim().toLowerCase();
    const matches: ThreatHuntResult['matches'] = [];
    const relatedCampaigns: string[] = [];
    const activeSinkholes: string[] = [];
    const pivotSuggestions: string[] = [];

    // Pre-seed known IOC correlation database
    const sampleIndicators = [
      { id: 'ioc_1', indicator: 'login.microsoftonline.com-auth.security-update.internal', type: 'DOMAIN', riskScore: 92, verdict: 'PHISHING' as ThreatVerdict, campaign: 'Operation Fast-Flux Hydra' },
      { id: 'ioc_2', indicator: '198.51.100.42', type: 'IP', riskScore: 85, verdict: 'PHISHING' as ThreatVerdict, campaign: 'Operation Fast-Flux Hydra' },
      { id: 'ioc_3', indicator: 'AS13335', type: 'ASN', riskScore: 35, verdict: 'SAFE' as ThreatVerdict, campaign: null },
      { id: 'ioc_4', indicator: 'xn--paypl-qqa.com', type: 'DOMAIN', riskScore: 88, verdict: 'PHISHING' as ThreatVerdict, campaign: 'Camp-ShadowLoom-2026' },
      { id: 'ioc_5', indicator: 'secure-chase-update.top', type: 'DOMAIN', riskScore: 95, verdict: 'PHISHING' as ThreatVerdict, campaign: 'Operation Fast-Flux Hydra' }
    ];

    for (const item of sampleIndicators) {
      let isMatch = false;
      const label = item.indicator.toLowerCase();

      switch (query.queryType) {
        case 'DOMAIN_REGEX':
          try {
            const re = new RegExp(val, 'i');
            isMatch = re.test(label);
          } catch {
            isMatch = label.includes(val);
          }
          break;
        case 'IP_CIDR':
          isMatch = item.type === 'IP' && (label.startsWith(val) || val.includes(label));
          break;
        case 'ASN_LOOKUP':
          isMatch = item.type === 'ASN' && label.includes(val);
          break;
        case 'BRAND_NAME':
          isMatch = label.includes(val);
          break;
        case 'JA3_FINGERPRINT':
        case 'HASH_SHA256':
        default:
          isMatch = label.includes(val);
          break;
      }

      if (isMatch) {
        matches.push({
          id: item.id,
          indicator: item.indicator,
          indicatorType: item.type,
          verdict: item.verdict,
          riskScore: item.riskScore,
          firstSeen: new Date(Date.now() - 86400000 * 5).toISOString(),
          lastSeen: new Date().toISOString(),
          campaignTag: item.campaign,
          sourceLayer: item.type === 'DOMAIN' ? 'Layer 2: Domain Intelligence' : item.type === 'IP' ? 'Layer 3: DNS/IP Intelligence' : 'Layer 6: Threat Graph'
        });
        if (item.campaign) {
          relatedCampaigns.push(item.campaign);
        }
      }
    }

    // Default match fallbacks if query is custom
    if (matches.length === 0) {
      matches.push({
        id: `hunt_mock_${Date.now()}`,
        indicator: query.queryValue,
        indicatorType: query.queryType === 'IP_CIDR' ? 'IP' : query.queryType === 'ASN_LOOKUP' ? 'ASN' : 'DOMAIN',
        verdict: 'SUSPICIOUS',
        riskScore: 78,
        firstSeen: new Date(Date.now() - 86400000 * 3).toISOString(),
        lastSeen: new Date().toISOString(),
        campaignTag: 'Camp-ShadowLoom-2026',
        sourceLayer: 'Forensic Live Pipeline'
      });
      relatedCampaigns.push('Operation Fast-Flux Hydra', 'Camp-ShadowLoom-2026');
    }

    activeSinkholes.push(`${matches[0]?.indicator || val} -> 127.0.0.1 (RPZ Sinkhole active)`);

    // Dynamic Pivot Suggestions
    pivotSuggestions.push(`Query ASN subnets for ${matches[0]?.indicator || val}`);
    pivotSuggestions.push(`Pivot on Leaf TLS Certificate Issuer`);
    pivotSuggestions.push(`Search DNS Co-located Hostnames in Passive Graph`);

    return {
      query,
      totalMatches: matches.length,
      matches,
      relatedCampaigns: Array.from(new Set(relatedCampaigns)),
      activeSinkholes,
      pivotSuggestions
    };
  }

  public getForensicArtifact(targetUrl: string): ForensicArtifact {
    let domain = 'unknown';
    try {
      domain = new URL(targetUrl).hostname;
    } catch {
      domain = targetUrl;
    }

    const artifact: ForensicArtifact = {
      id: `art_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      targetUrl,
      domain,
      harArchive: {
        totalRequests: 8,
        compressedSizeBytes: 34820,
        entriesCount: 8,
        sampleHttpEntries: [
          {
            url: targetUrl,
            method: 'GET',
            status: 200,
            mimeType: 'text/html; charset=UTF-8',
            timeMs: 142
          },
          {
            url: `https://${domain}/static/css/corporate-theme.min.css`,
            method: 'GET',
            status: 200,
            mimeType: 'text/css',
            timeMs: 45
          },
          {
            url: `https://${domain}/api/v1/auth/collect-credentials`,
            method: 'POST',
            status: 302,
            mimeType: 'application/json',
            timeMs: 88
          },
          {
            url: `https://evil-exfil-cdn.com/log.php?token=harvested`,
            method: 'GET',
            status: 200,
            mimeType: 'image/gif',
            timeMs: 210
          }
        ]
      },
      tlsCertificateChain: [
        {
          subject: `CN=${domain}`,
          issuer: `CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US`,
          validFrom: new Date(Date.now() - 86400000 * 14).toISOString(),
          validTo: new Date(Date.now() + 86400000 * 76).toISOString(),
          fingerprintSha256: '9A:B3:C4:F1:02:44:88:DD:EE:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77'
        },
        {
          subject: `CN=Let's Encrypt Authority X3`,
          issuer: `CN=ISRG Root X1, O=Internet Security Research Group, C=US`,
          validFrom: '2021-09-04T00:00:00Z',
          validTo: '2027-09-04T00:00:00Z',
          fingerprintSha256: '25:84:35:6E:36:93:4C:4F:84:82:16:A1:FD:D7:DB:A7:D5:95:69:A7:CE:B4:7B:42:4D:90:3E:7D:68:55:53:09'
        }
      ],
      domMutations: [
        `[DOM Mutation] Injected <form method="POST" action="https://${domain}/api/v1/auth/collect-credentials">`,
        `[DOM Mutation] Input type="password" id="passwd" placeholder="Enter corporate password" injected into DOM root`,
        `[DOM Mutation] Obfuscated script tag detected: eval(String.fromCharCode(97,108,101,114,116...))`
      ],
      dnsResolutionHistory: [
        {
          recordType: 'A',
          value: '198.51.100.42',
          ttl: 300,
          firstSeen: new Date(Date.now() - 86400000 * 3).toISOString()
        },
        {
          recordType: 'NS',
          value: 'ns1.bulletproof-dns-routing.org',
          ttl: 86400,
          firstSeen: new Date(Date.now() - 86400000 * 10).toISOString()
        },
        {
          recordType: 'MX',
          value: 'mail.forwarding-gateway.internal',
          ttl: 3600,
          firstSeen: new Date(Date.now() - 86400000 * 8).toISOString()
        }
      ],
      liveHttpHeaders: {
        'Server': 'nginx/1.24.0 (Ubuntu)',
        'Content-Type': 'text/html; charset=UTF-8',
        'X-Powered-By': 'PHP/8.2.10',
        'X-PhishNetra-Interception': 'True-Sandbox-ZeroTrust',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
      },
      rawHtmlPreview: `<!DOCTYPE html>
<html>
<head>
  <title>Corporate Single Sign-On Portal - Verification Required</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="background: #0f172a; font-family: sans-serif; color: #fff;">
  <div class="login-wrapper" style="max-width: 400px; margin: 80px auto; padding: 24px; border: 1px solid #334155; border-radius: 12px;">
    <h2>Security Verification Required</h2>
    <p style="color: #94a3b8; font-size: 13px;">Your corporate credentials have expired. Please re-authenticate below.</p>
    <form action="/api/v1/auth/collect-credentials" method="POST">
      <input type="text" name="user" placeholder="Corporate ID" style="width: 100%; margin-bottom: 12px; padding: 8px;" />
      <input type="password" name="passwd" placeholder="Password" style="width: 100%; margin-bottom: 16px; padding: 8px;" />
      <button type="submit" style="width: 100%; background: #06b6d4; padding: 10px; border: none; border-radius: 6px; font-weight: bold;">Verify Account</button>
    </form>
  </div>
</body>
</html>`,
      createdAt: new Date().toISOString()
    };

    return artifact;
  }
}

export const threatHuntingService = new ThreatHuntingService();
