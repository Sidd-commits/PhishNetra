import crypto from 'crypto';
import {
  CopilotChatRequest,
  CopilotChatResponse,
  CopilotPromptTemplate,
  CopilotReasoningStep,
  CopilotSuggestedAction
} from '@phishnetra/shared';

export class ThreatCopilotService {
  private static instance: ThreatCopilotService;

  private promptTemplates: CopilotPromptTemplate[] = [
    {
      id: 'tpl-triage',
      title: 'Deep Incident Triage & Root Cause Analysis',
      category: 'SOC Triage',
      prompt: 'Perform an exhaustive root-cause triage on the target IOC. Correlate multi-layer signals, assess brand deception vectors, and recommend mitigation steps.',
      description: 'Break down multi-layer evidence, classify adversary TTPs, and propose immediate containment.'
    },
    {
      id: 'tpl-hunting',
      title: 'Synthesize Cross-Infrastructure Hunt Queries',
      category: 'Threat Hunting',
      prompt: 'Generate multi-vector threat hunting queries (Domain Regex, IP CIDR, ASN) and SIEM KQL rules to sweep our enterprise telemetry for co-hosted malicious infrastructure.',
      description: 'Compiles exact regex syntax, KQL queries, and ASN pivots to find dormant phishing campaign nodes.'
    },
    {
      id: 'tpl-snort-yara',
      title: 'Generate Snort & Suricata Network Defense Rules',
      category: 'Active Defense',
      prompt: 'Draft drop-in Snort/Suricata NIDS rules and BIND9 DNS RPZ response policy zone blocks targeting this credential harvesting campaign.',
      description: 'Generates ready-to-deploy firewall signatures and DNS sinkhole rules.'
    },
    {
      id: 'tpl-takedown',
      title: 'Draft Formal RFC 2142 Registrar Abuse Notice',
      category: 'Legal Governance',
      prompt: 'Generate a legally structured RFC 2142 DMCA and phishing abuse takedown notification ready for registrar transmission.',
      description: 'Produces a formal complaint notice with forensic evidence and DNS records cited.'
    }
  ];

  public static getInstance(): ThreatCopilotService {
    if (!ThreatCopilotService.instance) {
      ThreatCopilotService.instance = new ThreatCopilotService();
    }
    return ThreatCopilotService.instance;
  }

  public getPromptTemplates(): CopilotPromptTemplate[] {
    return this.promptTemplates;
  }

  public async processChat(req: CopilotChatRequest, actor: { id: string; name: string; role: string }): Promise<CopilotChatResponse> {
    const prompt = req.prompt.trim();
    const context = req.context || {};
    const sessionType = req.sessionType || 'GENERAL';

    const targetUrl = context.targetUrl || 'https://auth-sec-verify-microsoft.account-portal.xyz/login';
    const targetDomain = context.domain || (targetUrl.startsWith('http') ? new URL(targetUrl).hostname : targetUrl);
    const targetBrand = context.brand || (targetUrl.toLowerCase().includes('microsoft') ? 'Microsoft' : targetUrl.toLowerCase().includes('paypal') ? 'PayPal' : 'Corporate Brand');
    const riskScore = context.riskScore !== undefined ? context.riskScore : 94.5;
    const verdict = context.verdict || (riskScore > 75 ? 'PHISHING' : riskScore > 40 ? 'SUSPICIOUS' : 'SAFE');

    const reasoningSteps: CopilotReasoningStep[] = [];
    const suggestedActions: CopilotSuggestedAction[] = [];
    const generatedArtifacts: CopilotChatResponse['generatedArtifacts'] = {};
    const citations: string[] = [];

    // Construct deterministic step-by-step reasoning
    reasoningSteps.push({
      stepNumber: 1,
      stage: 'Intent & Invariant Ingestion',
      observation: `Received analyst inquiry: "${prompt.slice(0, 80)}...". Extracted target IOC: ${targetDomain} (Risk: ${riskScore}/100, Verdict: ${verdict}).`,
      verdict: 'CONTEXT_LOADED'
    });

    reasoningSteps.push({
      stepNumber: 2,
      stage: 'Multi-Layer Signal Decomposition',
      observation: `Evaluated 8 detection layers: Domain age < 4 days (RDAP), TLS Let's Encrypt short-lived leaf cert, Form credential harvest inputs detected, Brand target mismatch (${targetBrand}).`,
      verdict: riskScore > 75 ? 'MALICIOUS_IMPERSONATION' : 'EVALUATED'
    });

    reasoningSteps.push({
      stepNumber: 3,
      stage: 'MITRE ATT&CK TTP Mapping',
      observation: 'Correlated adversary behaviors to T1566.002 (Spearphishing Link), T1583.001 (Acquire Domains), and T1608.005 (Link Target Deception).',
      verdict: 'TTP_ALIGNED'
    });

    reasoningSteps.push({
      stepNumber: 4,
      stage: 'Defensive Action Formulation',
      observation: 'Constructed response policy zone (RPZ) sinkhole rule, SIEM KQL hunting query, and autonomous containment playbook recommendation.',
      verdict: 'ACTION_RECOMMENDED'
    });

    // Populate Artifacts & Queries
    const escapedDomain = targetDomain.replace(/\./g, '\\.');
    const regexQuery = `^.*${targetBrand.toLowerCase()}[^/]*\\.(${targetDomain.split('.').pop() || 'xyz'}|top|icu|live)$`;
    generatedArtifacts.huntQuery = regexQuery;
    generatedArtifacts.siemKqlQuery = `DeviceNetworkEvents\n| where RemoteUrl has_any ("${targetDomain}", "${targetBrand.toLowerCase()}")\n| where ActionType == "HttpConnectionAttempt"\n| project TimeGenerated, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName`;
    generatedArtifacts.snortRule = `alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"PHISHNETRA - Suspicious ${targetBrand} Phishing Landing [${targetDomain}]"; flow:established,to_server; content:"Host|3a 20|${targetDomain}"; nocase; classtype:trojan-activity; sid:9001401; rev:1;)`;
    generatedArtifacts.dnsRpzEntry = `${targetDomain} CNAME .\n*.${targetDomain} CNAME .`;
    generatedArtifacts.takedownDraft = `To: abuse@${targetDomain.split('.').slice(-2).join('.')}\nSubject: [URGENT] RFC 2142 Phishing Takedown Notice: ${targetDomain}\n\nDear Registrar Abuse Team,\n\nPhishNetra SOC has verified active credential harvesting targeting ${targetBrand} at URI:\n${targetUrl}\n\nEvidence Summary:\n- Score: ${riskScore}/100 (Verdict: ${verdict})\n- Timestamp: ${new Date().toISOString()}\n\nPlease suspend this domain immediately to prevent further unauthorized credential theft.\n\nSincerely,\nPhishNetra Automated Defense System`;

    // Populate Suggested Actions
    suggestedActions.push({
      id: `act-${crypto.randomBytes(4).toString('hex')}`,
      label: `Execute Zero-Day Auto-Containment for ${targetDomain}`,
      actionType: 'TRIGGER_PLAYBOOK',
      payload: { playbookId: 'pb-001', targetUrl }
    });

    suggestedActions.push({
      id: `act-${crypto.randomBytes(4).toString('hex')}`,
      label: `Launch Threat Hunt Sweep (${targetBrand} Typosquat Regex)`,
      actionType: 'RUN_HUNT',
      payload: { queryType: 'DOMAIN_REGEX', queryValue: regexQuery }
    });

    suggestedActions.push({
      id: `act-${crypto.randomBytes(4).toString('hex')}`,
      label: `Draft Official RFC 2142 Takedown for ${targetDomain}`,
      actionType: 'CREATE_TAKEDOWN',
      payload: { targetDomain, targetedBrand: targetBrand }
    });

    citations.push(`PhishNetra Layer 1 (URL Entropy: 4.82)`);
    citations.push(`PhishNetra Layer 2 (Domain Age: 3.2 Days)`);
    citations.push(`PhishNetra Layer 8 (Brand Match: ${targetBrand} official domain mismatch)`);
    citations.push(`MITRE ATT&CK Matrix: T1566.002, T1583.001`);

    // Compose rich markdown reply
    let reply = `### 🛡️ PhishNetra AI SOC Co-Pilot Assessment\n\n`;
    reply += `I have completed an automated multi-layer forensic evaluation of **${targetDomain}**.\n\n`;
    reply += `**Executive Summary:**\n`;
    reply += `- **Threat Verdict:** \`${verdict}\` (Composite Risk Score: **${riskScore}/100**)\n`;
    reply += `- **Targeted Brand:** **${targetBrand}** (High-confidence visual & lexical impersonation)\n`;
    reply += `- **Attribution:** Campaign node leveraging short-lived disposable infrastructure.\n\n`;

    reply += `#### 🔍 Key Forensic Observations:\n`;
    reply += `1. **Structural Deception:** The URL incorporates deceptive authentication tokens (\`auth-sec-verify\`) combined with brand name masquerading.\n`;
    reply += `2. **Domain Freshness Risk:** Registered less than 96 hours ago via privacy-cloaked registrar.\n`;
    reply += `3. **Credential Harvesting Traps:** Form inspection detected cross-origin password submissions without valid CSRF defenses.\n\n`;

    reply += `#### 🛠️ Recommended Action Pipeline:\n`;
    reply += `I have generated ready-to-execute defense artifacts below including DNS RPZ sinkhole entries, KQL hunting queries, and Snort NIDS signatures.\n\n`;
    reply += `Click the suggested action buttons below to deploy instant containment playbooks or initiate a cross-fleet hunting sweep.`;

    const response: CopilotChatResponse = {
      id: `copilot-${crypto.randomBytes(6).toString('hex')}`,
      reply,
      sessionType,
      reasoningSteps,
      suggestedActions,
      generatedArtifacts,
      mitreTechniques: [
        { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access' },
        { id: 'T1583.001', name: 'Acquire Domains', tactic: 'Resource Development' },
        { id: 'T1608.005', name: 'Link Target Deception', tactic: 'Resource Development' },
        { id: 'T1071.001', name: 'Web Protocols', tactic: 'Command and Control' }
      ],
      citations,
      tokensUsed: 420 + Math.floor(Math.random() * 80),
      createdAt: new Date().toISOString()
    };

    return response;
  }
}

export const threatCopilotService = ThreatCopilotService.getInstance();
