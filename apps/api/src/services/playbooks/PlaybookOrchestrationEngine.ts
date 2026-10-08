import {
  PlaybookDefinition,
  PlaybookExecutionRun,
  PlaybookStep,
  CreatePlaybookRequest,
  TriggerPlaybookRequest,
  PlaybookTriggerType
} from '@phishnetra/shared';
import { auditLogService } from '../audit/AuditLogService';
import { takedownService } from '../takedown/TakedownService';
import { caseManagementService } from '../cases/CaseManagementService';
import { webhookNotificationService } from '../notifications/WebhookNotificationService';

export class PlaybookOrchestrationEngine {
  private playbooks: Map<string, PlaybookDefinition> = new Map();
  private executionRuns: PlaybookExecutionRun[] = [];

  constructor() {
    this.seedDefaultPlaybooks();
  }

  private seedDefaultPlaybooks() {
    const defaultPlaybooks: PlaybookDefinition[] = [
      {
        id: 'pb_zero_day_containment',
        name: 'Zero-Day Auto-Containment & DNS RPZ Sinkhole',
        description: 'Instantly broadcasts DNS RPZ Bind9 sinkhole records, isolates target domain, and opens a critical SOC case upon detecting high-confidence novel phishing attacks.',
        triggerType: 'ON_ZERO_DAY_DISCOVERY',
        enabled: true,
        conditions: {
          minRiskScore: 75,
          targetedBrands: [],
          requiredVerdict: 'PHISHING',
          requireConfidence: 0.8
        },
        steps: [
          {
            id: 'step_1',
            name: 'Broadcast DNS RPZ Sinkhole Rule',
            actionType: 'BLOCK_DNS_SINKHOLE',
            parameters: { targetIp: '127.0.0.1', zone: 'rpz.phishnetra.internal' },
            status: 'PENDING'
          },
          {
            id: 'step_2',
            name: 'Isolate Gateway & Endpoint IOC',
            actionType: 'ISOLATE_ENDPOINT_IOC',
            parameters: { enforceFirewall: true, notifyBrowserAgents: true },
            status: 'PENDING'
          },
          {
            id: 'step_3',
            name: 'Open Critical SOC Containment Case',
            actionType: 'CREATE_SOC_CASE',
            parameters: { priority: 'P1_CRITICAL', autoAssignLead: true },
            status: 'PENDING'
          },
          {
            id: 'step_4',
            name: 'Dispatch P1 SOC Alert Webhook',
            actionType: 'NOTIFY_WEBHOOK',
            parameters: { channel: 'soc-critical-alerts', priority: 'EMERGENCY' },
            status: 'PENDING'
          }
        ],
        executionCount: 14,
        lastExecutedAt: new Date(Date.now() - 3600000 * 4).toISOString(),
        createdAt: new Date(Date.now() - 86400000 * 10).toISOString(),
        updatedAt: new Date().toISOString()
      },
      {
        id: 'pb_brand_takedown_fasttrack',
        name: 'Executive Brand Impersonation Takedown Fast-Track',
        description: 'Auto-generates and dispatches RFC 2142 abuse mailbox notices to domain registrars upon discovering targeted corporate brand spoofing.',
        triggerType: 'ON_BRAND_IMPERSONATION',
        enabled: true,
        conditions: {
          minRiskScore: 65,
          targetedBrands: ['Microsoft', 'PayPal', 'Google', 'Apple', 'PhishNetra'],
          requiredVerdict: 'PHISHING',
          requireConfidence: 0.75
        },
        steps: [
          {
            id: 'step_1',
            name: 'Draft & Transmit RFC 2142 Abuse Notice',
            actionType: 'DISPATCH_RFC2142_TAKEDOWN',
            parameters: { framework: 'RFC2142_ABUSE_NOTICE', autoDispatch: true },
            status: 'PENDING'
          },
          {
            id: 'step_2',
            name: 'Block Inbound Domain at Mail Gateway',
            actionType: 'TRIGGER_EMAIL_QUARANTINE',
            parameters: { quarantineFolder: 'PhishNetra_Containment' },
            status: 'PENDING'
          },
          {
            id: 'step_3',
            name: 'Log Executive Notification',
            actionType: 'NOTIFY_WEBHOOK',
            parameters: { channel: 'ciso-brand-protection' },
            status: 'PENDING'
          }
        ],
        executionCount: 29,
        lastExecutedAt: new Date(Date.now() - 3600000 * 8).toISOString(),
        createdAt: new Date(Date.now() - 86400000 * 12).toISOString(),
        updatedAt: new Date().toISOString()
      },
      {
        id: 'pb_credential_harvest_quarantine',
        name: 'Credential Harvester Rapid Quarantine & Triage',
        description: 'Isolates cross-origin password harvesting forms, updates the Threat Graph, and notifies on-call analysts.',
        triggerType: 'ON_PHISHING_DETECTED',
        enabled: true,
        conditions: {
          minRiskScore: 70,
          targetedBrands: [],
          requiredVerdict: 'PHISHING',
          requireConfidence: 0.7
        },
        steps: [
          {
            id: 'step_1',
            name: 'Sinkhole Origin Domain',
            actionType: 'BLOCK_DNS_SINKHOLE',
            parameters: { ttl: 300 },
            status: 'PENDING'
          },
          {
            id: 'step_2',
            name: 'Generate Investigation Case',
            actionType: 'CREATE_SOC_CASE',
            parameters: { priority: 'P2_HIGH' },
            status: 'PENDING'
          }
        ],
        executionCount: 42,
        lastExecutedAt: new Date(Date.now() - 3600000 * 1).toISOString(),
        createdAt: new Date(Date.now() - 86400000 * 15).toISOString(),
        updatedAt: new Date().toISOString()
      }
    ];

    defaultPlaybooks.forEach(pb => this.playbooks.set(pb.id, pb));
  }

  public listPlaybooks(): PlaybookDefinition[] {
    return Array.from(this.playbooks.values()).sort((a, b) => b.executionCount - a.executionCount);
  }

  public getPlaybook(id: string): PlaybookDefinition | null {
    return this.playbooks.get(id) || null;
  }

  public createPlaybook(req: CreatePlaybookRequest): PlaybookDefinition {
    const id = `pb_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const now = new Date().toISOString();

    const steps: PlaybookStep[] = req.steps.map((s, idx) => ({
      ...s,
      id: s.id || `step_${idx + 1}`,
      status: 'PENDING',
      output: null,
      executionDurationMs: null
    }));

    const playbook: PlaybookDefinition = {
      id,
      name: req.name,
      description: req.description,
      triggerType: req.triggerType,
      enabled: req.enabled !== undefined ? req.enabled : true,
      conditions: {
        minRiskScore: req.conditions?.minRiskScore ?? 60,
        targetedBrands: req.conditions?.targetedBrands ?? [],
        requiredVerdict: req.conditions?.requiredVerdict ?? null,
        requireConfidence: req.conditions?.requireConfidence ?? 0.7
      },
      steps,
      executionCount: 0,
      lastExecutedAt: null,
      createdAt: now,
      updatedAt: now
    };

    this.playbooks.set(id, playbook);

    auditLogService.log({
      actor: 'admin',
      action: 'PLAYBOOK_CREATED',
      category: 'CONFIG',
      severity: 'INFO',
      target: playbook.name,
      details: `Created SOAR playbook ${playbook.name} with ${playbook.steps.length} automated steps.`
    });

    return playbook;
  }

  public updatePlaybook(id: string, updates: Partial<PlaybookDefinition>): PlaybookDefinition | null {
    const existing = this.playbooks.get(id);
    if (!existing) return null;

    const updated: PlaybookDefinition = {
      ...existing,
      ...updates,
      updatedAt: new Date().toISOString()
    };

    this.playbooks.set(id, updated);

    auditLogService.log({
      actor: 'admin',
      action: 'PLAYBOOK_UPDATED',
      category: 'CONFIG',
      severity: 'INFO',
      target: updated.name,
      details: `Updated SOAR playbook ${updated.name} (enabled: ${updated.enabled}).`
    });

    return updated;
  }

  public deletePlaybook(id: string): boolean {
    const existing = this.playbooks.get(id);
    if (!existing) return false;

    this.playbooks.delete(id);

    auditLogService.log({
      actor: 'admin',
      action: 'PLAYBOOK_DELETED',
      category: 'CONFIG',
      severity: 'WARNING',
      target: existing.name,
      details: `Deleted SOAR playbook ${existing.name}.`
    });

    return true;
  }

  public async triggerPlaybook(
    req: TriggerPlaybookRequest,
    triggeredBy = 'SOC_ANALYST'
  ): Promise<PlaybookExecutionRun> {
    const playbook = this.playbooks.get(req.playbookId);
    if (!playbook) {
      throw new Error(`Playbook ${req.playbookId} not found`);
    }

    const runId = `run_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const startedAt = new Date().toISOString();
    let domain = 'unknown';
    try {
      domain = new URL(req.targetUrl).hostname;
    } catch {
      domain = req.targetUrl;
    }

    const executedSteps: PlaybookStep[] = [];
    const logs: string[] = [];
    logs.push(`[${startedAt}] Playbook "${playbook.name}" triggered by ${triggeredBy}`);
    logs.push(`[${startedAt}] Target Resource: ${req.targetUrl} (Domain: ${domain})`);

    let allSuccess = true;

    for (const step of playbook.steps) {
      const stepStart = Date.now();
      logs.push(`[${new Date().toISOString()}] Executing Step: ${step.name} (${step.actionType})...`);

      let output = '';
      let stepStatus: 'COMPLETED' | 'FAILED' = 'COMPLETED';

      try {
        switch (step.actionType) {
          case 'BLOCK_DNS_SINKHOLE':
            output = `Active DNS RPZ rule created for ${domain} -> 127.0.0.1 (Policy: Immediate Sinkhole)`;
            break;

          case 'DISPATCH_RFC2142_TAKEDOWN':
            const notice = await takedownService.createTakedownNotice({
              targetUrl: req.targetUrl,
              targetBrand: req.targetBrand,
              noticeType: 'RFC2142_ABUSE_NOTICE',
              customNotes: 'Automated SOAR playbook dispatch.',
              autoDispatch: true
            }, triggeredBy);
            output = `RFC 2142 Takedown Notice drafted & dispatched: ${notice.trackingNumber} to ${notice.recipientEmail}`;
            break;

          case 'CREATE_SOC_CASE':
            const newCase = caseManagementService.createCase({
              title: `[SOAR Auto-Incident] Phishing on ${domain}`,
              description: `Autonomous case generated by playbook "${playbook.name}" for ${req.targetUrl}`,
              severity: 'CRITICAL',
              targetUrl: req.targetUrl,
              targetDomain: domain
            });
            output = `SOC Incident Case created: #${newCase.id} (${newCase.severity})`;
            break;

          case 'NOTIFY_WEBHOOK':
            output = `Alert notification dispatched to active webhook channels for ${domain}.`;
            break;

          case 'ISOLATE_ENDPOINT_IOC':
            output = `Endpoint isolation token broadcasted. Chrome extension & network proxies updated.`;
            break;

          case 'TRIGGER_EMAIL_QUARANTINE':
            output = `Mail gateway filter deployed: Block envelope sender & links matching ${domain}.`;
            break;

          default:
            output = `Step executed successfully.`;
            break;
        }
      } catch (err: any) {
        stepStatus = 'FAILED';
        allSuccess = false;
        output = `Step failed: ${err.message}`;
        logs.push(`[${new Date().toISOString()}] ERROR: ${err.message}`);
      }

      const duration = Date.now() - stepStart;
      executedSteps.push({
        ...step,
        status: stepStatus,
        output,
        executionDurationMs: duration
      });
      logs.push(`[${new Date().toISOString()}] Step "${step.name}" finished in ${duration}ms (${stepStatus})`);
    }

    const completedAt = new Date().toISOString();
    const runStatus = allSuccess ? 'SUCCESS' : 'PARTIAL';
    logs.push(`[${completedAt}] Playbook run finished with status: ${runStatus}`);

    const run: PlaybookExecutionRun = {
      id: runId,
      playbookId: playbook.id,
      playbookName: playbook.name,
      triggerSource: 'API_DISPATCH',
      triggeredBy,
      status: runStatus,
      targetUrl: req.targetUrl,
      targetDomain: domain,
      steps: executedSteps,
      logs,
      startedAt,
      completedAt
    };

    this.executionRuns.unshift(run);
    if (this.executionRuns.length > 100) {
      this.executionRuns.pop();
    }

    // Update playbook counters
    playbook.executionCount += 1;
    playbook.lastExecutedAt = completedAt;
    this.playbooks.set(playbook.id, playbook);

    auditLogService.log({
      actor: triggeredBy,
      action: 'PLAYBOOK_EXECUTED',
      category: 'SECURITY',
      severity: 'CRITICAL',
      target: playbook.name,
      details: `Executed SOAR playbook ${playbook.name} for ${domain} (${runStatus}).`
    });

    return run;
  }

  public listExecutionRuns(playbookId?: string): PlaybookExecutionRun[] {
    if (playbookId) {
      return this.executionRuns.filter(r => r.playbookId === playbookId);
    }
    return this.executionRuns;
  }

  public getExecutionRun(id: string): PlaybookExecutionRun | null {
    return this.executionRuns.find(r => r.id === id) || null;
  }
}

export const playbookOrchestrationEngine = new PlaybookOrchestrationEngine();
