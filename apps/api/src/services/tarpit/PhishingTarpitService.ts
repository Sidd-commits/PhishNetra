import crypto from 'crypto';
import {
  LaunchTarpitTaskRequest,
  PoisonedCredential,
  TarpitTask
} from '@phishnetra/shared';
import { auditLogService } from '../audit/AuditLogService';

export class PhishingTarpitService {
  private static instance: PhishingTarpitService;

  private tasks: Map<string, TarpitTask> = new Map();

  constructor() {
    this.seedDefaultTasks();
  }

  public static getInstance(): PhishingTarpitService {
    if (!PhishingTarpitService.instance) {
      PhishingTarpitService.instance = new PhishingTarpitService();
    }
    return PhishingTarpitService.instance;
  }

  private generatePoisonedCredentials(count: number, brand: string = 'Microsoft'): PoisonedCredential[] {
    const firstNames = ['james', 'sarah', 'michael', 'elizabeth', 'david', 'jennifer', 'robert', 'emily', 'william', 'jessica'];
    const lastNames = ['miller', 'davis', 'wilson', 'anderson', 'taylor', 'thomas', 'jackson', 'white', 'harris', 'martin'];
    const domains = ['enterprise.corp', 'global-defense.org', 'cloud-ops.net', 'finance-holdings.com'];

    const credentials: PoisonedCredential[] = [];
    const now = Date.now();

    for (let i = 0; i < count; i++) {
      const fn = firstNames[Math.floor(Math.random() * firstNames.length)];
      const ln = lastNames[Math.floor(Math.random() * lastNames.length)];
      const num = Math.floor(Math.random() * 899) + 100;
      const dom = domains[Math.floor(Math.random() * domains.length)];
      const canaryId = crypto.randomBytes(3).toString('hex');

      credentials.push({
        id: `cred-${crypto.randomBytes(4).toString('hex')}`,
        username: `${fn}.${ln}${num}@${dom}`,
        password: `Ph#N3tra_${crypto.randomBytes(4).toString('base64').replace(/[+/=]/g, '')}!${num}`,
        otpCode: String(Math.floor(100000 + Math.random() * 900000)),
        canaryTag: `CANARY-POISON-${canaryId.toUpperCase()}`,
        injectedAt: new Date(now - (count - i) * 800).toISOString(),
        submissionStatus: Math.random() > 0.05 ? 'SENT' : 'RATE_LIMITED',
        responseLatencyMs: 320 + Math.floor(Math.random() * 650) + i * 12
      });
    }

    return credentials;
  }

  private seedDefaultTasks(): void {
    const sampleCreds = this.generatePoisonedCredentials(45, 'Microsoft');
    const defaultTask: TarpitTask = {
      id: 'tarpit-001',
      targetUrl: 'https://auth-sec-verify-microsoft.account-portal.xyz/login.php',
      targetFormAction: 'https://auth-sec-verify-microsoft.account-portal.xyz/harvest_post.php',
      status: 'ACTIVE',
      concurrency: 8,
      totalCredentialsInjected: 1250,
      targetExhaustionRate: 84.5,
      meanAdversaryLatencyMs: 840.2,
      adversaryStatusCode: 504,
      poisonedCredentials: sampleCreds.slice(-15),
      startedAt: new Date(Date.now() - 3600 * 1000 * 2).toISOString(),
      stoppedAt: null
    };

    this.tasks.set(defaultTask.id, defaultTask);
  }

  public listTasks(): TarpitTask[] {
    return Array.from(this.tasks.values()).sort(
      (a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime()
    );
  }

  public getTask(id: string): TarpitTask | null {
    return this.tasks.get(id) || null;
  }

  public launchTask(req: LaunchTarpitTaskRequest, actor: { id: string; name: string }): TarpitTask {
    const id = `tarpit-${crypto.randomBytes(4).toString('hex')}`;
    const now = new Date().toISOString();
    const count = Math.min(req.credentialsCount || 50, 500);
    const creds = this.generatePoisonedCredentials(count, req.targetBrand || 'Corporate');

    const task: TarpitTask = {
      id,
      targetUrl: req.targetUrl,
      targetFormAction: req.targetFormAction,
      status: 'ACTIVE',
      concurrency: req.concurrency || 5,
      totalCredentialsInjected: count,
      targetExhaustionRate: 65.0,
      meanAdversaryLatencyMs: 580.4,
      adversaryStatusCode: 200,
      poisonedCredentials: creds,
      startedAt: now,
      stoppedAt: null
    };

    this.tasks.set(id, task);

    auditLogService.log({
      actor: actor.name,
      action: 'LAUNCH_PHISHING_TARPIT',
      category: 'REMEDIATION',
      target: id,
      details: `Launched synthetic credential tarpit against ${req.targetUrl} (${count} injected credentials)`,
      severity: 'WARNING'
    });

    return task;
  }

  public stopTask(id: string, actor: { id: string; name: string }): TarpitTask | null {
    const task = this.tasks.get(id);
    if (!task) return null;

    task.status = 'STOPPED';
    task.stoppedAt = new Date().toISOString();
    this.tasks.set(id, task);

    auditLogService.log({
      actor: actor.name,
      action: 'STOP_PHISHING_TARPIT',
      category: 'REMEDIATION',
      target: id,
      details: `Stopped credential tarpit flooder ${id}`,
      severity: 'INFO'
    });

    return task;
  }
}

export const phishingTarpitService = PhishingTarpitService.getInstance();
