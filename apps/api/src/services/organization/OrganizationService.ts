import {
  OrganizationWorkspace,
  TeamMember,
  OrganizationRole
} from '@phishnetra/shared';
import { auditLogService } from '../audit/AuditLogService';

export class OrganizationService {
  private workspace: OrganizationWorkspace;

  constructor() {
    this.workspace = {
      id: 'org_phishnetra_soc',
      name: 'Apex Global Security Operations Center',
      slug: 'apex-global-soc',
      plan: 'ENTERPRISE_SOC',
      memberCount: 4,
      monthlyScanQuota: 50000,
      usedScansThisMonth: 12480,
      members: [
        {
          id: 'usr_001',
          name: 'Sarah Connor',
          email: 's.connor@apex-security.internal',
          role: 'OWNER',
          joinedAt: '2026-01-15T08:00:00.000Z',
          lastActiveAt: new Date().toISOString()
        },
        {
          id: 'usr_002',
          name: 'Alex Mercer',
          email: 'a.mercer@apex-security.internal',
          role: 'SECURITY_ADMIN',
          joinedAt: '2026-02-01T09:30:00.000Z',
          lastActiveAt: new Date().toISOString()
        },
        {
          id: 'usr_003',
          name: 'David Lightman',
          email: 'd.lightman@apex-security.internal',
          role: 'SOC_ANALYST',
          joinedAt: '2026-03-10T14:15:00.000Z',
          lastActiveAt: new Date().toISOString()
        },
        {
          id: 'usr_004',
          name: 'Elena Rostova',
          email: 'e.rostova@apex-security.internal',
          role: 'AUDITOR',
          joinedAt: '2026-04-05T11:00:00.000Z',
          lastActiveAt: new Date().toISOString()
        }
      ],
      securityPolicy: {
        mfaEnforced: true,
        ipAllowlist: ['192.168.1.0/24', '10.50.0.0/16'],
        autoSinkholingEnabled: true,
        retentionDays: 365
      },
      createdAt: '2026-01-15T08:00:00.000Z'
    };
  }

  public async getWorkspace(): Promise<OrganizationWorkspace> {
    return this.workspace;
  }

  public async updateSecurityPolicy(
    policy: Partial<OrganizationWorkspace['securityPolicy']>,
    actor = 'admin'
  ): Promise<OrganizationWorkspace> {
    this.workspace.securityPolicy = {
      ...this.workspace.securityPolicy,
      ...policy
    };

    auditLogService.log({
      actor,
      action: 'ORGANIZATION_POLICY_UPDATED',
      category: 'CONFIG',
      severity: 'WARNING',
      target: this.workspace.slug,
      details: `Updated workspace security policy: MFA=${this.workspace.securityPolicy.mfaEnforced}, AutoSinkhole=${this.workspace.securityPolicy.autoSinkholingEnabled}`
    });

    return this.workspace;
  }

  public async inviteMember(
    name: string,
    email: string,
    role: OrganizationRole,
    actor = 'admin'
  ): Promise<TeamMember> {
    const newMember: TeamMember = {
      id: `usr_${Date.now()}`,
      name,
      email,
      role,
      joinedAt: new Date().toISOString(),
      lastActiveAt: new Date().toISOString()
    };

    this.workspace.members.push(newMember);
    this.workspace.memberCount = this.workspace.members.length;

    auditLogService.log({
      actor,
      action: 'TEAM_MEMBER_INVITED',
      category: 'SECURITY',
      severity: 'INFO',
      target: email,
      details: `Invited new team member ${name} (${email}) as ${role}`
    });

    return newMember;
  }

  public async removeMember(memberId: string, actor = 'admin'): Promise<boolean> {
    const initialLen = this.workspace.members.length;
    this.workspace.members = this.workspace.members.filter(m => m.id !== memberId);
    this.workspace.memberCount = this.workspace.members.length;

    const removed = this.workspace.members.length < initialLen;
    if (removed) {
      auditLogService.log({
        actor,
        action: 'TEAM_MEMBER_REMOVED',
        category: 'SECURITY',
        severity: 'WARNING',
        target: memberId,
        details: `Removed team member ${memberId} from workspace`
      });
    }

    return removed;
  }
}

export const organizationService = new OrganizationService();
