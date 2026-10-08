import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { useToast } from '../context/ToastContext';
import { OrganizationWorkspace, OrganizationRole, TeamMember } from '@phishnetra/shared';
import {
  Users,
  Shield,
  Lock,
  Key,
  Plus,
  Trash2,
  CheckCircle2,
  AlertCircle,
  Building2,
  RefreshCw,
  Sliders,
  Mail,
  UserCheck
} from 'lucide-react';

export const OrganizationPage: React.FC = () => {
  const { showToast } = useToast();
  const [workspace, setWorkspace] = useState<OrganizationWorkspace | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  // Invite Modal
  const [showInviteModal, setShowInviteModal] = useState<boolean>(false);
  const [inviteName, setInviteName] = useState<string>('');
  const [inviteEmail, setInviteEmail] = useState<string>('');
  const [inviteRole, setInviteRole] = useState<OrganizationRole>('SOC_ANALYST');
  const [isInviting, setIsInviting] = useState<boolean>(false);

  useEffect(() => {
    fetchWorkspace();
  }, []);

  const fetchWorkspace = async () => {
    try {
      setLoading(true);
      const ws = await api.getWorkspace();
      setWorkspace(ws);
    } catch (err: any) {
      showToast('error', 'Failed to load organization', err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleTogglePolicy = async (key: keyof OrganizationWorkspace['securityPolicy'], value: any) => {
    if (!workspace) return;
    try {
      const updated = await api.updateWorkspacePolicy({ [key]: value });
      setWorkspace(updated);
      showToast('success', 'Security Policy Updated', `Updated ${key} to ${value}`);
    } catch (err: any) {
      showToast('error', 'Policy Update Failed', err.message);
    }
  };

  const handleInviteMember = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteName.trim() || !inviteEmail.trim()) return;

    try {
      setIsInviting(true);
      const member = await api.inviteTeamMember(inviteName.trim(), inviteEmail.trim(), inviteRole);
      showToast('success', 'Member Invited', `Invited ${member.name} (${member.role})`);
      setShowInviteModal(false);
      setInviteName('');
      setInviteEmail('');
      fetchWorkspace();
    } catch (err: any) {
      showToast('error', 'Invite Failed', err.message);
    } finally {
      setIsInviting(false);
    }
  };

  const handleRemoveMember = async (memberId: string) => {
    if (!window.confirm('Are you sure you want to remove this member from the organization?')) return;
    try {
      await api.removeTeamMember(memberId);
      showToast('success', 'Member Removed', 'Team member removed from workspace.');
      fetchWorkspace();
    } catch (err: any) {
      showToast('error', 'Removal Failed', err.message);
    }
  };

  const getRoleBadge = (role: OrganizationRole) => {
    switch (role) {
      case 'OWNER':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">Owner</span>;
      case 'SECURITY_ADMIN':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">Security Admin</span>;
      case 'SOC_ANALYST':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">SOC Analyst</span>;
      case 'AUDITOR':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">Auditor</span>;
      default:
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-slate-500/20 text-slate-300 border border-slate-500/30">Viewer</span>;
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 bg-gradient-to-tr from-indigo-500 to-cyan-500 rounded-xl shadow-lg shadow-indigo-500/20">
              <Building2 className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Organization & Team Workspaces</h1>
              <p className="text-xs text-slate-400 font-mono">Multi-tenant SOC management, role-based access control (RBAC), and security policies</p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => fetchWorkspace()}
            className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => setShowInviteModal(true)}
            className="px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/20 flex items-center space-x-2 transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span>Invite Team Member</span>
          </button>
        </div>
      </div>

      {workspace && (
        <div className="space-y-8">
          {/* Top Metric Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 space-y-2">
              <span className="text-[10px] font-mono uppercase text-slate-500">Active Workspace</span>
              <h3 className="text-lg font-bold text-white">{workspace.name}</h3>
              <div className="flex items-center space-x-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                  {workspace.plan}
                </span>
                <span className="text-xs text-slate-400">• {workspace.memberCount} active members</span>
              </div>
            </div>

            <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 space-y-2">
              <span className="text-[10px] font-mono uppercase text-slate-500">Monthly Scan Capacity</span>
              <div className="flex items-baseline justify-between">
                <h3 className="text-lg font-bold text-cyan-400">{workspace.usedScansThisMonth.toLocaleString()}</h3>
                <span className="text-xs text-slate-500">/ {workspace.monthlyScanQuota.toLocaleString()} quota</span>
              </div>
              <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden">
                <div
                  className="bg-cyan-400 h-full rounded-full transition-all"
                  style={{ width: `${(workspace.usedScansThisMonth / workspace.monthlyScanQuota) * 100}%` }}
                />
              </div>
            </div>

            <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 space-y-2">
              <span className="text-[10px] font-mono uppercase text-slate-500">Security Governance</span>
              <div className="space-y-1 text-xs text-slate-300">
                <div className="flex justify-between">
                  <span>MFA Enforcement</span>
                  <strong className={workspace.securityPolicy.mfaEnforced ? 'text-emerald-400' : 'text-slate-500'}>
                    {workspace.securityPolicy.mfaEnforced ? 'STRICT' : 'OPTIONAL'}
                  </strong>
                </div>
                <div className="flex justify-between">
                  <span>Autonomous Sinkhole</span>
                  <strong className="text-cyan-400">{workspace.securityPolicy.autoSinkholingEnabled ? 'ACTIVE' : 'DISABLED'}</strong>
                </div>
              </div>
            </div>
          </div>

          {/* Members Table & Policy Settings */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Members List */}
            <div className="lg:col-span-8 bg-slate-900/70 border border-slate-800 rounded-2xl p-6 space-y-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Users className="w-4 h-4 text-cyan-400" />
                <span>Team Members & RBAC Roles ({workspace.members.length})</span>
              </h3>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-500 font-mono">
                      <th className="py-2.5 px-3">Member</th>
                      <th className="py-2.5 px-3">Role</th>
                      <th className="py-2.5 px-3">Joined Date</th>
                      <th className="py-2.5 px-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {workspace.members.map(m => (
                      <tr key={m.id} className="hover:bg-slate-800/30">
                        <td className="py-3 px-3">
                          <div className="font-bold text-white">{m.name}</div>
                          <div className="text-[11px] text-slate-400 font-mono">{m.email}</div>
                        </td>
                        <td className="py-3 px-3">{getRoleBadge(m.role)}</td>
                        <td className="py-3 px-3 font-mono text-slate-400">{new Date(m.joinedAt).toLocaleDateString()}</td>
                        <td className="py-3 px-3 text-right">
                          {m.role !== 'OWNER' && (
                            <button
                              onClick={() => handleRemoveMember(m.id)}
                              className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                              title="Remove member"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Security Policy Panel */}
            <div className="lg:col-span-4 bg-slate-900/70 border border-slate-800 rounded-2xl p-6 space-y-5">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Shield className="w-4 h-4 text-amber-400" />
                <span>Workspace Policies</span>
              </h3>

              <div className="space-y-4 text-xs">
                <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950 border border-slate-800">
                  <div>
                    <div className="font-bold text-white">Require Multi-Factor Auth</div>
                    <div className="text-[10px] text-slate-400">Enforce TOTP / WebAuthn for all roles</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={workspace.securityPolicy.mfaEnforced}
                    onChange={e => handleTogglePolicy('mfaEnforced', e.target.checked)}
                    className="w-4 h-4 accent-cyan-400 rounded cursor-pointer"
                  />
                </div>

                <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950 border border-slate-800">
                  <div>
                    <div className="font-bold text-white">Auto-Sinkhole Phishing</div>
                    <div className="text-[10px] text-slate-400">Broadcast RPZ BIND9 blocks immediately</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={workspace.securityPolicy.autoSinkholingEnabled}
                    onChange={e => handleTogglePolicy('autoSinkholingEnabled', e.target.checked)}
                    className="w-4 h-4 accent-cyan-400 rounded cursor-pointer"
                  />
                </div>

                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                  <div className="font-bold text-white">IP Subnet Allowlist</div>
                  <div className="text-[10px] text-slate-400 font-mono">
                    {workspace.securityPolicy.ipAllowlist.join(', ')}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Invite Member */}
      {showInviteModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4 animate-in fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <UserCheck className="w-5 h-5 text-cyan-400" />
                <span>Invite Team Member</span>
              </h3>
              <button onClick={() => setShowInviteModal(false)} className="text-slate-500 hover:text-white">✕</button>
            </div>

            <form onSubmit={handleInviteMember} className="space-y-4">
              <div>
                <label className="block text-xs font-bold text-slate-300 mb-1">Full Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. John Doe"
                  value={inviteName}
                  onChange={e => setInviteName(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-300 mb-1">Corporate Email Address *</label>
                <input
                  type="email"
                  required
                  placeholder="j.doe@company.internal"
                  value={inviteEmail}
                  onChange={e => setInviteEmail(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-cyan-400"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-300 mb-1">Assigned Role</label>
                <select
                  value={inviteRole}
                  onChange={e => setInviteRole(e.target.value as OrganizationRole)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-white focus:outline-none focus:border-cyan-400"
                >
                  <option value="SOC_ANALYST">SOC Analyst</option>
                  <option value="SECURITY_ADMIN">Security Admin</option>
                  <option value="AUDITOR">Auditor</option>
                  <option value="VIEWER">Viewer</option>
                </select>
              </div>

              <div className="flex items-center justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowInviteModal(false)}
                  className="px-4 py-2 rounded-xl text-xs text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isInviting}
                  className="px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/20 flex items-center space-x-1.5 transition-colors"
                >
                  <Plus className="w-4 h-4" />
                  <span>{isInviting ? 'Inviting...' : 'Send Invitation'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
