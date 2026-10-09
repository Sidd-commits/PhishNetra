import React, { useState, useRef, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  ShieldAlert,
  LayoutDashboard,
  Search,
  Layers,
  Globe,
  MessageSquare,
  Network,
  Flame,
  Brain,
  Server,
  FolderLock,
  Mail,
  LogOut,
  UserCheck,
  Radio,
  Sliders,
  FileText,
  ChevronDown,
  Menu,
  X,
  Zap,
  Activity,
  Shield,
  Crosshair,
  Gavel,
  Building2,
  FileSpreadsheet,
  Workflow,
  SearchCode,
  BrainCircuit,
  Radar,
  Eye,
  ShieldCheck,
  Fingerprint,
  QrCode,
  Target,
  Bot,
  PhoneCall,
  FileCode2,
  KeyRound,
  Database
} from 'lucide-react';

export const Navbar: React.FC = () => {
  const { user, logout, isAuthenticated } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  // Dropdown states
  const [openDropdown, setOpenDropdown] = useState<string | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);
  const navRef = useRef<HTMLDivElement>(null);

  // Close dropdowns on outside click or route change
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (navRef.current && !navRef.current.contains(e.target as Node)) {
        setOpenDropdown(null);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    setOpenDropdown(null);
    setMobileMenuOpen(false);
  }, [location.pathname]);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const isGroupActive = (paths: string[]) => {
    return paths.some(p => location.pathname.startsWith(p));
  };

  const toggleDropdown = (name: string) => {
    setOpenDropdown(prev => (prev === name ? null : name));
  };

  return (
    <nav ref={navRef} className="border-b border-slate-800/80 bg-slate-950/85 backdrop-blur-xl sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Logo */}
          <div className="flex items-center space-x-3">
            <Link to="/dashboard" className="flex items-center space-x-2.5 group">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-500 to-indigo-600 p-[1px] shadow-md shadow-cyan-500/20 group-hover:shadow-cyan-500/40 transition-all">
                <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
                  <ShieldAlert className="w-5 h-5 text-cyan-400 group-hover:scale-105 transition-transform" />
                </div>
              </div>
              <span className="text-lg font-bold tracking-tight text-white">
                Phish<span className="text-cyan-400">Netra</span>
              </span>
            </Link>
          </div>

          {/* Desktop Categorized Navigation */}
          {isAuthenticated && (
            <div className="hidden lg:flex items-center space-x-1.5">
              {/* Dashboard */}
              <Link
                to="/dashboard"
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                  location.pathname === '/dashboard'
                    ? 'bg-slate-800 text-cyan-400 shadow-inner'
                    : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
                }`}
              >
                <LayoutDashboard className="w-3.5 h-3.5" />
                <span>Dashboard</span>
              </Link>

              {/* Group 1: Detection & Ingestion */}
              <div className="relative">
                <button
                  onClick={() => toggleDropdown('detection')}
                  className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                    isGroupActive(['/analyze', '/batch', '/email-scanner', '/domains', '/quishing', '/genai-defense', '/telecom-threat', '/fido2-guard']) || openDropdown === 'detection'
                      ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                      : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
                  }`}
                >
                  <Search className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Detection</span>
                  <ChevronDown className={`w-3 h-3 transition-transform ${openDropdown === 'detection' ? 'rotate-180' : ''}`} />
                </button>

                {openDropdown === 'detection' && (
                  <div className="absolute left-0 mt-2 w-60 rounded-2xl bg-slate-900/95 border border-slate-800 p-2 shadow-2xl backdrop-blur-xl animate-in fade-in slide-in-from-top-2">
                    <Link
                      to="/genai-defense"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Bot className="w-4 h-4 text-purple-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">GenAI Prompt Defense</div>
                        <div className="text-[10px] text-slate-400">Indirect injection & stego lures</div>
                      </div>
                    </Link>
                    <Link
                      to="/telecom-threat"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <PhoneCall className="w-4 h-4 text-orange-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Telecom Threat Fusion</div>
                        <div className="text-[10px] text-slate-400">Vishing, smishing & STIR/SHAKEN</div>
                      </div>
                    </Link>
                    <Link
                      to="/analyze"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Search className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Live Multi-Layer Scan</div>
                        <div className="text-[10px] text-slate-400">8-layer URL & page inspection</div>
                      </div>
                    </Link>
                    <Link
                      to="/batch"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Layers className="w-4 h-4 text-indigo-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Batch Queue Scanner</div>
                        <div className="text-[10px] text-slate-400">High-capacity bulk ingestion</div>
                      </div>
                    </Link>
                    <Link
                      to="/email-scanner"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Mail className="w-4 h-4 text-purple-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Email & Raw IOC Scanner</div>
                        <div className="text-[10px] text-slate-400">RFC 822 EML & SPF spoof checks</div>
                      </div>
                    </Link>
                    <Link
                      to="/domains"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Globe className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Domain Dossier Hub</div>
                        <div className="text-[10px] text-slate-400">RDAP & typosquatting matrix</div>
                      </div>
                    </Link>
                    <Link
                      to="/quishing"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <QrCode className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Quishing Defense</div>
                        <div className="text-[10px] text-slate-400">QR barcode & visual OCR inspection</div>
                      </div>
                    </Link>
                    <Link
                      to="/fido2-guard"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <KeyRound className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">FIDO2 Credential Guard</div>
                        <div className="text-[10px] text-slate-400">Passkey origin binding & AiTM immunity</div>
                      </div>
                    </Link>
                  </div>
                )}
              </div>

              {/* Group 2: Threat Intelligence */}
              <div className="relative">
                <button
                  onClick={() => toggleDropdown('intel')}
                  className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                    isGroupActive(['/graph', '/campaigns', '/feeds', '/reports', '/executive-briefing', '/hunting', '/attack-surface', '/rbi-sandbox', '/intel-fusion', '/threat-attribution', '/d3fend', '/cti-exchange', '/bgp-integrity']) || openDropdown === 'intel'
                      ? 'bg-indigo-500/15 text-indigo-300 border border-indigo-500/30'
                      : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
                  }`}
                >
                  <Network className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Threat Intel</span>
                  <ChevronDown className={`w-3 h-3 transition-transform ${openDropdown === 'intel' ? 'rotate-180' : ''}`} />
                </button>

                {openDropdown === 'intel' && (
                  <div className="absolute left-0 mt-2 w-60 rounded-2xl bg-slate-900/95 border border-slate-800 p-2 shadow-2xl backdrop-blur-xl animate-in fade-in slide-in-from-top-2">
                    <Link
                      to="/cti-exchange"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Database className="w-4 h-4 text-indigo-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">CTI TAXII Exchange</div>
                        <div className="text-[10px] text-slate-400">STIX 2.1 feeds & CISA sharing</div>
                      </div>
                    </Link>
                    <Link
                      to="/bgp-integrity"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Globe className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">BGP & DNS Radar</div>
                        <div className="text-[10px] text-slate-400">Route hijack & DNS poisoning</div>
                      </div>
                    </Link>
                    <Link
                      to="/d3fend"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <ShieldCheck className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">MITRE D3FEND Matrix</div>
                        <div className="text-[10px] text-slate-400">Tactics, techniques & coverage</div>
                      </div>
                    </Link>
                    <Link
                      to="/threat-attribution"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Target className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Threat Actor Matrix & FAIR</div>
                        <div className="text-[10px] text-slate-400">APT attribution & cyber risk ($)</div>
                      </div>
                    </Link>
                    <Link
                      to="/intel-fusion"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Layers className="w-4 h-4 text-purple-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Threat Intel Fusion</div>
                        <div className="text-[10px] text-slate-400">Bayesian decay & NIST/SOC 2</div>
                      </div>
                    </Link>
                    <Link
                      to="/rbi-sandbox"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <ShieldCheck className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">RBI Sandbox</div>
                        <div className="text-[10px] text-slate-400">Zero-Trust browser isolation</div>
                      </div>
                    </Link>
                    <Link
                      to="/executive-briefing"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <FileSpreadsheet className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Executive Dossier</div>
                        <div className="text-[10px] text-slate-400">Board-level briefing & KPI export</div>
                      </div>
                    </Link>
                    <Link
                      to="/hunting"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <SearchCode className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Threat Hunting Lab</div>
                        <div className="text-[10px] text-slate-400">Regex, JA3, CIDR & HAR sandbox</div>
                      </div>
                    </Link>
                    <Link
                      to="/attack-surface"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Radar className="w-4 h-4 text-indigo-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Attack Surface (EASM)</div>
                        <div className="text-[10px] text-slate-400">CT Logs radar & brand perimeter</div>
                      </div>
                    </Link>
                    <Link
                      to="/graph"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Network className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Threat Graph Explorer</div>
                        <div className="text-[10px] text-slate-400">Force-directed IOC visualizer</div>
                      </div>
                    </Link>
                    <Link
                      to="/campaigns"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Flame className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Threat Campaigns</div>
                        <div className="text-[10px] text-slate-400">Adversary infrastructure clustering</div>
                      </div>
                    </Link>
                    <Link
                      to="/feeds"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Radio className="w-4 h-4 text-teal-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Threat Feeds Sync</div>
                        <div className="text-[10px] text-slate-400">URLhaus, OpenPhish live sync</div>
                      </div>
                    </Link>
                    <Link
                      to="/reports"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <MessageSquare className="w-4 h-4 text-purple-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Community Reports</div>
                        <div className="text-[10px] text-slate-400">Crowdsourced threat moderation</div>
                      </div>
                    </Link>
                  </div>
                )}
              </div>

              {/* Group 3: SOC Operations & SIEM */}
              <div className="relative">
                <button
                  onClick={() => toggleDropdown('soc')}
                  className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                    isGroupActive(['/cases', '/playbooks', '/takedowns', '/siem', '/audit-logs', '/integrations', '/copilot', '/deception', '/tarpit', '/aitm-defense', '/client-defense', '/session-anomaly', '/digital-forensics']) || openDropdown === 'soc'
                      ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                      : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
                  }`}
                >
                  <FolderLock className="w-3.5 h-3.5 text-amber-400" />
                  <span>SOC Ops</span>
                  <ChevronDown className={`w-3 h-3 transition-transform ${openDropdown === 'soc' ? 'rotate-180' : ''}`} />
                </button>

                {openDropdown === 'soc' && (
                  <div className="absolute left-0 mt-2 w-60 rounded-2xl bg-slate-900/95 border border-slate-800 p-2 shadow-2xl backdrop-blur-xl animate-in fade-in slide-in-from-top-2">
                    <Link
                      to="/digital-forensics"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <FileCode2 className="w-4 h-4 text-teal-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Digital Forensics & DPI</div>
                        <div className="text-[10px] text-slate-400">HAR packet inspection & SHA-256</div>
                      </div>
                    </Link>
                    <Link
                      to="/client-defense"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Shield className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Client Anti-Tamper SDK</div>
                        <div className="text-[10px] text-slate-400">DOM cloaking & devtools traps</div>
                      </div>
                    </Link>
                    <Link
                      to="/session-anomaly"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Activity className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Continuous Session Trust</div>
                        <div className="text-[10px] text-slate-400">Impossible travel & JA3 drift</div>
                      </div>
                    </Link>
                    <Link
                      to="/aitm-defense"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Fingerprint className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">AiTM Proxy Defense</div>
                        <div className="text-[10px] text-slate-400">Evilginx detection & Passkey step-up</div>
                      </div>
                    </Link>
                    <Link
                      to="/tarpit"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Flame className="w-4 h-4 text-orange-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Phishing Tarpit</div>
                        <div className="text-[10px] text-slate-400">Synthetic credential poisoner</div>
                      </div>
                    </Link>
                    <Link
                      to="/copilot"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <BrainCircuit className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">AI SOC Co-Pilot</div>
                        <div className="text-[10px] text-slate-400">Autonomous reasoning & rule compiler</div>
                      </div>
                    </Link>
                    <Link
                      to="/deception"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Eye className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Canary Deception</div>
                        <div className="text-[10px] text-slate-400">Honeypot tokens & anti-cloning web bugs</div>
                      </div>
                    </Link>
                    <Link
                      to="/cases"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <FolderLock className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Incident Cases</div>
                        <div className="text-[10px] text-slate-400">Triage & 1-click defense rules</div>
                      </div>
                    </Link>
                    <Link
                      to="/playbooks"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Workflow className="w-4 h-4 text-indigo-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">SOAR Playbooks</div>
                        <div className="text-[10px] text-slate-400">Autonomous containment & DNS RPZ</div>
                      </div>
                    </Link>
                    <Link
                      to="/takedowns"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Gavel className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">Legal Takedown Center</div>
                        <div className="text-[10px] text-slate-400">RFC 2142 notices & registrar sync</div>
                      </div>
                    </Link>
                    <Link
                      to="/siem"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <Server className="w-4 h-4 text-indigo-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">SIEM & Webhooks</div>
                        <div className="text-[10px] text-slate-400">CEF/LEEF logs & Slack alerts</div>
                      </div>
                    </Link>
                    <Link
                      to="/audit-logs"
                      className="flex items-start space-x-2.5 p-2 rounded-xl hover:bg-slate-800/80 transition-colors"
                    >
                      <FileText className="w-4 h-4 text-teal-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-xs font-bold text-white">SOC Audit Trail</div>
                        <div className="text-[10px] text-slate-400">Security event log & CSV export</div>
                      </div>
                    </Link>
                  </div>
                )}
              </div>

              {/* Threat Simulation Lab */}
              <Link
                to="/simulation"
                title="Red Team Attack Simulator & Defense Benchmark"
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                  location.pathname === '/simulation'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
                }`}
              >
                <Crosshair className="w-3.5 h-3.5 text-rose-400" />
                <span>Simulation</span>
              </Link>

              {/* MLOps */}
              <Link
                to="/mlops"
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                  location.pathname === '/mlops'
                    ? 'bg-teal-500/20 text-teal-300 border border-teal-500/30'
                    : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
                }`}
              >
                <Brain className="w-3.5 h-3.5 text-teal-400" />
                <span>MLOps</span>
              </Link>

              {/* Organization Workspace */}
              <Link
                to="/organization"
                title="Team Workspace & RBAC Governance"
                className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                  location.pathname === '/organization'
                    ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                    : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
                }`}
              >
                <Building2 className="w-3.5 h-3.5 text-purple-400" />
                <span>Workspace</span>
              </Link>

              {/* Settings / Calibration */}
              <Link
                to="/settings"
                title="System Calibration & Policy Engine"
                className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                  location.pathname === '/settings'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                    : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
                }`}
              >
                <Sliders className="w-3.5 h-3.5 text-cyan-400" />
                <span>Settings</span>
              </Link>
            </div>
          )}

          {/* Right Action Section: User Info & Mobile Hamburger */}
          <div className="flex items-center space-x-3">
            {isAuthenticated && user ? (
              <div className="flex items-center space-x-3">
                <div className="hidden md:flex flex-col text-right">
                  <span className="text-xs font-medium text-slate-200">{user.name}</span>
                  <span className="text-[11px] text-slate-400">
                    {user.role === 'ADMIN' ? 'Administrator' : 'Analyst'}
                  </span>
                </div>
                <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700/80 flex items-center justify-center text-slate-200 text-xs font-semibold">
                  {user.name.charAt(0).toUpperCase()}
                </div>
                <button
                  onClick={handleLogout}
                  title="Sign out"
                  className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <div className="flex items-center space-x-2">
                <Link
                  to="/login"
                  className="px-4 py-2 text-xs font-semibold text-slate-300 hover:text-white rounded-lg hover:bg-slate-800/60 transition-colors"
                >
                  Sign In
                </Link>
                <Link
                  to="/register"
                  className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg shadow-sm shadow-cyan-500/20 transition-colors flex items-center space-x-1.5"
                >
                  <UserCheck className="w-3.5 h-3.5" />
                  <span>Register</span>
                </Link>
              </div>
            )}

            {/* Mobile Hamburger Toggle */}
            {isAuthenticated && (
              <button
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                className="lg:hidden p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
              >
                {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Mobile Menu Drawer */}
      {isAuthenticated && mobileMenuOpen && (
        <div className="lg:hidden border-t border-slate-800 bg-slate-950/95 backdrop-blur-xl px-4 pt-3 pb-6 space-y-4 animate-in slide-in-from-top-4">
          <div className="space-y-1">
            <Link
              to="/dashboard"
              className="block px-3 py-2 rounded-lg text-xs font-semibold text-slate-200 hover:bg-slate-800"
            >
              Dashboard
            </Link>
          </div>

          <div className="space-y-1">
            <span className="text-[10px] font-mono uppercase text-slate-500 px-3">Detection & Ingestion</span>
            <Link to="/genai-defense" className="block px-3 py-1.5 rounded-lg text-xs text-purple-300 hover:bg-slate-800">GenAI Prompt Defense</Link>
            <Link to="/telecom-threat" className="block px-3 py-1.5 rounded-lg text-xs text-orange-300 hover:bg-slate-800">Telecom Threat Fusion</Link>
            <Link to="/analyze" className="block px-3 py-1.5 rounded-lg text-xs text-slate-300 hover:bg-slate-800">Live Scan</Link>
            <Link to="/batch" className="block px-3 py-1.5 rounded-lg text-xs text-slate-300 hover:bg-slate-800">Batch Queue</Link>
            <Link to="/email-scanner" className="block px-3 py-1.5 rounded-lg text-xs text-slate-300 hover:bg-slate-800">Email Scanner</Link>
            <Link to="/domains" className="block px-3 py-1.5 rounded-lg text-xs text-slate-300 hover:bg-slate-800">Domain Dossier</Link>
            <Link to="/quishing" className="block px-3 py-1.5 rounded-lg text-xs text-emerald-300 hover:bg-slate-800">Quishing Defense</Link>
            <Link to="/fido2-guard" className="block px-3 py-1.5 rounded-lg text-xs text-cyan-300 hover:bg-slate-800">FIDO2 Credential Guard</Link>
          </div>

          <div className="space-y-1">
            <span className="text-[10px] font-mono uppercase text-slate-500 px-3">Threat Intelligence</span>
            <Link to="/cti-exchange" className="block px-3 py-1.5 rounded-lg text-xs text-indigo-300 hover:bg-slate-800">CTI TAXII Exchange</Link>
            <Link to="/bgp-integrity" className="block px-3 py-1.5 rounded-lg text-xs text-rose-300 hover:bg-slate-800">BGP & DNS Radar</Link>
            <Link to="/d3fend" className="block px-3 py-1.5 rounded-lg text-xs text-cyan-300 hover:bg-slate-800">MITRE D3FEND Matrix</Link>
            <Link to="/threat-attribution" className="block px-3 py-1.5 rounded-lg text-xs text-rose-300 hover:bg-slate-800">Threat Actor Matrix & FAIR</Link>
            <Link to="/intel-fusion" className="block px-3 py-1.5 rounded-lg text-xs text-purple-300 hover:bg-slate-800">Threat Fusion & Compliance</Link>
            <Link to="/rbi-sandbox" className="block px-3 py-1.5 rounded-lg text-xs text-cyan-300 hover:bg-slate-800">RBI Sandbox</Link>
            <Link to="/executive-briefing" className="block px-3 py-1.5 rounded-lg text-xs text-cyan-300 hover:bg-slate-800">Executive Dossier</Link>
            <Link to="/hunting" className="block px-3 py-1.5 rounded-lg text-xs text-emerald-300 hover:bg-slate-800">Threat Hunting Lab</Link>
            <Link to="/attack-surface" className="block px-3 py-1.5 rounded-lg text-xs text-indigo-300 hover:bg-slate-800">Attack Surface (EASM)</Link>
            <Link to="/graph" className="block px-3 py-1.5 rounded-lg text-xs text-slate-300 hover:bg-slate-800">Threat Graph</Link>
            <Link to="/campaigns" className="block px-3 py-1.5 rounded-lg text-xs text-slate-300 hover:bg-slate-800">Campaigns</Link>
            <Link to="/feeds" className="block px-3 py-1.5 rounded-lg text-xs text-slate-300 hover:bg-slate-800">Threat Feeds</Link>
            <Link to="/reports" className="block px-3 py-1.5 rounded-lg text-xs text-slate-300 hover:bg-slate-800">Community Reports</Link>
          </div>

          <div className="space-y-1">
            <span className="text-[10px] font-mono uppercase text-slate-500 px-3">SOC Operations</span>
            <Link to="/digital-forensics" className="block px-3 py-1.5 rounded-lg text-xs text-teal-300 hover:bg-slate-800">Digital Forensics & DPI</Link>
            <Link to="/client-defense" className="block px-3 py-1.5 rounded-lg text-xs text-emerald-300 hover:bg-slate-800">Client Anti-Tamper SDK</Link>
            <Link to="/session-anomaly" className="block px-3 py-1.5 rounded-lg text-xs text-rose-300 hover:bg-slate-800">Continuous Session Trust</Link>
            <Link to="/aitm-defense" className="block px-3 py-1.5 rounded-lg text-xs text-rose-300 hover:bg-slate-800">AiTM Proxy Defense</Link>
            <Link to="/tarpit" className="block px-3 py-1.5 rounded-lg text-xs text-orange-300 hover:bg-slate-800">Phishing Tarpit</Link>
            <Link to="/copilot" className="block px-3 py-1.5 rounded-lg text-xs text-cyan-300 hover:bg-slate-800">AI SOC Co-Pilot</Link>
            <Link to="/deception" className="block px-3 py-1.5 rounded-lg text-xs text-amber-300 hover:bg-slate-800">Canary Deception</Link>
            <Link to="/cases" className="block px-3 py-1.5 rounded-lg text-xs text-slate-300 hover:bg-slate-800">Incident Cases</Link>
            <Link to="/playbooks" className="block px-3 py-1.5 rounded-lg text-xs text-indigo-300 hover:bg-slate-800">SOAR Playbooks</Link>
            <Link to="/takedowns" className="block px-3 py-1.5 rounded-lg text-xs text-rose-300 hover:bg-slate-800">Legal Takedowns</Link>
            <Link to="/siem" className="block px-3 py-1.5 rounded-lg text-xs text-slate-300 hover:bg-slate-800">SIEM & Webhooks</Link>
            <Link to="/audit-logs" className="block px-3 py-1.5 rounded-lg text-xs text-slate-300 hover:bg-slate-800">Audit Trail</Link>
          </div>

          <div className="space-y-1 pt-2 border-t border-slate-800">
            <Link to="/organization" className="block px-3 py-1.5 rounded-lg text-xs text-purple-300 hover:bg-slate-800">Team Workspace & RBAC</Link>
            <Link to="/simulation" className="block px-3 py-1.5 rounded-lg text-xs text-rose-300 hover:bg-slate-800">Threat Simulation Sandbox</Link>
            <Link to="/mlops" className="block px-3 py-1.5 rounded-lg text-xs text-slate-300 hover:bg-slate-800">MLOps Dashboard</Link>
            <Link to="/settings" className="block px-3 py-1.5 rounded-lg text-xs text-cyan-300 hover:bg-slate-800">System Settings & Calibration</Link>
          </div>
        </div>
      )}
    </nav>
  );
};
