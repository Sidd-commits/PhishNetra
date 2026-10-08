import React, { useState, useEffect, useRef } from 'react';
import { api } from '../services/api';
import {
  CopilotChatRequest,
  CopilotChatResponse,
  CopilotPromptTemplate,
  CopilotSessionType
} from '@phishnetra/shared';
import { useToast } from '../context/ToastContext';
import {
  BrainCircuit,
  Send,
  Sparkles,
  Bot,
  User,
  ShieldCheck,
  ShieldAlert,
  Terminal,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Search,
  Crosshair,
  FileCode,
  Flame,
  Zap,
  RefreshCw,
  Sliders,
  Layers,
  Globe
} from 'lucide-react';

interface ChatMessage {
  id: string;
  sender: 'USER' | 'COPILOT';
  text: string;
  responsePayload?: CopilotChatResponse;
  timestamp: string;
}

export const ThreatCopilotPage: React.FC = () => {
  const { showToast } = useToast();

  const [templates, setTemplates] = useState<CopilotPromptTemplate[]>([]);
  const [sessionType, setSessionType] = useState<CopilotSessionType>('TRIAGE');
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputText, setInputText] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [contextDomain, setContextDomain] = useState<string>('auth-sec-verify-microsoft.account-portal.xyz');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [expandedReasoning, setExpandedReasoning] = useState<Record<string, boolean>>({});

  const chatEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetchTemplates();
    seedWelcomeMessage();
  }, []);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const fetchTemplates = async () => {
    try {
      const data = await api.getCopilotTemplates();
      setTemplates(data);
    } catch (err: any) {
      console.error('Failed to load copilot templates', err);
    }
  };

  const seedWelcomeMessage = () => {
    const welcome: ChatMessage = {
      id: 'msg-welcome',
      sender: 'COPILOT',
      text: `### 🤖 Welcome to PhishNetra AI SOC Co-Pilot\n\nI am your **Zero-Trust Autonomous Security Co-Pilot**. I can assist you with:\n\n- **Deep Incident Triage:** Multi-layer signal decomposition and root cause forensics.\n- **Threat Hunting Query Synthesis:** Compiling Regex, IP CIDRs, ASN pivots, and SIEM KQL rules.\n- **Active Remediation:** Generating BIND9 DNS RPZ sinkhole entries, Snort/Suricata rules, and RFC 2142 takedowns.\n- **MITRE ATT&CK Mapping:** Correlating adversary TTPs to real-world threat actors.\n\nSelect a prompt template below or type your inquiry to begin.`,
      timestamp: new Date().toLocaleTimeString()
    };
    setMessages([welcome]);
  };

  const handleSendMessage = async (customPrompt?: string) => {
    const promptToSend = customPrompt || inputText;
    if (!promptToSend.trim() || loading) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'USER',
      text: promptToSend,
      timestamp: new Date().toLocaleTimeString()
    };

    setMessages(prev => [...prev, userMsg]);
    if (!customPrompt) setInputText('');
    setLoading(true);

    try {
      const chatReq: CopilotChatRequest = {
        prompt: promptToSend,
        sessionType,
        context: {
          domain: contextDomain,
          targetUrl: `https://${contextDomain}/login`,
          brand: contextDomain.toLowerCase().includes('microsoft') ? 'Microsoft' : 'PayPal',
          riskScore: 96.5,
          verdict: 'PHISHING'
        },
        history: messages.map(m => ({
          sender: m.sender,
          message: m.text,
          timestamp: m.timestamp
        }))
      };

      const res = await api.sendCopilotChat(chatReq);

      const copilotMsg: ChatMessage = {
        id: res.id,
        sender: 'COPILOT',
        text: res.reply,
        responsePayload: res,
        timestamp: new Date().toLocaleTimeString()
      };

      setMessages(prev => [...prev, copilotMsg]);
      // Auto-expand reasoning for the latest message
      setExpandedReasoning(prev => ({ ...prev, [res.id]: true }));
    } catch (err: any) {
      showToast('error', 'Inference Failed', err.response?.data?.error || 'Copilot reasoning request failed');
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    showToast('success', 'Copied to Clipboard');
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const toggleReasoning = (id: string) => {
    setExpandedReasoning(prev => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-lg shadow-cyan-500/10">
              <BrainCircuit className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-2xl font-black tracking-tight text-white">AI SOC Co-Pilot</h1>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                  Agentic Triage Engine
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Autonomous reasoning, cross-layer IOC triage, rule compiler & natural language response generator
              </p>
            </div>
          </div>
        </div>

        {/* Session Type & Context Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-slate-900/90 border border-slate-800 text-xs">
            <span className="text-slate-400 text-[10px] uppercase font-mono">Mode:</span>
            <select
              value={sessionType}
              onChange={e => setSessionType(e.target.value as CopilotSessionType)}
              className="bg-transparent text-cyan-300 font-semibold focus:outline-none cursor-pointer"
            >
              <option value="TRIAGE" className="bg-slate-900">SOC Triage</option>
              <option value="HUNTING_COMPILER" className="bg-slate-900">Hunt Compiler</option>
              <option value="INCIDENT_ANALYSIS" className="bg-slate-900">Incident Analysis</option>
              <option value="REMEDIATION" className="bg-slate-900">Remediation Rules</option>
              <option value="GENERAL" className="bg-slate-900">General Intel</option>
            </select>
          </div>

          <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-slate-900/90 border border-slate-800 text-xs font-mono">
            <Globe className="w-3.5 h-3.5 text-slate-400" />
            <input
              type="text"
              value={contextDomain}
              onChange={e => setContextDomain(e.target.value)}
              placeholder="Target IOC Domain"
              className="bg-transparent text-slate-200 focus:outline-none w-48 text-[11px]"
              title="Active target domain context for Co-Pilot"
            />
          </div>
        </div>
      </div>

      {/* Suggested Prompt Templates Carousel */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {templates.map(tpl => (
          <button
            key={tpl.id}
            onClick={() => handleSendMessage(tpl.prompt)}
            className="text-left p-3.5 rounded-2xl bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 hover:border-cyan-500/40 transition-all duration-200 group flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between text-[10px] font-mono text-cyan-400 uppercase tracking-wider mb-1.5">
                <span>{tpl.category}</span>
                <Sparkles className="w-3 h-3 group-hover:scale-125 transition-transform" />
              </div>
              <div className="text-xs font-bold text-white group-hover:text-cyan-300 transition-colors">
                {tpl.title}
              </div>
              <div className="text-[11px] text-slate-400 mt-1 line-clamp-2">
                {tpl.description}
              </div>
            </div>
            <div className="mt-3 flex items-center space-x-1 text-[10px] font-semibold text-cyan-400/80 group-hover:text-cyan-300">
              <span>Execute Prompt</span>
              <ChevronRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
            </div>
          </button>
        ))}
      </div>

      {/* Chat Messages Log */}
      <div className="rounded-2xl bg-slate-900/50 border border-slate-800/80 backdrop-blur-xl p-4 sm:p-6 min-h-[480px] max-h-[640px] overflow-y-auto space-y-6">
        {messages.map(msg => (
          <div
            key={msg.id}
            className={`flex items-start space-x-3.5 ${msg.sender === 'USER' ? 'justify-end' : 'justify-start'}`}
          >
            {msg.sender === 'COPILOT' && (
              <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-cyan-500 to-indigo-600 p-[1px] shrink-0 mt-1 shadow-md shadow-cyan-500/20">
                <div className="w-full h-full bg-slate-950 rounded-[11px] flex items-center justify-center text-cyan-300">
                  <Bot className="w-4 h-4" />
                </div>
              </div>
            )}

            <div
              className={`max-w-3xl rounded-2xl p-4 sm:p-5 ${
                msg.sender === 'USER'
                  ? 'bg-cyan-500/15 border border-cyan-500/30 text-white rounded-tr-none'
                  : 'bg-slate-900/90 border border-slate-800 text-slate-200 rounded-tl-none shadow-xl'
              }`}
            >
              {/* Message Header */}
              <div className="flex items-center justify-between gap-4 mb-2 pb-2 border-b border-slate-800/60 text-[10px] font-mono text-slate-400">
                <span className="font-semibold text-cyan-400 flex items-center space-x-1">
                  {msg.sender === 'COPILOT' ? (
                    <>
                      <Sparkles className="w-3 h-3 text-cyan-400" />
                      <span>PhishNetra Co-Pilot Reasoning Core</span>
                    </>
                  ) : (
                    <>
                      <User className="w-3 h-3 text-slate-300" />
                      <span>SOC Lead Analyst</span>
                    </>
                  )}
                </span>
                <span>{msg.timestamp}</span>
              </div>

              {/* Message Text / Markdown Content */}
              <div className="text-xs leading-relaxed space-y-2 whitespace-pre-wrap font-sans">
                {msg.text}
              </div>

              {/* Co-Pilot Extra Reasoning and Artifact Panels */}
              {msg.responsePayload && (
                <div className="mt-4 pt-4 border-t border-slate-800 space-y-4">
                  {/* Reasoning Steps Collapsible */}
                  {msg.responsePayload.reasoningSteps?.length > 0 && (
                    <div className="rounded-xl bg-slate-950/70 border border-slate-800/80 p-3">
                      <button
                        onClick={() => toggleReasoning(msg.id)}
                        className="w-full flex items-center justify-between text-xs font-bold text-slate-300 hover:text-white"
                      >
                        <span className="flex items-center space-x-2">
                          <BrainCircuit className="w-3.5 h-3.5 text-indigo-400" />
                          <span>Chain-of-Thought Reasoning Steps ({msg.responsePayload.reasoningSteps.length})</span>
                        </span>
                        {expandedReasoning[msg.id] ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                      </button>

                      {expandedReasoning[msg.id] && (
                        <div className="mt-3 space-y-2 pt-2 border-t border-slate-800/60">
                          {msg.responsePayload.reasoningSteps.map(step => (
                            <div key={step.stepNumber} className="text-[11px] p-2 rounded-lg bg-slate-900/80 border border-slate-800/60 flex items-start space-x-2.5">
                              <span className="px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono text-[10px] font-bold">
                                #{step.stepNumber}
                              </span>
                              <div className="flex-1">
                                <div className="font-semibold text-slate-200">{step.stage}</div>
                                <div className="text-slate-400 mt-0.5">{step.observation}</div>
                              </div>
                              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                                {step.verdict}
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* MITRE ATT&CK Badges */}
                  {msg.responsePayload.mitreTechniques?.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="text-[10px] font-mono text-slate-500 uppercase">MITRE ATT&CK:</span>
                      {msg.responsePayload.mitreTechniques.map(tech => (
                        <span
                          key={tech.id}
                          className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-rose-500/10 text-rose-300 border border-rose-500/20"
                          title={`${tech.name} (${tech.tactic})`}
                        >
                          {tech.id}: {tech.name}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Generated Defense Artifacts */}
                  {msg.responsePayload.generatedArtifacts && (
                    <div className="space-y-2.5">
                      <div className="text-[11px] font-bold text-slate-300 flex items-center space-x-1.5">
                        <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Synthesized Defense Artifacts</span>
                      </div>

                      {/* SIEM KQL Query */}
                      {msg.responsePayload.generatedArtifacts.siemKqlQuery && (
                        <div className="rounded-xl bg-slate-950 border border-slate-800 p-3 font-mono text-[11px]">
                          <div className="flex items-center justify-between text-[10px] text-indigo-400 mb-1.5">
                            <span>Microsoft Sentinel / Defender KQL Query</span>
                            <button
                              onClick={() => handleCopy(msg.responsePayload!.generatedArtifacts.siemKqlQuery!, `kql-${msg.id}`)}
                              className="text-slate-400 hover:text-white flex items-center space-x-1"
                            >
                              {copiedKey === `kql-${msg.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              <span>{copiedKey === `kql-${msg.id}` ? 'Copied' : 'Copy'}</span>
                            </button>
                          </div>
                          <pre className="text-slate-300 overflow-x-auto whitespace-pre-wrap">{msg.responsePayload.generatedArtifacts.siemKqlQuery}</pre>
                        </div>
                      )}

                      {/* Snort Rule */}
                      {msg.responsePayload.generatedArtifacts.snortRule && (
                        <div className="rounded-xl bg-slate-950 border border-slate-800 p-3 font-mono text-[11px]">
                          <div className="flex items-center justify-between text-[10px] text-amber-400 mb-1.5">
                            <span>Snort / Suricata NIDS Rule</span>
                            <button
                              onClick={() => handleCopy(msg.responsePayload!.generatedArtifacts.snortRule!, `snort-${msg.id}`)}
                              className="text-slate-400 hover:text-white flex items-center space-x-1"
                            >
                              {copiedKey === `snort-${msg.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              <span>{copiedKey === `snort-${msg.id}` ? 'Copied' : 'Copy'}</span>
                            </button>
                          </div>
                          <pre className="text-slate-300 overflow-x-auto whitespace-pre-wrap">{msg.responsePayload.generatedArtifacts.snortRule}</pre>
                        </div>
                      )}

                      {/* DNS RPZ */}
                      {msg.responsePayload.generatedArtifacts.dnsRpzEntry && (
                        <div className="rounded-xl bg-slate-950 border border-slate-800 p-3 font-mono text-[11px]">
                          <div className="flex items-center justify-between text-[10px] text-emerald-400 mb-1.5">
                            <span>BIND9 DNS RPZ Response Policy Zone Sinkhole</span>
                            <button
                              onClick={() => handleCopy(msg.responsePayload!.generatedArtifacts.dnsRpzEntry!, `rpz-${msg.id}`)}
                              className="text-slate-400 hover:text-white flex items-center space-x-1"
                            >
                              {copiedKey === `rpz-${msg.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              <span>{copiedKey === `rpz-${msg.id}` ? 'Copied' : 'Copy'}</span>
                            </button>
                          </div>
                          <pre className="text-slate-300 overflow-x-auto whitespace-pre-wrap">{msg.responsePayload.generatedArtifacts.dnsRpzEntry}</pre>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Suggested Action Buttons */}
                  {msg.responsePayload.suggestedActions?.length > 0 && (
                    <div className="pt-2">
                      <div className="text-[10px] font-mono uppercase text-slate-500 mb-2">1-Click SOC Actions:</div>
                      <div className="flex flex-wrap gap-2">
                        {msg.responsePayload.suggestedActions.map(act => (
                          <button
                            key={act.id}
                            onClick={() => {
                              showToast('info', 'Action Dispatched', `Executing autonomous action: ${act.label}`);
                            }}
                            className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/40 transition-colors flex items-center space-x-1.5"
                          >
                            <Zap className="w-3 h-3 text-indigo-400" />
                            <span>{act.label}</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {msg.sender === 'USER' && (
              <div className="w-8 h-8 rounded-xl bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 flex items-center justify-center shrink-0 mt-1">
                <User className="w-4 h-4" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex items-center space-x-3 text-cyan-400 text-xs font-mono animate-pulse">
            <RefreshCw className="w-4 h-4 animate-spin" />
            <span>Reasoning across 8 detection layers, compiling rules, and verifying citations...</span>
          </div>
        )}

        <div ref={chatEndRef} />
      </div>

      {/* Input Form Bar */}
      <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-2.5 backdrop-blur-xl shadow-2xl flex items-center space-x-2">
        <input
          type="text"
          value={inputText}
          onChange={e => setInputText(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              handleSendMessage();
            }
          }}
          placeholder="Ask PhishNetra Co-Pilot (e.g. 'Triage this IOC', 'Compile Snort rule', 'Draft takedown notice')..."
          className="flex-1 bg-transparent px-4 py-2 text-xs text-white placeholder-slate-500 focus:outline-none"
        />
        <button
          onClick={() => handleSendMessage()}
          disabled={loading || !inputText.trim()}
          className="px-5 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/20 transition-all flex items-center space-x-1.5"
        >
          <span>Send</span>
          <Send className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
};
