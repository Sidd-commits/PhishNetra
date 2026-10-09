import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Network,
  Search,
  Download,
  RefreshCw,
  Zap,
  Globe,
  Server,
  Shield,
  Lock,
  Tag,
  Flame,
  Info,
  Layers,
  ChevronRight,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Sliders
} from 'lucide-react';
import { GraphData, GraphNode, GraphEdge, GraphNodeType } from '@phishnetra/shared';
import { api } from '../services/api';

interface VisualNode extends GraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  color: string;
  icon: string;
}

export const ThreatGraphPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], edges: [] });
  const [loading, setLoading] = useState<boolean>(true);
  const [searchDomain, setSearchDomain] = useState<string>('');
  const [depth, setDepth] = useState<number>(2);
  const [selectedNode, setSelectedNode] = useState<VisualNode | null>(null);
  const [typeFilters, setTypeFilters] = useState<Record<GraphNodeType, boolean>>({
    DOMAIN: true,
    IP: true,
    ASN: true,
    CERTIFICATE: true,
    NAMESERVER: true,
    REGISTRAR: true,
    BRAND: true,
    CAMPAIGN: true,
    URL: true
  });
  const [clustering, setClustering] = useState<boolean>(false);
  const [clusterNotice, setClusterNotice] = useState<string | null>(null);

  // Canvas / SVG Viewport state
  const [zoom, setZoom] = useState<number>(1);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [draggedNode, setDraggedNode] = useState<VisualNode | null>(null);

  const [visualNodes, setVisualNodes] = useState<VisualNode[]>([]);
  const animFrameRef = useRef<number | null>(null);

  const fetchOverviewGraph = async () => {
    setLoading(true);
    try {
      const data = await api.getGraphOverview(80);
      if (data && data.nodes) {
        setGraphData(data);
      }
    } catch (err) {
      console.error('Failed to load overview graph:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchDomainSubGraph = async (domain: string) => {
    if (!domain.trim()) return;
    setLoading(true);
    try {
      const data = await api.getDomainSubGraph(domain.trim(), depth);
      if (data && data.nodes) {
        setGraphData(data);
      }
    } catch (err) {
      console.error('Failed to load domain subgraph:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleExpandNeighbors = async (nodeId: string) => {
    try {
      const res = await api.getNodeNeighbors(nodeId);
      if (res && res.nodes && res.nodes.length > 0) {
        const newNodes = res.nodes;
        const newEdges = res.edges;

        setGraphData((prev) => {
          const existingNodeIds = new Set(prev.nodes.map((n) => n.id));
          const existingEdgeIds = new Set(prev.edges.map((e) => e.id));

          const mergedNodes = [...prev.nodes];
          for (const n of newNodes) {
            if (!existingNodeIds.has(n.id)) {
              mergedNodes.push(n);
              existingNodeIds.add(n.id);
            }
          }

          const mergedEdges = [...prev.edges];
          for (const e of newEdges) {
            if (!existingEdgeIds.has(e.id)) {
              mergedEdges.push(e);
              existingEdgeIds.add(e.id);
            }
          }

          return {
            nodes: mergedNodes,
            edges: mergedEdges,
            stats: {
              totalNodes: mergedNodes.length,
              totalEdges: mergedEdges.length
            }
          };
        });
      }
    } catch (err) {
      console.error('Failed to expand neighbors:', err);
    }
  };

  const handleRunClustering = async () => {
    setClustering(true);
    setClusterNotice(null);
    try {
      const res = await api.clusterCampaigns();
      if (res && res.success) {
        const result = res.data;
        setClusterNotice(`Discovered & clustered ${result?.newCampaignsCreated ?? 0} Threat Campaign(s) across ${result?.domainsClustered ?? 0} domains.`);
        await fetchOverviewGraph();
      }
    } catch (err: any) {
      setClusterNotice(`Clustering error: ${err.message}`);
    } finally {
      setClustering(false);
    }
  };

  const handleExportSTIX = () => {
    const baseUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';
    const url = searchDomain
      ? `${baseUrl}/graph/export/stix?domain=${encodeURIComponent(searchDomain)}`
      : `${baseUrl}/graph/export/stix`;
    window.open(url, '_blank');
  };

  useEffect(() => {
    const domainParam = searchParams.get('domain');
    if (domainParam) {
      setSearchDomain(domainParam);
      fetchDomainSubGraph(domainParam);
    } else {
      fetchOverviewGraph();
    }
  }, [searchParams]);

  // Initialize and run Force-Directed Simulation Layout
  useEffect(() => {
    if (graphData.nodes.length === 0) {
      setVisualNodes([]);
      return;
    }

    const width = 1000;
    const height = 650;
    const centerX = width / 2;
    const centerY = height / 2;

    // Filter nodes by enabled types
    const filteredNodes = graphData.nodes.filter((n) => typeFilters[n.type] !== false);
    const validNodeIdSet = new Set(filteredNodes.map((n) => n.id));

    // Build visual nodes
    const nodeMap = new Map<string, VisualNode>();
    filteredNodes.forEach((node, i) => {
      const angle = (i / filteredNodes.length) * 2 * Math.PI;
      const dist = 140 + (i % 3) * 80;
      const x = centerX + Math.cos(angle) * dist + (Math.random() - 0.5) * 40;
      const y = centerY + Math.sin(angle) * dist + (Math.random() - 0.5) * 40;

      nodeMap.set(node.id, {
        ...node,
        x,
        y,
        vx: 0,
        vy: 0,
        radius: getNodeRadius(node),
        color: getNodeColor(node),
        icon: getNodeIcon(node.type)
      });
    });

    const vNodes = Array.from(nodeMap.values());
    const validEdges = graphData.edges.filter(
      (e) => validNodeIdSet.has(e.source) && validNodeIdSet.has(e.target)
    );

    // Physics Simulation loop
    let step = 0;
    const maxSteps = 160;

    const tick = () => {
      if (step > maxSteps) return;

      // 1. Repulsion between all nodes (Coulomb's Law)
      for (let i = 0; i < vNodes.length; i++) {
        for (let j = i + 1; j < vNodes.length; j++) {
          const n1 = vNodes[i];
          const n2 = vNodes[j];
          const dx = n2.x - n1.x;
          const dy = n2.y - n1.y;
          const distSq = dx * dx + dy * dy || 1;
          const dist = Math.sqrt(distSq);

          if (dist < 320) {
            const force = (1200 / distSq);
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;
            n1.vx -= fx;
            n1.vy -= fy;
            n2.vx += fx;
            n2.vy += fy;
          }
        }
      }

      // 2. Attraction along edges (Hooke's Law Spring)
      for (const edge of validEdges) {
        const source = nodeMap.get(edge.source);
        const target = nodeMap.get(edge.target);
        if (source && target) {
          const dx = target.x - source.x;
          const dy = target.y - source.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const targetDist = edge.type === 'PART_OF_CAMPAIGN' ? 90 : 130;
          const force = (dist - targetDist) * 0.035;
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;

          source.vx += fx;
          source.vy += fy;
          target.vx -= fx;
          target.vy -= fy;
        }
      }

      // 3. Center gravity & update position
      vNodes.forEach((node) => {
        const cdx = centerX - node.x;
        const cdy = centerY - node.y;
        node.vx += cdx * 0.003;
        node.vy += cdy * 0.003;

        // Damping
        node.vx *= 0.85;
        node.vy *= 0.85;

        node.x += node.vx;
        node.y += node.vy;
      });

      setVisualNodes([...vNodes]);
      step++;
      animFrameRef.current = requestAnimationFrame(tick);
    };

    animFrameRef.current = requestAnimationFrame(tick);

    return () => {
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [graphData, typeFilters]);

  // Pan and Drag Handlers
  const handleMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    if (e.target === e.currentTarget) {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (isDragging) {
      setPan({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y
      });
    } else if (draggedNode) {
      const rect = e.currentTarget.getBoundingClientRect();
      const mouseX = (e.clientX - rect.left - pan.x) / zoom;
      const mouseY = (e.clientY - rect.top - pan.y) / zoom;
      draggedNode.x = mouseX;
      draggedNode.y = mouseY;
      setVisualNodes([...visualNodes]);
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
    setDraggedNode(null);
  };

  const handleZoom = (delta: number) => {
    setZoom((prev) => Math.min(2.5, Math.max(0.4, prev + delta)));
  };

  const handleResetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    setSelectedNode(null);
  };

  const toggleTypeFilter = (type: GraphNodeType) => {
    setTypeFilters((prev) => ({ ...prev, [type]: !prev[type] }));
  };

  function getNodeColor(node: GraphNode): string {
    if (node.type === 'CAMPAIGN') return '#dc2626'; // Bright Crimson
    if (node.type === 'BRAND') return '#eab308'; // Gold
    if (node.type === 'ASN') return '#a855f7'; // Purple
    if (node.type === 'IP') return '#3b82f6'; // Blue
    if (node.type === 'CERTIFICATE') return '#10b981'; // Emerald
    if (node.type === 'NAMESERVER') return '#06b6d4'; // Cyan
    if (node.type === 'REGISTRAR') return '#64748b'; // Slate

    // Domain coloring based on risk
    if (node.riskLevel === 'CRITICAL' || (node.riskScore && node.riskScore >= 75)) return '#ef4444';
    if (node.riskLevel === 'HIGH' || (node.riskScore && node.riskScore >= 50)) return '#f97316';
    if (node.riskLevel === 'MEDIUM' || (node.riskScore && node.riskScore >= 30)) return '#eab308';
    return '#10b981';
  }

  function getNodeRadius(node: GraphNode): number {
    if (node.type === 'CAMPAIGN') return 28;
    if (node.type === 'BRAND') return 24;
    if (node.type === 'ASN') return 22;
    if (node.type === 'DOMAIN') return 20;
    return 16;
  }

  function getNodeIcon(type: GraphNodeType): string {
    switch (type) {
      case 'CAMPAIGN': return '⚡';
      case 'BRAND': return '🏷️';
      case 'ASN': return '🏢';
      case 'IP': return '🖥️';
      case 'CERTIFICATE': return '🔒';
      case 'NAMESERVER': return '🌐';
      case 'REGISTRAR': return '🏛️';
      default: return '🌐';
    }
  }

  const activeConnectedEdges = selectedNode
    ? graphData.edges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
    : [];

  return (
    <div className="min-h-[calc(100vh-4rem)] bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Header & Search Bar */}
      <div className="border-b border-slate-900 bg-slate-950/80 px-6 py-4 backdrop-blur-md">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2">
              <Network className="w-6 h-6 text-cyan-400" />
              <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                Threat Intelligence Graph Explorer
              </h1>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Infrastructure topology, autonomous campaign clustering, and IOC correlation
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center space-x-2 w-full md:w-auto">
            <button
              onClick={handleRunClustering}
              disabled={clustering}
              className="flex items-center space-x-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 transition-colors shadow-sm"
            >
              <Zap className={`w-3.5 h-3.5 ${clustering ? 'animate-spin' : ''}`} />
              <span>{clustering ? 'Clustering...' : 'Cluster Threat Rings'}</span>
            </button>

            <button
              onClick={handleExportSTIX}
              className="flex items-center space-x-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors shadow-sm"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Export STIX 2.1</span>
            </button>

            <button
              onClick={fetchOverviewGraph}
              title="Refresh Graph"
              className="p-2 rounded-lg text-slate-400 hover:text-white bg-slate-900 border border-slate-800 transition-colors"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Search & Hop Depth Toolbar */}
        <div className="max-w-7xl mx-auto mt-4 flex flex-wrap items-center justify-between gap-3">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              fetchDomainSubGraph(searchDomain);
            }}
            className="flex items-center space-x-2 flex-1 max-w-lg"
          >
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Query target domain (e.g. security-verify-paypal.xyz)..."
                value={searchDomain}
                onChange={(e) => setSearchDomain(e.target.value)}
                className="w-full bg-slate-900/90 border border-slate-800 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
            <select
              value={depth}
              onChange={(e) => setDepth(parseInt(e.target.value, 10))}
              className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value={1}>1-Hop Expansion</option>
              <option value={2}>2-Hop Expansion</option>
              <option value={3}>3-Hop Expansion</option>
            </select>
            <button
              type="submit"
              className="px-3 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-lg text-xs transition-colors"
            >
              Explore
            </button>
          </form>

          {/* Type Filter Pills */}
          <div className="flex items-center space-x-1.5 overflow-x-auto py-1">
            {(['CAMPAIGN', 'DOMAIN', 'IP', 'ASN', 'BRAND', 'CERTIFICATE', 'NAMESERVER', 'REGISTRAR'] as GraphNodeType[]).map((type) => {
              const active = typeFilters[type];
              return (
                <button
                  key={type}
                  onClick={() => toggleTypeFilter(type)}
                  className={`text-[11px] font-semibold px-2.5 py-1 rounded-full border transition-all ${
                    active
                      ? 'bg-slate-800 text-slate-200 border-slate-600 shadow-sm'
                      : 'bg-slate-950/40 text-slate-600 border-slate-900 opacity-60'
                  }`}
                >
                  {type}
                </button>
              );
            })}
          </div>
        </div>

        {/* Cluster Notice Alert */}
        {clusterNotice && (
          <div className="max-w-7xl mx-auto mt-2 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-xs flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Flame className="w-3.5 h-3.5 text-emerald-400" />
              {clusterNotice}
            </span>
            <button onClick={() => setClusterNotice(null)} className="text-emerald-400 hover:text-white font-bold">✕</button>
          </div>
        )}
      </div>

      {/* Main Graph Canvas Area */}
      <div className="h-[calc(100vh-14rem)] min-h-[580px] w-full relative overflow-hidden bg-[#070b14]">
        {/* Loading Overlay */}
        {loading && (
          <div className="absolute inset-0 z-30 flex flex-col items-center justify-center bg-slate-950/70 backdrop-blur-xs">
            <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl flex flex-col items-center space-y-3">
              <RefreshCw className="w-7 h-7 text-cyan-400 animate-spin" />
              <span className="text-xs font-mono text-slate-300">Rendering Threat Topology Graph...</span>
            </div>
          </div>
        )}

        {/* Empty State Overlay */}
        {!loading && visualNodes.length === 0 && (
          <div className="absolute inset-0 z-20 flex flex-col items-center justify-center pointer-events-none">
            <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 text-center max-w-md pointer-events-auto">
              <Network className="w-10 h-10 text-slate-600 mx-auto mb-3" />
              <h3 className="text-sm font-bold text-white mb-1">No Threat Entities Found</h3>
              <p className="text-xs text-slate-400 mb-4">No nodes match the selected filters or search query.</p>
              <button
                onClick={fetchOverviewGraph}
                className="px-3 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold rounded-lg transition-colors"
              >
                Reload Fleet Overview
              </button>
            </div>
          </div>
        )}

        {/* Zoom & Viewport Controls Overlay */}
        <div className="absolute top-4 left-4 z-20 flex flex-col space-y-1.5 bg-slate-900/90 border border-slate-800 p-1 rounded-lg backdrop-blur-md shadow-xl">
          <button
            onClick={() => handleZoom(0.2)}
            title="Zoom In"
            className="p-1.5 text-slate-300 hover:text-white hover:bg-slate-800 rounded transition-colors"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={() => handleZoom(-0.2)}
            title="Zoom Out"
            className="p-1.5 text-slate-300 hover:text-white hover:bg-slate-800 rounded transition-colors"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={handleResetView}
            title="Reset Viewport"
            className="p-1.5 text-slate-300 hover:text-white hover:bg-slate-800 rounded transition-colors"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
        </div>

        {/* Graph Legend Overlay */}
        <div className="absolute bottom-4 left-4 z-20 hidden md:flex items-center space-x-3 bg-slate-900/80 border border-slate-800/80 px-3 py-2 rounded-lg backdrop-blur-md text-[10px] font-mono text-slate-400 shadow-xl">
          <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block shadow-sm shadow-red-500" /> Phishing Domain</span>
          <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block" /> IP Node</span>
          <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-purple-500 inline-block" /> ASN</span>
          <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-yellow-500 inline-block" /> Brand</span>
          <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-red-600 inline-block animate-pulse" /> Threat Campaign</span>
        </div>

        {/* SVG Interactive Canvas */}
        <svg
          viewBox="0 0 1000 650"
          preserveAspectRatio="xMidYMid meet"
          className="w-full h-full cursor-grab active:cursor-grabbing"
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
        >
          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            {/* 1. Render Graph Edges */}
            {graphData.edges.map((edge) => {
              const src = visualNodes.find((n) => n.id === edge.source);
              const tgt = visualNodes.find((n) => n.id === edge.target);
              if (!src || !tgt) return null;

              const isHighlighted = selectedNode && (selectedNode.id === src.id || selectedNode.id === tgt.id);

              return (
                <g key={edge.id}>
                  <line
                    x1={src.x}
                    y1={src.y}
                    x2={tgt.x}
                    y2={tgt.y}
                    stroke={isHighlighted ? '#38bdf8' : (edge.type === 'PART_OF_CAMPAIGN' ? '#ef4444' : '#334155')}
                    strokeWidth={isHighlighted ? 2.5 : (edge.type === 'PART_OF_CAMPAIGN' ? 2 : 1.2)}
                    strokeDasharray={edge.type === 'CO_LOCATED_WITH' ? '4 3' : undefined}
                    opacity={isHighlighted ? 0.9 : 0.6}
                  />
                  {/* Midpoint Edge Label for Selected Connections */}
                  {isHighlighted && (
                    <text
                      x={(src.x + tgt.x) / 2}
                      y={(src.y + tgt.y) / 2 - 4}
                      fill="#94a3b8"
                      fontSize="9"
                      fontFamily="monospace"
                      textAnchor="middle"
                    >
                      {edge.type}
                    </text>
                  )}
                </g>
              );
            })}

            {/* 2. Render Graph Nodes */}
            {visualNodes.map((node) => {
              const isSelected = selectedNode?.id === node.id;
              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  onClick={() => setSelectedNode(node)}
                  onMouseDown={(e) => {
                    e.stopPropagation();
                    setDraggedNode(node);
                  }}
                  className="cursor-pointer group"
                >
                  {/* Outer Glow Halo for Selected / High Risk */}
                  {(isSelected || node.type === 'CAMPAIGN' || node.riskLevel === 'CRITICAL') && (
                    <circle
                      r={node.radius + 8}
                      fill={node.color}
                      opacity={isSelected ? 0.35 : 0.15}
                      className={node.type === 'CAMPAIGN' ? 'animate-pulse' : ''}
                    />
                  )}

                  {/* Core Node Circle */}
                  <circle
                    r={node.radius}
                    fill="#0f172a"
                    stroke={node.color}
                    strokeWidth={isSelected ? 3 : 2}
                    className="transition-transform group-hover:scale-110"
                  />

                  {/* Node Icon */}
                  <text
                    textAnchor="middle"
                    dy=".3em"
                    fontSize={node.radius > 20 ? '14' : '11'}
                  >
                    {node.icon}
                  </text>

                  {/* Node Label Text */}
                  <text
                    textAnchor="middle"
                    y={node.radius + 13}
                    fill={isSelected ? '#38bdf8' : '#cbd5e1'}
                    fontSize="10"
                    fontWeight={isSelected ? 'bold' : 'normal'}
                    fontFamily="monospace"
                    className="select-none pointer-events-none"
                  >
                    {node.label.length > 22 ? `${node.label.substring(0, 20)}...` : node.label}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>

        {/* Right Side Inspector Drawer */}
        {selectedNode && (
          <div className="absolute top-0 right-0 h-full w-96 bg-slate-900/95 border-l border-slate-800 shadow-2xl backdrop-blur-xl p-5 overflow-y-auto z-30 transition-transform">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center space-x-2">
                <span className="text-xl">{selectedNode.icon}</span>
                <div>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                    {selectedNode.type} Entity
                  </span>
                  <h3 className="text-sm font-bold text-white font-mono break-all">
                    {selectedNode.label}
                  </h3>
                </div>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-white text-sm p-1"
              >
                ✕
              </button>
            </div>

            {/* Risk Badge & Severity */}
            {selectedNode.riskScore !== undefined && (
              <div className="mb-4 bg-slate-950 p-3 rounded-xl border border-slate-800">
                <div className="flex items-center justify-between text-xs mb-1.5">
                  <span className="text-slate-400 font-semibold">Threat Risk Rating</span>
                  <span className="font-bold text-rose-400">{selectedNode.riskScore}/100</span>
                </div>
                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-emerald-400 via-amber-400 to-rose-500 transition-all duration-500"
                    style={{ width: `${selectedNode.riskScore}%` }}
                  />
                </div>
              </div>
            )}

            {/* Actions Bar */}
            <div className="flex flex-col gap-2 mb-4">
              <button
                onClick={() => handleExpandNeighbors(selectedNode.id)}
                className="w-full flex items-center justify-center space-x-2 px-3 py-2 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-bold transition-colors"
              >
                <Network className="w-3.5 h-3.5" />
                <span>Expand 1-Hop Neighbors</span>
              </button>

              {selectedNode.type === 'DOMAIN' && (
                <a
                  href={`/domains/${encodeURIComponent(selectedNode.label)}`}
                  className="w-full flex items-center justify-center space-x-2 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors"
                >
                  <Globe className="w-3.5 h-3.5 text-purple-400" />
                  <span>Inspect Domain Dossier</span>
                </a>
              )}
            </div>

            {/* Connected Relationships List */}
            <div className="mb-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                Connected IOCs ({activeConnectedEdges.length})
              </h4>
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {activeConnectedEdges.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">No connected edges mapped yet.</p>
                ) : (
                  activeConnectedEdges.map((edge) => {
                    const otherId = edge.source === selectedNode.id ? edge.target : edge.source;
                    const otherNode = visualNodes.find((n) => n.id === otherId);
                    return (
                      <div
                        key={edge.id}
                        onClick={() => {
                          if (otherNode) setSelectedNode(otherNode);
                        }}
                        className="flex items-center justify-between p-2 rounded-lg bg-slate-950/70 border border-slate-800/80 hover:border-cyan-500/40 cursor-pointer transition-colors text-xs"
                      >
                        <span className="font-mono text-slate-300 truncate max-w-[170px]">
                          {otherNode?.label || otherId}
                        </span>
                        <span className="text-[10px] font-semibold text-cyan-400 bg-cyan-500/10 px-1.5 py-0.5 rounded">
                          {edge.type}
                        </span>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Raw Properties Accordion */}
            {selectedNode.properties && Object.keys(selectedNode.properties).length > 0 && (
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
                  <Info className="w-3.5 h-3.5 text-slate-400" />
                  Entity Metadata
                </h4>
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80 text-[11px] font-mono text-slate-300 space-y-1 overflow-x-auto">
                  {Object.entries(selectedNode.properties).map(([k, v]) => (
                    <div key={k} className="flex justify-between gap-2 border-b border-slate-900 pb-1">
                      <span className="text-slate-500">{k}:</span>
                      <span className="text-slate-200 text-right font-semibold">{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
