import { Router, Request, Response } from 'express';
import { ThreatGraphEngine } from '../services/graph/ThreatGraphEngine';
import { STIXExportService } from '../services/graph/STIXExportService';

const router = Router();

/**
 * GET /api/graph/overview
 * Returns global threat infrastructure graph statistics and top connected nodes
 */
router.get('/overview', async (req: Request, res: Response) => {
  try {
    const limit = parseInt(req.query.limit as string, 10) || 80;
    const overview = await ThreatGraphEngine.getGraphOverview(limit);
    return res.json({ success: true, data: overview });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/graph/domain/:domain
 * Returns k-hop sub-graph centered around a specific domain
 */
router.get('/domain/:domain', async (req: Request, res: Response) => {
  try {
    const domain = req.params.domain;
    const depth = parseInt(req.query.depth as string, 10) || 2;
    const maxNodes = parseInt(req.query.maxNodes as string, 10) || 60;

    const subGraph = await ThreatGraphEngine.getDomainSubGraph(domain, depth, maxNodes);
    return res.json({ success: true, data: subGraph });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/graph/nodes/:id/neighbors
 * Returns 1-hop immediate neighbors for node expansion in interactive canvas
 */
router.get('/nodes/:id/neighbors', async (req: Request, res: Response) => {
  try {
    const nodeId = req.params.id;
    const limit = parseInt(req.query.limit as string, 10) || 30;

    const neighbors = await ThreatGraphEngine.getNodeNeighbors(nodeId, limit);
    return res.json({ success: true, data: neighbors });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/graph/search
 * Search graph entities by label and optional type filter
 */
router.get('/search', async (req: Request, res: Response) => {
  try {
    const q = (req.query.q as string) || '';
    const type = (req.query.type as string) || 'ALL';
    const limit = parseInt(req.query.limit as string, 10) || 25;

    const results = await ThreatGraphEngine.searchNodes(q, type, limit);
    return res.json({ success: true, data: results });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/graph/export/stix
 * Exports current domain subgraph or global overview as STIX 2.1 JSON bundle
 */
router.get('/export/stix', async (req: Request, res: Response) => {
  try {
    const domain = req.query.domain as string;
    let graphData;
    if (domain) {
      graphData = await ThreatGraphEngine.getDomainSubGraph(domain, 2, 50);
    } else {
      graphData = await ThreatGraphEngine.getGraphOverview(80);
    }

    const stixBundle = STIXExportService.generateGraphSTIXBundle(graphData);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="phishnetra-threat-graph-${Date.now()}.json"`);
    return res.json(stixBundle);
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
