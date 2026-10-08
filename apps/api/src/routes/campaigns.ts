import { Router, Request, Response } from 'express';
import { CampaignClusteringEngine } from '../services/graph/CampaignClusteringEngine';
import { STIXExportService } from '../services/graph/STIXExportService';

const router = Router();

/**
 * GET /api/campaigns
 * Lists all detected threat campaigns
 */
router.get('/', async (req: Request, res: Response) => {
  try {
    const status = req.query.status as string;
    const brand = req.query.brand as string;
    const limit = parseInt(req.query.limit as string, 10) || 50;

    const campaigns = await CampaignClusteringEngine.listCampaigns({ status, brand, limit });
    return res.json({ success: true, data: campaigns });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/campaigns/cluster
 * Triggers on-demand autonomous threat campaign clustering across infrastructure
 */
router.post('/cluster', async (_req: Request, res: Response) => {
  try {
    const result = await CampaignClusteringEngine.runClustering();
    return res.json({ success: true, data: result });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/campaigns/:id
 * Retrieves detailed threat campaign profile
 */
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const campaign = await CampaignClusteringEngine.getCampaignById(req.params.id);
    if (!campaign) {
      return res.status(404).json({ success: false, error: 'Campaign not found' });
    }
    return res.json({ success: true, data: campaign });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/campaigns/:id/stix
 * Downloads STIX 2.1 JSON bundle for a specific campaign
 */
router.get('/:id/stix', async (req: Request, res: Response) => {
  try {
    const campaign = await CampaignClusteringEngine.getCampaignById(req.params.id);
    if (!campaign) {
      return res.status(404).json({ success: false, error: 'Campaign not found' });
    }

    const stixBundle = STIXExportService.generateCampaignSTIXBundle(campaign);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="stix-campaign-${campaign.id}.json"`);
    return res.json(stixBundle);
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
