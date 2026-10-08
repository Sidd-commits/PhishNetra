import { Router, Request, Response } from 'express';
import { taxiiServerService } from '../services/taxii/TaxiiServerService';

const router = Router();

// GET /api/taxii21/discovery (Standard TAXII 2.1 Server Discovery)
router.get('/discovery', (req: Request, res: Response) => {
  try {
    const discovery = taxiiServerService.getDiscovery();
    res.setHeader('Content-Type', 'application/taxii+json;version=2.1');
    return res.json(discovery);
  } catch (err: any) {
    return res.status(500).json({ error: 'TAXII discovery failed', details: err.message });
  }
});

// GET /api/taxii21/collections (List TAXII Collections)
router.get('/collections', (req: Request, res: Response) => {
  try {
    const collections = taxiiServerService.listCollections();
    res.setHeader('Content-Type', 'application/taxii+json;version=2.1');
    return res.json({ collections });
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to list collections', details: err.message });
  }
});

// GET /api/taxii21/collections/:id (Collection details)
router.get('/collections/:id', (req: Request, res: Response) => {
  try {
    const collection = taxiiServerService.getCollection(req.params.id);
    if (!collection) {
      return res.status(404).json({ error: 'TAXII collection not found' });
    }
    res.setHeader('Content-Type', 'application/taxii+json;version=2.1');
    return res.json(collection);
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to get collection', details: err.message });
  }
});

// GET /api/taxii21/collections/:id/objects (STIX 2.1 Objects in collection)
router.get('/collections/:id/objects', (req: Request, res: Response) => {
  try {
    const objects = taxiiServerService.getStixObjects(req.params.id);
    res.setHeader('Content-Type', 'application/stix+json;version=2.1');
    return res.json(objects);
  } catch (err: any) {
    return res.status(500).json({ error: 'Failed to retrieve STIX objects', details: err.message });
  }
});

export default router;
