import { Router, Request, Response } from 'express';
import { attackSimulationService } from '../services/simulation/AttackSimulationService';
import { AttackSimulationRequestSchema } from '@phishnetra/shared';

const router = Router();

// GET /api/simulation/presets - List pre-configured attack scenarios
router.get('/presets', (req: Request, res: Response) => {
  try {
    const presets = attackSimulationService.listPresets();
    return res.status(200).json({
      success: true,
      data: presets
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { message: err.message || 'Failed to list attack presets' }
    });
  }
});

// POST /api/simulation/run - Execute simulated attack scenario
router.post('/run', async (req: Request, res: Response) => {
  try {
    const parseResult = AttackSimulationRequestSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        error: {
          message: 'Invalid simulation request payload',
          details: parseResult.error.format()
        }
      });
    }

    const actor = (req as any).user?.email || 'admin@phishnetra.internal';
    const result = await attackSimulationService.simulateAttack(parseResult.data, actor);

    return res.status(200).json({
      success: true,
      data: result
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { message: err.message || 'Attack simulation execution failed' }
    });
  }
});

// POST /api/simulation/benchmark - Run Red Team Automated Defense Benchmark
router.post('/benchmark', async (req: Request, res: Response) => {
  try {
    const actor = (req as any).user?.email || 'admin@phishnetra.internal';
    const report = await attackSimulationService.runAutomatedBenchmark(actor);

    return res.status(200).json({
      success: true,
      data: report
    });
  } catch (err: any) {
    return res.status(500).json({
      success: false,
      error: { message: err.message || 'Defense benchmark execution failed' }
    });
  }
});

export default router;
