import { Router, Request, Response } from 'express';
import { threatReportExportService } from '../services/reports/ThreatReportExportService';
import { requireAuth } from '../middleware/authMiddleware';

const router = Router();

// Generate executive threat briefing JSON
router.get('/', requireAuth, async (req: Request, res: Response) => {
  try {
    const timeRange = (req.query.timeRange as string) || 'Last 30 Days';
    const report = await threatReportExportService.generateExecutiveReport(timeRange);
    res.status(200).json({ success: true, data: report });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Download Markdown / Plain Text dossier
router.get('/download/markdown', requireAuth, async (req: Request, res: Response) => {
  try {
    const timeRange = (req.query.timeRange as string) || 'Last 30 Days';
    const report = await threatReportExportService.generateExecutiveReport(timeRange);
    const md = threatReportExportService.generateMarkdownReport(report);
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="PhishNetra_Executive_Report_${Date.now()}.md"`);
    res.status(200).send(md);
  } catch (err: any) {
    res.status(500).send(`# ERROR: Failed to generate report: ${err.message}\n`);
  }
});

export default router;
