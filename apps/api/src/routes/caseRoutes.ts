import { Router, Request, Response } from 'express';
import { caseManagementService } from '../services/cases/CaseManagementService';
import {
  CreateCaseRequestSchema,
  UpdateCaseRequestSchema,
  RemediationTypeSchema
} from '@phishnetra/shared';
import { z } from 'zod';

const router = Router();

const AddNoteSchema = z.object({
  author: z.string().min(2),
  text: z.string().min(2)
});

const RemediateSchema = z.object({
  actionType: RemediationTypeSchema
});

/**
 * GET /api/cases
 * List SOC cases with optional status/severity filters
 */
router.get('/', (req: Request, res: Response, next) => {
  try {
    const status = req.query.status as string | undefined;
    const severity = req.query.severity as string | undefined;
    const cases = caseManagementService.listCases({ status, severity });
    res.json({
      success: true,
      data: cases
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/cases
 * Create a new security case
 */
router.post('/', (req: Request, res: Response, next) => {
  try {
    const payload = CreateCaseRequestSchema.parse(req.body);
    const created = caseManagementService.createCase(payload);
    res.status(201).json({
      success: true,
      data: created
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/cases/:id
 * Retrieve specific case details
 */
router.get('/:id', (req: Request, res: Response, next) => {
  try {
    const c = caseManagementService.getCase(req.params.id);
    if (!c) {
      res.status(404).json({ error: 'Not Found', message: `Case '${req.params.id}' not found` });
      return;
    }
    res.json({
      success: true,
      data: c
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PATCH /api/cases/:id
 * Update case status, severity, or assignment
 */
router.patch('/:id', (req: Request, res: Response, next) => {
  try {
    const payload = UpdateCaseRequestSchema.parse(req.body);
    const updated = caseManagementService.updateCase(req.params.id, payload);
    res.json({
      success: true,
      data: updated
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/cases/:id/notes
 * Add an investigation note to the case
 */
router.post('/:id/notes', (req: Request, res: Response, next) => {
  try {
    const { author, text } = AddNoteSchema.parse(req.body);
    const updated = caseManagementService.addNote(req.params.id, author, text);
    res.json({
      success: true,
      data: updated
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/cases/:id/remediate
 * Generate SOC remediation defense artifacts (DNS RPZ, Firewall, Abuse Notice)
 */
router.post('/:id/remediate', (req: Request, res: Response, next) => {
  try {
    const { actionType } = RemediateSchema.parse(req.body);
    const result = caseManagementService.executeRemediation(req.params.id, actionType);
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    next(error);
  }
});

export default router;
