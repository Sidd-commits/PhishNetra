import { Router, Request, Response } from 'express';
import { QuishingScanRequestSchema } from '@phishnetra/shared';
import { quishingDefenseService } from '../services/multimodal/QuishingDefenseService';

export const quishingRouter = Router();

// POST /api/quishing/scan
quishingRouter.post('/scan', async (req: Request, res: Response) => {
  try {
    const parsed = QuishingScanRequestSchema.parse(req.body);
    const result = await quishingDefenseService.scanQuishing(parsed);
    return res.status(200).json({ success: true, data: result });
  } catch (error: any) {
    return res.status(400).json({
      success: false,
      error: { code: 'INVALID_QUISHING_REQUEST', message: error.message }
    });
  }
});

// GET /api/quishing/samples
quishingRouter.get('/samples', (_req: Request, res: Response) => {
  return res.status(200).json({
    success: true,
    data: [
      {
        title: 'MFA Authenticator Reset Lure',
        imageUrl: 'https://cdn.phishnetra.internal/samples/qr-okta-mfa-reset.png',
        rawText: 'Scan to update your Authenticator app now to avoid immediate account suspension',
        targetedBrand: 'Okta'
      },
      {
        title: 'Microsoft 365 Password Expiry Lure',
        imageUrl: 'https://cdn.phishnetra.internal/samples/qr-m365-expiry.png',
        rawText: 'Microsoft 365 security alert: Session expired. Scan QR barcode with mobile device.',
        targetedBrand: 'Microsoft 365'
      },
      {
        title: 'Overdue Vendor Wire Transfer QR',
        imageUrl: 'https://cdn.phishnetra.internal/samples/qr-invoice-payment.png',
        rawText: 'Urgent DocuSign Invoice pending payment wire transfer verification.',
        targetedBrand: 'DocuSign'
      }
    ]
  });
});
