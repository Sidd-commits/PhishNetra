import crypto from 'crypto';
import {
  AttackSurfaceAsset,
  CTLogEntry,
  CreateAttackSurfaceAssetRequest,
  RiskLevel
} from '@phishnetra/shared';
import { auditLogService } from '../audit/AuditLogService';

export class AttackSurfaceService {
  private static instance: AttackSurfaceService;

  private assets: Map<string, AttackSurfaceAsset> = new Map();
  private ctLogs: CTLogEntry[] = [];

  constructor() {
    this.seedDefaultAssets();
    this.seedCTLogs();
  }

  public static getInstance(): AttackSurfaceService {
    if (!AttackSurfaceService.instance) {
      AttackSurfaceService.instance = new AttackSurfaceService();
    }
    return AttackSurfaceService.instance;
  }

  private seedDefaultAssets(): void {
    const defaultAssets: AttackSurfaceAsset[] = [
      {
        id: 'asset-001',
        name: 'Primary Corporate Apex Domain',
        assetType: 'DOMAIN',
        targetValue: 'phishnetra.security',
        riskLevel: 'LOW',
        status: 'MONITORED',
        discoverySource: 'MANUAL',
        associatedBrands: ['PhishNetra'],
        openPorts: [80, 443],
        tlsExpiryDate: new Date(Date.now() + 86400 * 1000 * 240).toISOString(),
        detectedThreatsCount: 0,
        lastScannedAt: new Date().toISOString(),
        createdAt: new Date(Date.now() - 86400 * 1000 * 90).toISOString()
      },
      {
        id: 'asset-002',
        name: 'Single Sign-On Auth Gateway',
        assetType: 'SUBDOMAIN',
        targetValue: 'sso.phishnetra.security',
        riskLevel: 'LOW',
        status: 'MONITORED',
        discoverySource: 'CT_LOGS',
        associatedBrands: ['PhishNetra'],
        openPorts: [443],
        tlsExpiryDate: new Date(Date.now() + 86400 * 1000 * 65).toISOString(),
        detectedThreatsCount: 1,
        lastScannedAt: new Date(Date.now() - 3600 * 1000 * 2).toISOString(),
        createdAt: new Date(Date.now() - 86400 * 1000 * 60).toISOString()
      },
      {
        id: 'asset-003',
        name: 'Microsoft 365 Impersonation Radar',
        assetType: 'BRAND_KEYWORD',
        targetValue: 'microsoft-login',
        riskLevel: 'HIGH',
        status: 'ATTACKED',
        discoverySource: 'DARK_WEB',
        associatedBrands: ['Microsoft', 'Azure'],
        openPorts: [],
        tlsExpiryDate: null,
        detectedThreatsCount: 14,
        lastScannedAt: new Date(Date.now() - 3600 * 1000 * 1).toISOString(),
        createdAt: new Date(Date.now() - 86400 * 1000 * 30).toISOString()
      },
      {
        id: 'asset-004',
        name: 'Cloud Ingress Load Balancer IP',
        assetType: 'IP_ADDRESS',
        targetValue: '198.51.100.22',
        riskLevel: 'MEDIUM',
        status: 'MONITORED',
        discoverySource: 'DNS_BRUTEFORCE',
        associatedBrands: ['PhishNetra'],
        openPorts: [80, 443, 8080, 8443],
        tlsExpiryDate: null,
        detectedThreatsCount: 0,
        lastScannedAt: new Date(Date.now() - 3600 * 1000 * 6).toISOString(),
        createdAt: new Date(Date.now() - 86400 * 1000 * 45).toISOString()
      }
    ];

    for (const a of defaultAssets) {
      this.assets.set(a.id, a);
    }
  }

  private seedCTLogs(): void {
    this.ctLogs = [
      {
        id: 'ct-001',
        domain: 'phishnetra-secure-login.xyz',
        issuer: "Let's Encrypt Authority X3",
        sanNames: ['phishnetra-secure-login.xyz', 'auth.phishnetra-secure-login.xyz'],
        loggedAt: new Date(Date.now() - 3600 * 1000 * 2).toISOString(),
        isTyposquat: true,
        targetedBrand: 'PhishNetra',
        riskScore: 96.5,
        autoQuarantined: true
      },
      {
        id: 'ct-002',
        domain: 'microsoft-security-verify-365.com',
        issuer: 'ZeroSSL RSA Domain Secure CA',
        sanNames: ['microsoft-security-verify-365.com', 'login.microsoft-security-verify-365.com'],
        loggedAt: new Date(Date.now() - 3600 * 1000 * 4).toISOString(),
        isTyposquat: true,
        targetedBrand: 'Microsoft',
        riskScore: 98.0,
        autoQuarantined: true
      },
      {
        id: 'ct-003',
        domain: 'api-gateway.phishnetra.security',
        issuer: 'DigiCert Global Root G2',
        sanNames: ['api-gateway.phishnetra.security'],
        loggedAt: new Date(Date.now() - 3600 * 1000 * 12).toISOString(),
        isTyposquat: false,
        targetedBrand: 'PhishNetra',
        riskScore: 10.0,
        autoQuarantined: false
      }
    ];
  }

  public listAssets(): AttackSurfaceAsset[] {
    return Array.from(this.assets.values()).sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }

  public getAsset(id: string): AttackSurfaceAsset | null {
    return this.assets.get(id) || null;
  }

  public createAsset(req: CreateAttackSurfaceAssetRequest, actor: { id: string; name: string }): AttackSurfaceAsset {
    const id = `asset-${crypto.randomBytes(4).toString('hex')}`;
    const now = new Date().toISOString();

    const asset: AttackSurfaceAsset = {
      id,
      name: req.name,
      assetType: req.assetType,
      targetValue: req.targetValue,
      riskLevel: 'LOW',
      status: 'MONITORED',
      discoverySource: 'MANUAL',
      associatedBrands: req.associatedBrands || [],
      openPorts: req.assetType === 'DOMAIN' || req.assetType === 'SUBDOMAIN' ? [80, 443] : [],
      tlsExpiryDate: req.assetType === 'DOMAIN' || req.assetType === 'SSL_CERTIFICATE'
        ? new Date(Date.now() + 86400 * 1000 * 90).toISOString()
        : null,
      detectedThreatsCount: 0,
      lastScannedAt: now,
      createdAt: now
    };

    this.assets.set(id, asset);

    auditLogService.log({
      actor: actor.name,
      action: 'ADD_ATTACK_SURFACE_ASSET',
      category: 'CONFIG',
      target: id,
      details: `Added perimeter asset "${req.name}" (${req.assetType}: ${req.targetValue})`,
      severity: 'INFO'
    });

    return asset;
  }

  public removeAsset(id: string, actor: { id: string; name: string }): boolean {
    const exists = this.assets.has(id);
    if (!exists) return false;

    this.assets.delete(id);

    auditLogService.log({
      actor: actor.name,
      action: 'REMOVE_ATTACK_SURFACE_ASSET',
      category: 'CONFIG',
      target: id,
      details: `Removed perimeter asset ${id}`,
      severity: 'WARNING'
    });

    return true;
  }

  public listCTLogs(): CTLogEntry[] {
    return [...this.ctLogs].sort(
      (a, b) => new Date(b.loggedAt).getTime() - new Date(a.loggedAt).getTime()
    );
  }

  public triggerPerimeterScan(): { totalAssets: number; scannedAt: string; newlyDiscoveredCount: number } {
    const now = new Date().toISOString();
    for (const asset of this.assets.values()) {
      asset.lastScannedAt = now;
      this.assets.set(asset.id, asset);
    }
    return {
      totalAssets: this.assets.size,
      scannedAt: now,
      newlyDiscoveredCount: Math.floor(Math.random() * 3) + 1
    };
  }
}

export const attackSurfaceService = AttackSurfaceService.getInstance();
