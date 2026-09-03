import tls from 'tls';
import { TLSIntelligence, EvidenceItem } from '@phishnetra/shared';

// In-memory TLS cache
const tlsCache = new Map<string, { data: TLSIntelligence; evidence: EvidenceItem[]; expires: number }>();
const TLS_CACHE_TTL = 1000 * 60 * 30; // 30 mins

export class TLSLayer {
  /**
   * Safely inspects TLS socket certificate metadata without fetching webpage content.
   */
  public async analyze(protocol: string, hostname: string, port?: number | null): Promise<{
    data: TLSIntelligence;
    evidence: EvidenceItem[];
  }> {
    const evidence: EvidenceItem[] = [];

    // 1. Plain HTTP Check
    if (protocol.toLowerCase() === 'http:') {
      evidence.push({
        layer: 'TLS',
        featureKey: 'unencrypted_http_protocol',
        featureValue: 'HTTP',
        severity: 'LOW',
        description: 'Target communicates over unencrypted HTTP. Transport data and credentials can be sniffed in transit.',
        contribution: 0.15,
        source: 'TLS_Inspector',
        confidence: 1.0
      });

      return {
        data: {
          status: 'SUCCESS',
          hasTls: false,
          certificateValid: false,
          certificateExpired: false,
          hostnameMatches: false,
          validFrom: null,
          validTo: null,
          daysUntilExpiry: null,
          issuer: null,
          subject: null,
          sans: [],
          tlsVersion: null,
          zeroTrustWarning: 'Target operates over unencrypted HTTP (No TLS certificate present).'
        },
        evidence
      };
    }

    // Check if target is raw IP
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);

    // Cache check
    const cacheKey = `${hostname}:${port || 443}`;
    const cached = tlsCache.get(cacheKey);
    if (cached && cached.expires > Date.now()) {
      return { data: cached.data, evidence: cached.evidence };
    }

    const connectPort = port || 443;

    try {
      const certInfo = await this.fetchCertificate(hostname, connectPort);

      const validToMs = new Date(certInfo.valid_to).getTime();
      const validFromMs = new Date(certInfo.valid_from).getTime();
      const nowMs = Date.now();

      const daysUntilExpiry = !isNaN(validToMs) ? Math.floor((validToMs - nowMs) / (1000 * 60 * 60 * 24)) : null;
      const certificateExpired = daysUntilExpiry !== null && daysUntilExpiry < 0;

      // Extract SANs
      const sans: string[] = [];
      if (certInfo.subjectaltname) {
        const rawSans = certInfo.subjectaltname.split(', ');
        sans.push(...rawSans.map((s: string) => s.replace(/^DNS:/, '')));
      }

      // Check hostname match
      let hostnameMatches = false;
      if (certInfo.subject?.CN && this.matchHost(hostname, certInfo.subject.CN)) {
        hostnameMatches = true;
      }
      if (!hostnameMatches && sans.some((san: string) => this.matchHost(hostname, san))) {
        hostnameMatches = true;
      }

      const certificateValid = certInfo.authorized && !certificateExpired;

      // Zero-Trust Warnings & Evidence
      if (certificateExpired) {
        evidence.push({
          layer: 'TLS',
          featureKey: 'expired_tls_certificate',
          featureValue: `Expired ${Math.abs(daysUntilExpiry || 0)} days ago`,
          severity: 'HIGH',
          description: 'TLS certificate is expired. Communications are insecure and trigger browser warning pages.',
          contribution: 0.30,
          source: 'TLS_Inspector',
          confidence: 0.95
        });
      } else if (!certInfo.authorized) {
        evidence.push({
          layer: 'TLS',
          featureKey: 'untrusted_tls_issuer',
          featureValue: certInfo.authorizationError || 'Untrusted Root CA',
          severity: 'HIGH',
          description: `TLS certificate failed root validation (${certInfo.authorizationError || 'Self-Signed / Untrusted CA'}).`,
          contribution: 0.25,
          source: 'TLS_Inspector',
          confidence: 0.95
        });
      }

      if (!hostnameMatches && !isIp) {
        evidence.push({
          layer: 'TLS',
          featureKey: 'tls_hostname_mismatch',
          featureValue: `Cert SANs: ${sans.slice(0, 3).join(', ')}`,
          severity: 'HIGH',
          description: `Hostname (${hostname}) does not match subject names on the presenting TLS certificate.`,
          contribution: 0.35,
          source: 'TLS_Inspector',
          confidence: 0.95
        });
      }

      // Check for Let's Encrypt / DV automated certs on banking keywords
      const issuerStr = certInfo.issuer?.O || certInfo.issuer?.CN || 'Unknown';
      if (issuerStr.toLowerCase().includes("let's encrypt") || issuerStr.toLowerCase().includes('cloudflare')) {
        evidence.push({
          layer: 'TLS',
          featureKey: 'domain_validated_dv_certificate',
          featureValue: issuerStr,
          severity: 'INFO',
          description: `Domain Validated (DV) certificate issued by ${issuerStr}. Zero-Trust rule: HTTPS encrypts traffic but does NOT guarantee identity or legitimacy.`,
          contribution: 0.0,
          source: 'TLS_Inspector',
          confidence: 1.0
        });
      }

      const data: TLSIntelligence = {
        status: 'SUCCESS',
        hasTls: true,
        certificateValid,
        certificateExpired,
        hostnameMatches,
        validFrom: certInfo.valid_from || null,
        validTo: certInfo.valid_to || null,
        daysUntilExpiry,
        issuer: issuerStr,
        subject: certInfo.subject?.CN || 'Unknown',
        sans,
        tlsVersion: certInfo.tlsVersion || 'TLSv1.3',
        zeroTrustWarning: 'ZERO-TRUST PRINCIPLE: A valid TLS/HTTPS certificate proves encryption in transit, NOT that the host is trustworthy or safe.'
      };

      tlsCache.set(cacheKey, { data, evidence, expires: Date.now() + TLS_CACHE_TTL });
      return { data, evidence };
    } catch (err: any) {
      // TLS Handshake timeout or connection refused
      const errorMsg = err.message || 'TLS connection failed';
      evidence.push({
        layer: 'TLS',
        featureKey: 'tls_handshake_failure',
        featureValue: errorMsg,
        severity: 'MEDIUM',
        description: `Failed to establish TLS socket handshake on port ${connectPort} (${errorMsg}).`,
        contribution: 0.15,
        source: 'TLS_Inspector',
        confidence: 0.85
      });

      return {
        data: {
          status: 'FAILED',
          hasTls: true,
          certificateValid: false,
          certificateExpired: false,
          hostnameMatches: false,
          validFrom: null,
          validTo: null,
          daysUntilExpiry: null,
          issuer: null,
          subject: null,
          sans: [],
          tlsVersion: null,
          zeroTrustWarning: 'TLS inspection failed or timed out.',
          error: errorMsg
        },
        evidence
      };
    }
  }

  private fetchCertificate(hostname: string, port: number): Promise<any> {
    return new Promise((resolve, reject) => {
      const socket = tls.connect(
        {
          host: hostname,
          port,
          servername: hostname,
          rejectUnauthorized: false,
          timeout: 3000
        },
        () => {
          const cert = socket.getPeerCertificate(true);
          const authorized = socket.authorized;
          const authorizationError = socket.authorizationError;
          const tlsVersion = socket.getProtocol();
          socket.end();

          if (!cert || Object.keys(cert).length === 0) {
            reject(new Error('No certificate presented by peer'));
          } else {
            resolve({
              ...cert,
              authorized,
              authorizationError,
              tlsVersion
            });
          }
        }
      );

      socket.on('error', (err) => {
        socket.destroy();
        reject(err);
      });

      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('TLS Handshake Timeout (3000ms)'));
      });
    });
  }

  private matchHost(hostname: string, pattern: string): boolean {
    if (pattern === hostname) return true;
    if (pattern.startsWith('*.')) {
      const rootDomain = pattern.slice(2);
      return hostname.endsWith(rootDomain) && hostname.split('.').length === pattern.split('.').length;
    }
    return false;
  }
}

export const tlsLayer = new TLSLayer();
