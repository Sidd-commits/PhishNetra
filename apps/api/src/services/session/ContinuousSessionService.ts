import {
  SessionTelemetryProbe,
  ContinuousRiskAssessment
} from '@phishnetra/shared';
import crypto from 'crypto';
import { auditLogService } from '../audit/AuditLogService';

export class ContinuousSessionService {
  // Store historical telemetry by sessionId
  private sessionHistory: Map<string, SessionTelemetryProbe[]> = new Map();

  constructor() {
    // Seed initial active sessions
    this.sessionHistory.set('sess-emp-01', [
      {
        sessionId: 'sess-emp-01',
        userEmail: 'alice.security@enterprise.com',
        timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
        ipAddress: '198.51.100.12',
        geoCoordinates: {
          latitude: 40.7128,
          longitude: -74.006,
          city: 'New York',
          country: 'United States'
        },
        tlsJa3Fingerprint: '771,4865-4866-4867,0-23-65281-10-11,29-23-24,0',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
      }
    ]);
  }

  // Haversine distance formula in kilometers
  private calculateHaversineDistanceKm(
    lat1: number,
    lon1: number,
    lat2: number,
    lon2: number
  ): number {
    const R = 6371; // Earth radius in km
    const dLat = ((lat2 - lat1) * Math.PI) / 180;
    const dLon = ((lon2 - lon1) * Math.PI) / 180;
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos((lat1 * Math.PI) / 180) *
        Math.cos((lat2 * Math.PI) / 180) *
        Math.sin(dLon / 2) *
        Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return Number((R * c).toFixed(2));
  }

  public evaluateSession(probe: SessionTelemetryProbe): ContinuousRiskAssessment {
    const assessmentId = `cra-${crypto.randomUUID()}`;
    const evaluatedAt = new Date().toISOString();
    const anomaliesDetected: string[] = [];
    let continuousRiskScore = 10;
    let impossibleTravelVelocityKmh: number | undefined = undefined;
    let tlsDriftDetected = false;
    let deviceProfileMutated = false;

    const history = this.sessionHistory.get(probe.sessionId) || [];
    const lastProbe = history[history.length - 1];

    if (lastProbe) {
      // 1. Calculate Velocity (Impossible Travel)
      const timeDiffHours =
        (new Date(probe.timestamp).getTime() - new Date(lastProbe.timestamp).getTime()) /
        (1000 * 60 * 60);

      const distanceKm = this.calculateHaversineDistanceKm(
        lastProbe.geoCoordinates.latitude,
        lastProbe.geoCoordinates.longitude,
        probe.geoCoordinates.latitude,
        probe.geoCoordinates.longitude
      );

      if (timeDiffHours > 0) {
        impossibleTravelVelocityKmh = Math.round(distanceKm / timeDiffHours);
        // Commercial aviation threshold: 850 km/h
        if (impossibleTravelVelocityKmh > 850) {
          anomaliesDetected.push(
            `Impossible travel velocity: ${impossibleTravelVelocityKmh} km/h between ${lastProbe.geoCoordinates.city} and ${probe.geoCoordinates.city}`
          );
          continuousRiskScore += 60;
        }
      }

      // 2. TLS JA3 Signature Drift
      if (probe.tlsJa3Fingerprint !== lastProbe.tlsJa3Fingerprint) {
        tlsDriftDetected = true;
        anomaliesDetected.push('TLS JA3 fingerprint drift on persistent session cookie token');
        continuousRiskScore += 35;
      }

      // 3. User-Agent / Device Profile Mutation
      if (probe.userAgent !== lastProbe.userAgent) {
        deviceProfileMutated = true;
        anomaliesDetected.push('Client User-Agent profile altered mid-session');
        continuousRiskScore += 25;
      }
    }

    continuousRiskScore = Math.min(100, Math.max(5, continuousRiskScore));

    // Determine Action
    let actionTaken: ContinuousRiskAssessment['actionTaken'] = 'ALLOW';
    let killSwitchDispatched = false;

    if (continuousRiskScore >= 80) {
      actionTaken = 'TERMINATE_SESSION';
      killSwitchDispatched = true;
    } else if (continuousRiskScore >= 45) {
      actionTaken = 'STEP_UP_CHALLENGE';
    }

    // Append to session history
    history.push(probe);
    this.sessionHistory.set(probe.sessionId, history);

    // Audit log
    auditLogService.log({
      actor: probe.userEmail,
      action: 'CONTINUOUS_SESSION_EVALUATED',
      details: JSON.stringify({
        assessmentId,
        sessionId: probe.sessionId,
        score: continuousRiskScore,
        action: actionTaken,
        anomalies: anomaliesDetected
      }),
      category: 'SECURITY',
      severity: actionTaken === 'TERMINATE_SESSION' ? 'CRITICAL' : actionTaken === 'STEP_UP_CHALLENGE' ? 'WARNING' : 'INFO'
    });

    return {
      assessmentId,
      sessionId: probe.sessionId,
      userEmail: probe.userEmail,
      evaluatedAt,
      continuousRiskScore,
      anomaliesDetected,
      impossibleTravelVelocityKmh,
      tlsDriftDetected,
      deviceProfileMutated,
      actionTaken,
      killSwitchDispatched
    };
  }

  public getSessionHistory(sessionId: string): SessionTelemetryProbe[] {
    return this.sessionHistory.get(sessionId) || [];
  }
}

export const continuousSessionService = new ContinuousSessionService();
