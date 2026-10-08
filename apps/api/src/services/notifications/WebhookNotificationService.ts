import crypto from 'crypto';
import axios from 'axios';
import {
  WebhookConfig,
  CreateWebhookRequest,
  WebhookDeliveryLog,
  AnalysisResponse,
  ThreatCampaign,
  SOCCase
} from '@phishnetra/shared';

export class WebhookNotificationService {
  private webhooks: Map<string, WebhookConfig> = new Map();
  private deliveryLogs: WebhookDeliveryLog[] = [];

  constructor() {
    this.seedDefaultWebhooks();
  }

  private seedDefaultWebhooks() {
    const defaultWebhook: WebhookConfig = {
      id: 'wh_default_slack',
      name: 'Primary SOC Slack Channel',
      url: 'https://notifications.phishnetra.internal/alerts/slack',
      channelType: 'SLACK',
      secretKey: 'phishnetra_soc_secret_key',
      minSeverity: 'HIGH',
      events: ['CRITICAL_THREAT_DETECTED', 'CAMPAIGN_CLUSTERED', 'CASE_CREATED'],
      enabled: true,
      createdAt: new Date().toISOString(),
      lastTriggeredAt: null
    };
    this.webhooks.set(defaultWebhook.id, defaultWebhook);
  }

  public listWebhooks(): WebhookConfig[] {
    return Array.from(this.webhooks.values());
  }

  public getWebhook(id: string): WebhookConfig | undefined {
    return this.webhooks.get(id);
  }

  public createWebhook(req: CreateWebhookRequest): WebhookConfig {
    const id = `wh_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const config: WebhookConfig = {
      id,
      name: req.name,
      url: req.url,
      channelType: req.channelType,
      secretKey: req.secretKey || null,
      minSeverity: req.minSeverity || 'HIGH',
      events: req.events || ['CRITICAL_THREAT_DETECTED', 'CAMPAIGN_CLUSTERED', 'CASE_CREATED'],
      enabled: req.enabled ?? true,
      createdAt: new Date().toISOString(),
      lastTriggeredAt: null
    };

    this.webhooks.set(id, config);
    return config;
  }

  public deleteWebhook(id: string): boolean {
    return this.webhooks.delete(id);
  }

  public getLogs(limit: number = 50): WebhookDeliveryLog[] {
    return this.deliveryLogs.slice(-limit).reverse();
  }

  public async testWebhook(id: string): Promise<WebhookDeliveryLog> {
    const webhook = this.webhooks.get(id);
    if (!webhook) {
      throw new Error(`Webhook '${id}' not found`);
    }

    const testPayload = {
      event: 'TEST_ALERT',
      message: 'This is a test notification from the PhishNetra Zero-Trust Threat Mitigation platform.',
      timestamp: new Date().toISOString(),
      platform: 'PhishNetra SOC Engine v1.0'
    };

    return this.sendNotification(webhook, 'TEST_ALERT', testPayload);
  }

  public async dispatchThreatAlert(analysis: AnalysisResponse): Promise<void> {
    const isCritical = analysis.verdict === 'PHISHING' || analysis.riskLevel === 'CRITICAL' || analysis.riskScore >= 80;
    const isHigh = analysis.riskLevel === 'HIGH' || analysis.riskScore >= 60;

    for (const wh of this.webhooks.values()) {
      if (!wh.enabled) continue;
      if (wh.minSeverity === 'CRITICAL' && !isCritical) continue;
      if (wh.minSeverity === 'HIGH' && (!isCritical && !isHigh)) continue;

      const payload = this.formatPayloadForChannel(wh.channelType, 'CRITICAL_THREAT_DETECTED', analysis);
      this.sendNotification(wh, 'CRITICAL_THREAT_DETECTED', payload).catch(err => {
        console.warn(`[Webhook] Dispatch failed for ${wh.name}:`, err.message);
      });
    }
  }

  public async dispatchCampaignAlert(campaign: ThreatCampaign): Promise<void> {
    for (const wh of this.webhooks.values()) {
      if (!wh.enabled) continue;
      const payload = this.formatCampaignPayload(wh.channelType, campaign);
      this.sendNotification(wh, 'CAMPAIGN_CLUSTERED', payload).catch(err => {
        console.warn(`[Webhook] Campaign dispatch failed for ${wh.name}:`, err.message);
      });
    }
  }

  private async sendNotification(
    webhook: WebhookConfig,
    event: string,
    payload: any
  ): Promise<WebhookDeliveryLog> {
    const logId = `log_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const timestamp = new Date().toISOString();

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'PhishNetra-SOC-AlertEngine/1.0'
    };

    if (webhook.secretKey) {
      const hmac = crypto.createHmac('sha256', webhook.secretKey);
      hmac.update(JSON.stringify(payload));
      headers['X-PhishNetra-Signature'] = `sha256=${hmac.digest('hex')}`;
    }

    try {
      // If it's a simulated or mock endpoint, mock success without sending real network packet
      if (webhook.url.includes('phishnetra.internal') || webhook.url.includes('example.com') || webhook.url.includes('mock_channel')) {
        const log: WebhookDeliveryLog = {
          id: logId,
          webhookId: webhook.id,
          webhookName: webhook.name,
          channelType: webhook.channelType,
          event,
          statusCode: 200,
          success: true,
          error: null,
          payloadSummary: `Dispatched ${event} event successfully (Simulated delivery)`,
          timestamp
        };
        this.deliveryLogs.push(log);
        webhook.lastTriggeredAt = timestamp;
        return log;
      }

      const res = await axios.post(webhook.url, payload, { headers, timeout: 5000 });
      const log: WebhookDeliveryLog = {
        id: logId,
        webhookId: webhook.id,
        webhookName: webhook.name,
        channelType: webhook.channelType,
        event,
        statusCode: res.status,
        success: res.status >= 200 && res.status < 300,
        error: null,
        payloadSummary: `Delivered ${event} to ${webhook.channelType}`,
        timestamp
      };
      this.deliveryLogs.push(log);
      webhook.lastTriggeredAt = timestamp;
      return log;
    } catch (err: any) {
      const log: WebhookDeliveryLog = {
        id: logId,
        webhookId: webhook.id,
        webhookName: webhook.name,
        channelType: webhook.channelType,
        event,
        statusCode: err.response?.status || 500,
        success: false,
        error: err.message,
        payloadSummary: `Failed to deliver ${event}: ${err.message}`,
        timestamp
      };
      this.deliveryLogs.push(log);
      return log;
    }
  }

  private formatPayloadForChannel(channel: string, event: string, analysis: AnalysisResponse): any {
    if (channel === 'SLACK') {
      return {
        text: `🚨 *PhishNetra Security Alert: ${analysis.verdict} URL Detected*`,
        blocks: [
          {
            type: 'header',
            text: { type: 'plain_text', text: `🚨 Threat Alert: ${analysis.verdict} (${analysis.riskScore}/100)` }
          },
          {
            type: 'section',
            fields: [
              { type: 'mrkdwn', text: `*Target URL:*\n\`${analysis.url}\`` },
              { type: 'mrkdwn', text: `*Risk Level:*\n*${analysis.riskLevel}*` },
              { type: 'mrkdwn', text: `*Confidence:*\n${(analysis.confidence * 100).toFixed(1)}%` },
              { type: 'mrkdwn', text: `*Domain:*\n${analysis.layers?.domain?.registrableDomain || 'N/A'}` }
            ]
          },
          {
            type: 'section',
            text: { type: 'mrkdwn', text: `*Summary:*\n${analysis.summary || 'Threat identified by multi-layer risk engine.'}` }
          }
        ]
      };
    } else if (channel === 'DISCORD') {
      return {
        content: `🚨 **PhishNetra Threat Alert**`,
        embeds: [
          {
            title: `${analysis.verdict} Target Identified (${analysis.riskScore}/100)`,
            description: analysis.summary || 'Suspicious infrastructure detected.',
            color: analysis.verdict === 'PHISHING' ? 0xff0033 : 0xffaa00,
            fields: [
              { name: 'Target URL', value: `\`${analysis.url}\``, inline: false },
              { name: 'Risk Level', value: analysis.riskLevel, inline: true },
              { name: 'Confidence', value: `${(analysis.confidence * 100).toFixed(1)}%`, inline: true }
            ],
            footer: { text: 'PhishNetra Zero-Trust Threat Mitigation' },
            timestamp: analysis.createdAt
          }
        ]
      };
    }

    return {
      event,
      timestamp: new Date().toISOString(),
      threat: {
        analysisId: analysis.analysisId,
        url: analysis.url,
        verdict: analysis.verdict,
        riskScore: analysis.riskScore,
        riskLevel: analysis.riskLevel,
        confidence: analysis.confidence,
        summary: analysis.summary,
        evidence: analysis.evidence?.map(e => (e as any).title || e.description || e.featureKey) || []
      }
    };
  }

  private formatCampaignPayload(channel: string, campaign: ThreatCampaign): any {
    return {
      event: 'CAMPAIGN_CLUSTERED',
      timestamp: new Date().toISOString(),
      campaign: {
        id: campaign.id,
        name: campaign.name,
        targetedBrands: campaign.targetedBrands,
        domainCount: campaign.domainCount,
        ipCount: campaign.ipCount,
        severityScore: campaign.severityScore,
        riskLevel: campaign.riskLevel,
        description: campaign.description
      }
    };
  }
}

export const webhookNotificationService = new WebhookNotificationService();
