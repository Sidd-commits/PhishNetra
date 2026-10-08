/**
 * PhishNetra Extension — Badge Manager
 * 
 * Dynamically updates Chrome Action icon badge and tooltip
 * based on real-time threat analysis and risk level.
 */

export type BadgeState = 'SCANNING' | 'SAFE' | 'SUSPICIOUS' | 'PHISHING' | 'WHITELISTED' | 'BYPASSED' | 'CLEAR';

export class BadgeManager {
  /**
   * Sets badge to scanning state
   */
  public static async setScanning(tabId?: number): Promise<void> {
    if (typeof chrome === 'undefined' || !chrome.action) return;

    await chrome.action.setBadgeText({ text: '•••', tabId });
    await chrome.action.setBadgeBackgroundColor({ color: '#3b82f6', tabId }); // Blue
    await chrome.action.setTitle({
      title: 'PhishNetra: Analyzing page security and threat indicators...',
      tabId
    });
  }

  /**
   * Sets badge based on risk score and classification
   */
  public static async setRiskStatus(
    score: number,
    verdictOrLevel: 'SAFE' | 'SUSPICIOUS' | 'PHISHING' | 'UNKNOWN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    tabId?: number
  ): Promise<void> {
    if (typeof chrome === 'undefined' || !chrome.action) return;

    let badgeText = `${Math.round(score)}`;
    let badgeColor = '#10b981'; // Green
    let title = `PhishNetra: Page Safe (Threat Score: ${Math.round(score)}/100)`;

    const isPhishing = verdictOrLevel === 'PHISHING' || verdictOrLevel === 'CRITICAL' || score >= 75;
    const isSuspicious = verdictOrLevel === 'SUSPICIOUS' || verdictOrLevel === 'HIGH' || verdictOrLevel === 'MEDIUM' || score >= 40;

    if (isPhishing) {
      badgeText = score >= 90 ? '90+' : `${Math.round(score)}`;
      badgeColor = '#ef4444'; // Red
      title = `⚠️ PhishNetra Alert: Phishing Threat Detected! (Risk Score: ${Math.round(score)}/100)`;
    } else if (isSuspicious) {
      badgeColor = '#f59e0b'; // Amber
      title = `⚠️ PhishNetra: Suspicious Site Detected (Risk Score: ${Math.round(score)}/100)`;
    }

    await chrome.action.setBadgeText({ text: badgeText, tabId });
    await chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });
    await chrome.action.setTitle({ title, tabId });
  }

  /**
   * Sets badge to whitelisted state
   */
  public static async setWhitelisted(tabId?: number): Promise<void> {
    if (typeof chrome === 'undefined' || !chrome.action) return;

    await chrome.action.setBadgeText({ text: 'OK', tabId });
    await chrome.action.setBadgeBackgroundColor({ color: '#059669', tabId }); // Emerald
    await chrome.action.setTitle({
      title: 'PhishNetra: Domain is trusted and whitelisted',
      tabId
    });
  }

  /**
   * Sets badge to bypassed state
   */
  public static async setBypassed(tabId?: number): Promise<void> {
    if (typeof chrome === 'undefined' || !chrome.action) return;

    await chrome.action.setBadgeText({ text: 'IGN', tabId });
    await chrome.action.setBadgeBackgroundColor({ color: '#6b7280', tabId }); // Gray
    await chrome.action.setTitle({
      title: 'PhishNetra: Threat warning bypassed by user for this session',
      tabId
    });
  }

  /**
   * Clears badge (for internal pages, chrome://, etc.)
   */
  public static async clearBadge(tabId?: number): Promise<void> {
    if (typeof chrome === 'undefined' || !chrome.action) return;

    await chrome.action.setBadgeText({ text: '', tabId });
    await chrome.action.setTitle({
      title: 'PhishNetra: Real-Time Threat Mitigation Active',
      tabId
    });
  }
}
