/**
 * PhishNetra Extension — Threat Mitigation Interstitial Overlay
 * 
 * Implements strict Zero Silent Redirects policy:
 * Renders an un-bypassable DOM security barrier neutralizing dangerous page interactions
 * while presenting the security analyst/user with 3 autonomous choices:
 *  1. Return to Safety (Go Back / Close)
 *  2. Inspect SOC Evidence (Deep link to Web Console)
 *  3. Bypass & Continue Anyway (Session bypass)
 */

export interface InterstitialPayload {
  url: string;
  domain: string;
  compositeScore: number;
  riskLevel: string;
  riskBreakdown?: Record<string, number>;
  criticalIndicators?: string[];
  aiConfidence?: number;
  dashboardUrl?: string;
}

const OVERLAY_ID = 'phishnetra-security-interstitial-root';

export function showInterstitial(payload: InterstitialPayload): void {
  // Prevent duplicate insertion
  if (document.getElementById(OVERLAY_ID)) {
    return;
  }

  // Freeze host page scrolling
  document.documentElement.style.overflow = 'hidden';
  if (document.body) {
    document.body.style.overflow = 'hidden';
  }

  const container = document.createElement('div');
  container.id = OVERLAY_ID;
  container.style.cssText = `
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    width: 100vw !important;
    height: 100vh !important;
    z-index: 2147483647 !important;
    background: radial-gradient(circle at 50% 20%, #1e1014 0%, #0a0a0f 80%) !important;
    color: #f3f4f6 !important;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    padding: 24px !important;
    box-sizing: border-box !important;
    overflow-y: auto !important;
  `;

  const dashboardLink = `${payload.dashboardUrl || 'http://localhost:5173'}/analysis?url=${encodeURIComponent(payload.url)}`;

  const indicatorsListHtml = (payload.criticalIndicators || [])
    .slice(0, 4)
    .map(ind => `<li style="margin-bottom: 6px; display: flex; align-items: flex-start; gap: 8px;">
      <span style="color: #ef4444; font-weight: bold;">✕</span>
      <span style="color: #d1d5db; font-size: 13px;">${escapeHtml(ind)}</span>
    </li>`)
    .join('');

  container.innerHTML = `
    <div style="
      background: rgba(17, 24, 39, 0.95);
      border: 1px solid rgba(239, 68, 68, 0.4);
      box-shadow: 0 0 50px rgba(239, 68, 68, 0.25), inset 0 0 20px rgba(239, 68, 68, 0.1);
      border-radius: 16px;
      max-width: 680px;
      width: 100%;
      padding: 36px;
      box-sizing: border-box;
      backdrop-filter: blur(12px);
      text-align: left;
    ">
      <!-- Top Banner Header -->
      <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid rgba(239, 68, 68, 0.2); padding-bottom: 18px; margin-bottom: 24px;">
        <div style="display: flex; align-items: center; gap: 14px;">
          <div style="
            width: 48px;
            height: 48px;
            border-radius: 12px;
            background: linear-gradient(135deg, rgba(239,68,68,0.2) 0%, rgba(220,38,38,0.4) 100%);
            border: 1px solid #ef4444;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
          ">
            🛡️
          </div>
          <div>
            <div style="font-size: 11px; font-weight: 700; letter-spacing: 0.1em; color: #ef4444; text-transform: uppercase;">
              Zero-Trust Threat Mitigation
            </div>
            <h1 style="margin: 0; font-size: 22px; font-weight: 800; color: #ffffff; letter-spacing: -0.02em;">
              Phishing Threat Intercepted
            </h1>
          </div>
        </div>

        <div style="
          background: rgba(239, 68, 68, 0.15);
          border: 1px solid #ef4444;
          color: #fca5a5;
          padding: 6px 14px;
          border-radius: 9999px;
          font-weight: 800;
          font-size: 14px;
        ">
          Score: ${Math.round(payload.compositeScore)}/100
        </div>
      </div>

      <!-- Domain Warning Box -->
      <div style="
        background: rgba(31, 41, 55, 0.6);
        border: 1px solid rgba(75, 85, 99, 0.4);
        border-radius: 10px;
        padding: 14px 18px;
        margin-bottom: 20px;
        word-break: break-all;
      ">
        <div style="font-size: 12px; color: #9ca3af; margin-bottom: 4px;">Target URL</div>
        <div style="font-family: monospace; font-size: 14px; color: #f87171; font-weight: 600;">
          ${escapeHtml(payload.url)}
        </div>
      </div>

      <!-- Threat Rationale -->
      <p style="font-size: 14px; line-height: 1.6; color: #e5e7eb; margin-bottom: 20px;">
        PhishNetra real-time threat intelligence has intercepted navigation to this domain. Multi-layer inspection detected credential theft signatures, brand spoofing, or deceptive domain artifacts.
      </p>

      ${indicatorsListHtml ? `
        <div style="margin-bottom: 24px; background: rgba(0,0,0,0.3); padding: 14px; border-radius: 8px;">
          <div style="font-size: 12px; font-weight: 700; color: #9ca3af; text-transform: uppercase; margin-bottom: 8px;">
            Key Threat Indicators Detected
          </div>
          <ul style="list-style: none; padding: 0; margin: 0;">
            ${indicatorsListHtml}
          </ul>
        </div>
      ` : ''}

      <!-- Action Buttons Grid -->
      <div style="display: flex; flex-direction: column; gap: 12px; margin-top: 28px;">
        <button id="phishnetra-btn-goback" style="
          background: #ef4444;
          color: #ffffff;
          border: none;
          border-radius: 8px;
          padding: 14px 20px;
          font-size: 15px;
          font-weight: 700;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 10px;
          box-shadow: 0 4px 14px rgba(239, 68, 68, 0.4);
          transition: background 0.2s;
        ">
          <span>←</span> Return to Safety (Recommended)
        </button>

        <div style="display: flex; gap: 12px;">
          <a id="phishnetra-btn-inspect" href="${dashboardLink}" target="_blank" rel="noopener noreferrer" style="
            flex: 1;
            background: rgba(59, 130, 246, 0.15);
            border: 1px solid #3b82f6;
            color: #93c5fd;
            border-radius: 8px;
            padding: 12px 16px;
            font-size: 13px;
            font-weight: 600;
            text-align: center;
            text-decoration: none;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
          ">
            <span>🔬</span> Inspect SOC Evidence
          </a>

          <button id="phishnetra-btn-bypass" style="
            background: transparent;
            border: 1px solid rgba(156, 163, 175, 0.3);
            color: #9ca3af;
            border-radius: 8px;
            padding: 12px 16px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: color 0.2s;
          ">
            I Understand Risks (Continue)
          </button>
        </div>
      </div>
    </div>
  `;

  document.documentElement.appendChild(container);

  // Button Listeners
  const goBackBtn = container.querySelector('#phishnetra-btn-goback');
  if (goBackBtn) {
    goBackBtn.addEventListener('click', () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = 'https://www.google.com';
      }
    });
  }

  const bypassBtn = container.querySelector('#phishnetra-btn-bypass');
  if (bypassBtn) {
    bypassBtn.addEventListener('click', () => {
      if (typeof chrome !== 'undefined' && chrome.runtime) {
        chrome.runtime.sendMessage({
          type: 'BYPASS_THREAT',
          url: payload.url
        }, () => {
          hideInterstitial();
        });
      } else {
        hideInterstitial();
      }
    });
  }
}

export function hideInterstitial(): void {
  const overlay = document.getElementById(OVERLAY_ID);
  if (overlay) {
    overlay.remove();
  }
  document.documentElement.style.overflow = '';
  if (document.body) {
    document.body.style.overflow = '';
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
