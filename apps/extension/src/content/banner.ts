/**
 * PhishNetra Extension — Suspicious Warning Banner
 * 
 * Non-intrusive floating top banner for domains evaluated with SUSPICIOUS status.
 */

export interface BannerPayload {
  url: string;
  domain: string;
  compositeScore: number;
  dashboardUrl?: string;
}

const BANNER_ID = 'phishnetra-warning-banner-root';

export function showBanner(payload: BannerPayload): void {
  if (document.getElementById(BANNER_ID)) return;

  const banner = document.createElement('div');
  banner.id = BANNER_ID;
  banner.style.cssText = `
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    width: 100% !important;
    z-index: 2147483646 !important;
    background: linear-gradient(90deg, #1c1917 0%, #292524 100%) !important;
    border-bottom: 2px solid #f59e0b !important;
    color: #fef3c7 !important;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
    font-size: 13px !important;
    padding: 10px 18px !important;
    display: flex !important;
    align-items: center !important;
    justify-content: space-between !important;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.5) !important;
    box-sizing: border-box !important;
  `;

  const dashboardLink = `${payload.dashboardUrl || 'http://localhost:5173'}/analysis?url=${encodeURIComponent(payload.url)}`;

  banner.innerHTML = `
    <div style="display: flex; align-items: center; gap: 12px;">
      <span style="font-size: 16px;">⚠️</span>
      <div>
        <strong style="color: #fbbf24;">PhishNetra Security Warning:</strong>
        <span style="color: #f3f4f6; margin-left: 4px;">
          This domain exhibits suspicious threat indicators (Risk Score: <strong>${Math.round(payload.compositeScore)}/100</strong>). Do not enter passwords or financial information.
        </span>
      </div>
    </div>

    <div style="display: flex; align-items: center; gap: 10px;">
      <a href="${dashboardLink}" target="_blank" rel="noopener noreferrer" style="
        background: #f59e0b;
        color: #1c1917;
        padding: 5px 12px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 12px;
        text-decoration: none;
      ">
        Inspect SOC Dossier
      </a>
      <button id="phishnetra-banner-dismiss" style="
        background: transparent;
        border: 1px solid rgba(254, 243, 199, 0.4);
        color: #fef3c7;
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 12px;
        cursor: pointer;
      ">
        Dismiss
      </button>
    </div>
  `;

  document.documentElement.appendChild(banner);

  const dismissBtn = banner.querySelector('#phishnetra-banner-dismiss');
  if (dismissBtn) {
    dismissBtn.addEventListener('click', () => {
      hideBanner();
    });
  }
}

export function hideBanner(): void {
  const banner = document.getElementById(BANNER_ID);
  if (banner) {
    banner.remove();
  }
}
