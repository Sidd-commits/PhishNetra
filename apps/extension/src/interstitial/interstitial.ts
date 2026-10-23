/**
 * PhishNetra Extension — Threat Mitigation Interstitial Page Logic
 */

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

document.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get('url') || window.location.href;
  const score = parseInt(params.get('score') || '90', 10);
  const dashboardUrl = (params.get('dashboardUrl') || 'http://localhost:5173').replace(/\/$/, '');
  
  let indicators: string[] = [];
  try {
    const rawIndicators = params.get('indicators');
    if (rawIndicators) {
      indicators = JSON.parse(decodeURIComponent(rawIndicators));
    }
  } catch {
    indicators = ['High-risk phishing signatures or credential theft indicators detected'];
  }

  // Notify background service worker to lock threat badge and state for this tab
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'INTERSTITIAL_PAGE_LOADED',
      url: window.location.href,
      targetUrl,
      score,
      level: params.get('level') || 'PHISHING'
    });
  }

  // 1. Update Score Badge
  const scoreBadge = document.getElementById('score-badge');
  if (scoreBadge) {
    scoreBadge.textContent = `Score: ${score}/100`;
  }

  // 2. Update Target URL
  const targetUrlEl = document.getElementById('target-url');
  if (targetUrlEl) {
    targetUrlEl.textContent = targetUrl;
  }

  // 3. Populate Indicators List
  const indicatorsList = document.getElementById('indicators-list');
  if (indicatorsList) {
    if (indicators && indicators.length > 0) {
      indicatorsList.innerHTML = indicators.map((ind) => `
        <li class="indicator-item">
          <span class="indicator-x">✕</span>
          <span>${escapeHtml(ind)}</span>
        </li>
      `).join('');
    } else {
      indicatorsList.innerHTML = `
        <li class="indicator-item">
          <span class="indicator-x">✕</span>
          <span>Deceptive domain heuristics or credential theft indicators detected</span>
        </li>
      `;
    }
  }

  // 4. Update Inspect SOC Button
  const btnInspect = document.getElementById('btn-inspect') as HTMLAnchorElement | null;
  if (btnInspect) {
    btnInspect.href = `${dashboardUrl}/analysis?url=${encodeURIComponent(targetUrl)}`;
  }

  // 5. Wire Return to Safety Button
  const btnGoBack = document.getElementById('btn-goback');
  if (btnGoBack) {
    btnGoBack.addEventListener('click', () => {
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.getCurrent) {
        chrome.tabs.getCurrent((tab) => {
          if (tab?.id) {
            chrome.tabs.remove(tab.id);
          } else if (window.history.length > 1) {
            window.history.back();
          } else {
            window.location.href = 'https://www.google.com';
          }
        });
      } else if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = 'https://www.google.com';
      }
    });
  }

  // 6. Wire Bypass Button
  const btnBypass = document.getElementById('btn-bypass');
  if (btnBypass) {
    btnBypass.addEventListener('click', () => {
      btnBypass.textContent = 'Granting bypass...';
      btnBypass.setAttribute('disabled', 'true');

      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage(
          { type: 'BYPASS_THREAT', url: targetUrl },
          () => {
            // Once session bypass is stored in background, navigate to target
            window.location.href = targetUrl;
          }
        );
      } else {
        window.location.href = targetUrl;
      }
    });
  }
});
