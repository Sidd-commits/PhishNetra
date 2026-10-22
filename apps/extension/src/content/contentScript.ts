/**
 * PhishNetra Extension — Content Script
 * 
 * Injected into matching web pages to manage security overlays (interstitial, banner).
 */

import { showInterstitial, hideInterstitial, InterstitialPayload } from './interstitial';
import { showBanner, hideBanner, BannerPayload } from './banner';

// Listen for threat signals from background service worker
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'SHOW_INTERSTITIAL') {
    hideBanner();
    showInterstitial(message.payload as InterstitialPayload);
    sendResponse({ received: true });
  } else if (message.type === 'SHOW_BANNER') {
    hideInterstitial();
    showBanner(message.payload as BannerPayload);
    sendResponse({ received: true });
  } else if (message.type === 'HIDE_OVERLAYS') {
    hideInterstitial();
    hideBanner();
    sendResponse({ received: true });
  }
});

// Proactively check current page threat status from background worker on load
function checkCurrentPageThreat(): void {
  try {
    const currentUrl = window.location.href;
    if (!currentUrl || !currentUrl.startsWith('http')) return;

    chrome.runtime.sendMessage(
      { type: 'CHECK_PAGE_THREAT', url: currentUrl },
      (response: any) => {
        if (chrome.runtime.lastError || !response) return;
        if (response.action === 'SHOW_INTERSTITIAL' && response.payload) {
          hideBanner();
          showInterstitial(response.payload as InterstitialPayload);
        } else if (response.action === 'SHOW_BANNER' && response.payload) {
          hideInterstitial();
          showBanner(response.payload as BannerPayload);
        } else if (response.action === 'HIDE_OVERLAYS') {
          hideInterstitial();
          hideBanner();
        }
      }
    );
  } catch (err) {
    // Ignore in isolated or restricted contexts
  }
}

// Notify background worker and run proactive check
checkCurrentPageThreat();
