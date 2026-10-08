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

// Notify background worker that content script is initialized and ready
try {
  chrome.runtime.sendMessage({ type: 'CONTENT_SCRIPT_READY' });
} catch (err) {
  // Ignore in isolated frames
}
