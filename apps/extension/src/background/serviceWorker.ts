/**
 * PhishNetra Extension — Background Service Worker (Manifest V3)
 * 
 * Orchestrates real-time tab interception, local heuristics pre-filtering,
 * backend multi-tier pipeline dispatch, client-side caching, and threat overlays.
 */

import { StorageService } from '../utils/storage';
import { evaluateLocalHeuristics, LocalHeuristicResult } from './localHeuristics';
import { BadgeManager } from './badgeManager';
import { AnalysisResponse, ThreatVerdict } from '@phishnetra/shared';

// In-memory tab state tracking for active inspection
interface TabInspectionState {
  url: string;
  domain: string;
  localHeuristics: LocalHeuristicResult;
  analysis: AnalysisResponse | null;
  status: ThreatVerdict | 'PENDING' | 'WHITELISTED' | 'BYPASSED';
  error?: string;
  analyzedAt: number;
}

const tabStateMap = new Map<number, TabInspectionState>();

/**
 * Validates whether a URL should be analyzed
 */
function shouldAnalyzeUrl(urlStr: string): boolean {
  if (!urlStr) return false;
  try {
    const url = new URL(urlStr);
    // Ignore internal browser schemes and developer dashboards
    if (['chrome:', 'chrome-extension:', 'edge:', 'about:', 'devtools:', 'view-source:'].includes(url.protocol)) {
      return false;
    }
    // Ignore PhishNetra console itself
    if (url.hostname === 'localhost' && ['5173', '5000'].includes(url.port)) {
      return false;
    }
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

const inFlightAnalysisMap = new Map<number, Promise<void>>();

/**
 * Dispatches analysis for a given tab
 */
async function processTabAnalysis(tabId: number, url: string, forceRefresh = false): Promise<void> {
  const run = async () => {
    if (!shouldAnalyzeUrl(url)) {
      BadgeManager.clearBadge(tabId);
      tabStateMap.delete(tabId);
      return;
    }

    const parsedUrl = new URL(url);
    const domain = parsedUrl.hostname;

    // 1. Check Whitelist
    const isWhitelisted = await StorageService.isWhitelisted(domain);
    if (isWhitelisted) {
      tabStateMap.set(tabId, {
        url,
        domain,
        localHeuristics: evaluateLocalHeuristics(url),
        analysis: null,
        status: 'WHITELISTED',
        analyzedAt: Date.now()
      });
      await BadgeManager.setWhitelisted(tabId);
      sendMessageToTab(tabId, { type: 'HIDE_OVERLAYS' });
      return;
    }

    // 2. Check Session Bypass
    const isBypassed = await StorageService.hasTemporaryBypass(url);
    if (isBypassed) {
      await BadgeManager.setBypassed(tabId);
      sendMessageToTab(tabId, { type: 'HIDE_OVERLAYS' });
      return;
    }

    const settings = await StorageService.getSettings();

    // 3. Fast Local Heuristic Pre-Evaluation
    const localHeuristics = evaluateLocalHeuristics(url);
    if (localHeuristics.isLikelyPhishing) {
      await BadgeManager.setRiskStatus(localHeuristics.score, 'PHISHING', tabId);
      const isBypassedNow = await StorageService.hasTemporaryBypass(url);
      if (!isBypassedNow) {
        await triggerThreatInterstitial(
          tabId,
          url,
          domain,
          localHeuristics.score,
          'PHISHING',
          localHeuristics.reasons,
          0.85,
          settings.dashboardUrl
        );
      }
    } else {
      await BadgeManager.setScanning(tabId);
    }

    tabStateMap.set(tabId, {
      url,
      domain,
      localHeuristics,
      analysis: null,
      status: 'PENDING',
      analyzedAt: Date.now()
    });

    try {
      let analysis: AnalysisResponse | null = null;

      // 4. Check Client-Side Cache if not force refreshed
      if (!forceRefresh) {
        analysis = await StorageService.getCachedAnalysis(url);
      }

      // 5. Backend Pipeline Query if not in cache
      if (!analysis) {
        const response = await fetch(`${settings.apiUrl}/analyze`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ url })
        });

        if (!response.ok) {
          throw new Error(`PhishNetra API error: ${response.status} ${response.statusText}`);
        }

        analysis = await response.json();
        if (analysis) {
          await StorageService.setCachedAnalysis(url, analysis);
        }
      }

      if (!analysis) {
        throw new Error('No analysis data received from engine');
      }

      const riskScore = analysis.riskScore ?? 0;
      const verdict = analysis.verdict || 'SAFE';

      tabStateMap.set(tabId, {
        url,
        domain,
        localHeuristics,
        analysis,
        status: verdict,
        analyzedAt: Date.now()
      });

      // 6. Update Extension Action Badge
      await BadgeManager.setRiskStatus(riskScore, verdict, tabId);

      // 7. Trigger In-Page Threat Mitigations (Zero Silent Redirects Policy)
      const isCritical = verdict === 'PHISHING' || riskScore >= settings.blockThreshold;
      const isSuspicious = verdict === 'SUSPICIOUS' || (riskScore >= 35 && !isCritical);

      if (isCritical) {
        const bypassed = await StorageService.hasTemporaryBypass(url);
        if (!bypassed) {
          const evidenceDescriptions = analysis.evidence?.map((e) => e.description) || localHeuristics.reasons;
          await triggerThreatInterstitial(
            tabId,
            url,
            domain,
            riskScore,
            verdict,
            evidenceDescriptions,
            analysis.confidence ?? 0.85,
            settings.dashboardUrl
          );
        }
      } else if (isSuspicious) {
        const bypassed = await StorageService.hasTemporaryBypass(url);
        if (!bypassed) {
          sendMessageToTab(tabId, {
            type: 'SHOW_BANNER',
            payload: {
              url,
              domain,
              compositeScore: riskScore,
              dashboardUrl: settings.dashboardUrl
            }
          });
        }
      } else {
        sendMessageToTab(tabId, { type: 'HIDE_OVERLAYS' });
      }

    } catch (err: any) {
      console.error('[PhishNetra Background] Analysis error:', err);
      tabStateMap.set(tabId, {
        url,
        domain,
        localHeuristics,
        analysis: null,
        status: localHeuristics.isLikelyPhishing ? 'PHISHING' : 'SAFE',
        error: err.message || 'API connection failed',
        analyzedAt: Date.now()
      });

      // Fall back to local heuristic status if backend is unreachable
      if (localHeuristics.isLikelyPhishing) {
        await BadgeManager.setRiskStatus(localHeuristics.score, 'PHISHING', tabId);
        const bypassed = await StorageService.hasTemporaryBypass(url);
        if (!bypassed) {
          await triggerThreatInterstitial(
            tabId,
            url,
            domain,
            localHeuristics.score,
            'PHISHING',
            localHeuristics.reasons,
            0.85,
            settings.dashboardUrl
          );
        }
      } else if (localHeuristics.isSuspicious) {
        await BadgeManager.setRiskStatus(localHeuristics.score, 'SUSPICIOUS', tabId);
      } else {
        await BadgeManager.setRiskStatus(10, 'SAFE', tabId);
      }
    }
  };

  const promise = run();
  inFlightAnalysisMap.set(tabId, promise);
  try {
    await promise;
  } finally {
    if (inFlightAnalysisMap.get(tabId) === promise) {
      inFlightAnalysisMap.delete(tabId);
    }
  }
}

/**
 * Triggers Threat Mitigation Interstitial Overlay.
 * Tries in-DOM messaging first; if content script is unavailable (e.g. DNS NXDOMAIN, error page),
 * navigates tab to the extension's dedicated interstitial threat barrier.
 */
async function triggerThreatInterstitial(
  tabId: number,
  url: string,
  domain: string,
  score: number,
  verdict: string,
  evidenceDescriptions: string[],
  aiConfidence: number,
  dashboardUrl: string
): Promise<void> {
  const payload = {
    url,
    domain,
    compositeScore: score,
    riskLevel: verdict,
    criticalIndicators: evidenceDescriptions,
    aiConfidence,
    dashboardUrl
  };

  const interstitialUrl = chrome.runtime.getURL(
    `src/interstitial/interstitial.html?url=${encodeURIComponent(url)}&domain=${encodeURIComponent(domain)}&score=${Math.round(score)}&level=${encodeURIComponent(verdict)}&confidence=${aiConfidence}&indicators=${encodeURIComponent(JSON.stringify(evidenceDescriptions))}&dashboardUrl=${encodeURIComponent(dashboardUrl)}`
  );

  let deliveredInDom = false;
  if (typeof chrome !== 'undefined' && chrome.tabs) {
    try {
      await new Promise<void>((resolve) => {
        chrome.tabs.sendMessage(tabId, { type: 'SHOW_INTERSTITIAL', payload }, () => {
          if (!chrome.runtime.lastError) {
            deliveredInDom = true;
          }
          resolve();
        });
      });
    } catch {
      // In-DOM script not yet ready or tab is on error page
    }

    if (!deliveredInDom) {
      try {
        const tab = await chrome.tabs.get(tabId);
        if (tab && tab.url && !tab.url.includes('interstitial.html')) {
          await chrome.tabs.update(tabId, { url: interstitialUrl });
        }
      } catch {
        // Tab may have closed
      }
    }
  }
}

/**
 * Safely sends message to content script
 */
function sendMessageToTab(tabId: number, message: any) {
  if (typeof chrome === 'undefined' || !chrome.tabs) return;
  chrome.tabs.sendMessage(tabId, message, () => {
    // Ignore errors when tab/content script is not yet injected or active
    if (chrome.runtime.lastError) {
      // Content script may not be loaded yet; it will query status on ready
    }
  });
}

// Tab navigation listener
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url) {
    processTabAnalysis(tabId, tab.url);
  }
});

// Tab switch listener
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url) {
      const existing = tabStateMap.get(activeInfo.tabId);
      if (!existing || existing.url !== tab.url) {
        processTabAnalysis(activeInfo.tabId, tab.url);
      }
    }
  } catch (err) {
    // Tab might have closed
  }
});

// Message listener from popup, options, and content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id || message.tabId;

  if (message.type === 'GET_CURRENT_TAB_STATUS') {
    (async () => {
      let targetTabId = tabId;
      let targetUrl = message.url;

      if (!targetTabId) {
        const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (activeTab) {
          targetTabId = activeTab.id;
          targetUrl = activeTab.url;
        }
      }

      if (!targetTabId || !targetUrl) {
        sendResponse({ success: false, error: 'No active tab detected' });
        return;
      }

      let state = tabStateMap.get(targetTabId);
      if (!state || state.url !== targetUrl) {
        // Trigger fresh analysis if state missing
        await processTabAnalysis(targetTabId, targetUrl);
        state = tabStateMap.get(targetTabId);
      }

      const isWhitelisted = await StorageService.isWhitelisted(new URL(targetUrl).hostname);
      const isBypassed = await StorageService.hasTemporaryBypass(targetUrl);

      sendResponse({
        success: true,
        state,
        isWhitelisted,
        isBypassed,
        url: targetUrl
      });
    })();
    return true; // Keep message channel open for async response
  }

  if (message.type === 'RESCAN_URL') {
    (async () => {
      const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (activeTab && activeTab.id && activeTab.url) {
        await processTabAnalysis(activeTab.id, activeTab.url, true);
        sendResponse({ success: true });
      } else {
        sendResponse({ success: false, error: 'Cannot rescan current tab' });
      }
    })();
    return true;
  }

  if (message.type === 'BYPASS_THREAT') {
    (async () => {
      const url = message.url;
      if (url) {
        await StorageService.setTemporaryBypass(url);
        if (tabId) {
          await BadgeManager.setBypassed(tabId);
          sendMessageToTab(tabId, { type: 'HIDE_OVERLAYS' });
        }
        sendResponse({ success: true });
      }
    })();
    return true;
  }

  if (message.type === 'WHITELIST_DOMAIN') {
    (async () => {
      const domain = message.domain;
      if (domain) {
        await StorageService.addToWhitelist(domain);
        if (tabId) {
          await BadgeManager.setWhitelisted(tabId);
          sendMessageToTab(tabId, { type: 'HIDE_OVERLAYS' });
        }
        sendResponse({ success: true });
      }
    })();
    return true;
  }

  if (message.type === 'REPORT_THREAT') {
    (async () => {
      try {
        const settings = await StorageService.getSettings();
        const res = await fetch(`${settings.apiUrl}/reports`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url: message.targetUrl,
            reportType: message.category || 'PHISHING',
            description: message.description || 'Reported via PhishNetra Chrome Extension',
            evidenceDetails: JSON.stringify(message.evidence || {})
          })
        });
        const result = await res.json();
        sendResponse({ success: true, result });
      } catch (err: any) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }

  if (message.type === 'CHECK_PAGE_THREAT' || message.type === 'CONTENT_SCRIPT_READY') {
    (async () => {
      const targetUrl = message.url || sender.tab?.url;
      const targetTabId = tabId || sender.tab?.id;
      if (!targetUrl || !targetTabId || !shouldAnalyzeUrl(targetUrl)) {
        sendResponse({ action: 'NONE' });
        return;
      }

      // If an analysis is currently running in background for this tab, await it
      const inFlight = inFlightAnalysisMap.get(targetTabId);
      if (inFlight) {
        await inFlight;
      }

      let state = tabStateMap.get(targetTabId);
      if (!state || state.url !== targetUrl || state.status === 'PENDING') {
        await processTabAnalysis(targetTabId, targetUrl);
        state = tabStateMap.get(targetTabId);
      }

      if (state) {
        const settings = await StorageService.getSettings();
        // Authoritative score: use backend analysis riskScore if available, else local heuristics
        const score = state.analysis !== null
          ? (state.analysis.riskScore ?? 0)
          : (state.localHeuristics?.score ?? 0);
        const verdict = state.analysis?.verdict ?? (state.localHeuristics?.isLikelyPhishing ? 'PHISHING' : state.localHeuristics?.isSuspicious ? 'SUSPICIOUS' : 'SAFE');
        const isCritical = verdict === 'PHISHING' || score >= settings.blockThreshold;
        const isSuspicious = verdict === 'SUSPICIOUS' || (score >= 35 && !isCritical);
        const bypassed = await StorageService.hasTemporaryBypass(targetUrl);
        const isWhitelisted = await StorageService.isWhitelisted(state.domain);

        const aiConfidence = state.analysis?.confidence ?? 0.85;

        if (!bypassed && !isWhitelisted && isCritical) {
          const evidenceDescriptions = state.analysis?.evidence?.map((e: any) => e.description) || state.localHeuristics?.reasons || [];
          sendResponse({
            action: 'SHOW_INTERSTITIAL',
            payload: {
              url: targetUrl,
              domain: state.domain,
              compositeScore: score,
              riskLevel: verdict,
              criticalIndicators: evidenceDescriptions,
              aiConfidence,
              dashboardUrl: settings.dashboardUrl
            }
          });
          return;
        } else if (!bypassed && !isWhitelisted && isSuspicious) {
          sendResponse({
            action: 'SHOW_BANNER',
            payload: {
              url: targetUrl,
              domain: state.domain,
              compositeScore: score,
              dashboardUrl: settings.dashboardUrl
            }
          });
          return;
        }
      }

      sendResponse({ action: 'NONE' });
    })();
    return true;
  }
});
