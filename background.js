import { scoreUrl, getExplanation } from './rules/heuristics.js';

chrome.runtime.onInstalled.addListener(async () => {
  await chrome.storage.local.set({
    stats: { totalScans: 0, phishingDetected: 0, lastReset: Date.now() },
    recentScans: []
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case 'SCAN_URL':
      handleScan(message.url).then(sendResponse);
      return true;
    case 'GET_STATS':
      getStats().then(sendResponse);
      return true;
    case 'RESET_STATS':
      resetStats().then(sendResponse);
      return true;
    case 'OPEN_POPUP':
      chrome.action.openPopup();
      sendResponse({ success: true });
      return true;
  }
});

async function handleScan(url) {
  try {
    const heuristicResult = scoreUrl(url);

    const verdict = {
      url,
      timestamp: Date.now(),
      heuristicScore: heuristicResult.score,
      heuristicRiskLevel: heuristicResult.riskLevel,
      heuristicTriggers: heuristicResult.triggered,
      heuristicExplanation: getExplanation(heuristicResult),
      blocklistMatch: null,
      isPhishing: heuristicResult.isPhishing,
      confidence: calculateConfidence(heuristicResult),
      riskLevel: determineRiskLevel(heuristicResult)
    };

    await updateStats(verdict.isPhishing);
    await storeRecentScan(verdict);

    return { verdict };
  } catch (error) {
    console.error('[PhishGuard] Scan error:', error);
    return {
      verdict: {
        url,
        error: error.message,
        isPhishing: false,
        confidence: 0,
        riskLevel: 'error'
      }
    };
  }
}

function calculateConfidence(heuristic) {
  if (heuristic.score >= 50) return 0.85;
  if (heuristic.score >= 30) return 0.70;
  if (heuristic.score >= 15) return 0.40;
  return 0.10;
}

function determineRiskLevel(heuristic) {
  if (heuristic.score >= 50) return 'critical';
  if (heuristic.score >= 30) return 'high';
  if (heuristic.score >= 15) return 'medium';
  if (heuristic.score >= 5) return 'low';
  return 'safe';
}

async function updateStats(isPhishing) {
  const { stats = { totalScans: 0, phishingDetected: 0 } } = await chrome.storage.local.get('stats');
  stats.totalScans++;
  if (isPhishing) stats.phishingDetected++;
  await chrome.storage.local.set({ stats });
}

async function getStats() {
  const { stats = { totalScans: 0, phishingDetected: 0 } } = await chrome.storage.local.get('stats');
  return { ...stats, clean: stats.totalScans - stats.phishingDetected };
}

async function resetStats() {
  await chrome.storage.local.set({
    stats: { totalScans: 0, phishingDetected: 0, lastReset: Date.now() },
    recentScans: []
  });
  return { success: true };
}

async function storeRecentScan(verdict) {
  const { recentScans = [] } = await chrome.storage.local.get('recentScans');
  recentScans.unshift(verdict);
  if (recentScans.length > 50) recentScans.length = 50;
  await chrome.storage.local.set({ recentScans });
}