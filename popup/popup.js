document.addEventListener('DOMContentLoaded', async () => {
  await loadCurrentTab();
  await loadStats();
  await loadRecentScans();

  document.getElementById('scanBtn').addEventListener('click', scanCurrentTab);
  document.getElementById('clearBtn').addEventListener('click', clearHistory);
});

async function loadCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return;

  const url = new URL(tab.url);
  const siteInfo = document.getElementById('siteInfo');
  siteInfo.innerHTML = `
    <div class="pg-site-avatar">${getFavicon(url.hostname)}</div>
    <div class="pg-site-details">
      <span class="pg-site-hostname">${escapeHtml(url.hostname)}</span>
      <span class="pg-site-path">${escapeHtml(url.pathname || '/')}</span>
    </div>
  `;
}

function getFavicon(hostname) {
  return `<img src="https://www.google.com/s2/favicons?domain=${encodeURIComponent(hostname)}&sz=32" alt="" width="24" height="24">`;
}

async function scanCurrentTab() {
  const btn = document.getElementById('scanBtn');
  const originalText = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="pg-btn-icon">⏳</span> Scanning...';

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const response = await chrome.runtime.sendMessage({ type: 'SCAN_URL', url: tab.url });
    showVerdict(response.verdict);
    await loadStats();
    await loadRecentScans();
  } catch (error) {
    showError(error.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalText;
  }
}

function showVerdict(verdict) {
  const container = document.getElementById('verdict');
  container.style.display = 'block';

  const isPhishing = verdict.isPhishing;
  const riskClass = `pg-verdict-${verdict.riskLevel}`;
  const icon = verdict.riskLevel === 'critical' ? '🚨' : verdict.riskLevel === 'high' ? '⚠️' : verdict.riskLevel === 'medium' ? '⚡' : '✅';
  const label = isPhishing ? 'THREAT DETECTED' : 'APPEARS SAFE';

  let detailsHtml = '';
  if (verdict.blocklistMatch) {
    detailsHtml += `<span class="pg-tag pg-tag-blocklist">🛡️ Blocklist: ${escapeHtml(verdict.blocklistMatch.threat)}</span>`;
  }
  if (verdict.heuristicTriggers?.length) {
    detailsHtml += verdict.heuristicTriggers.slice(0, 4).map(t =>
      `<span class="pg-tag">${escapeHtml(t.reason)}</span>`
    ).join('');
    if (verdict.heuristicTriggers.length > 4) {
      detailsHtml += `<span class="pg-tag pg-tag-more">+${verdict.heuristicTriggers.length - 4} more</span>`;
    }
  }

  container.innerHTML = `
    <div class="pg-verdict ${riskClass}">
      <div class="pg-verdict-header">
        <span class="pg-verdict-icon">${icon}</span>
        <div>
          <strong>${label}</strong>
          <div class="pg-verdict-meta">
            Score: ${verdict.heuristicScore}/100 • Confidence: ${Math.round(verdict.confidence * 100)}%
          </div>
        </div>
      </div>
      <div class="pg-verdict-details">${detailsHtml || '<span class="pg-tag pg-tag-safe">No suspicious indicators</span>'}</div>
      ${verdict.heuristicExplanation ? `<details class="pg-verdict-explanation"><summary>Why?</summary><pre>${escapeHtml(verdict.heuristicExplanation)}</pre></details>` : ''}
    </div>
  `;
}

function showError(message) {
  const container = document.getElementById('verdict');
  container.style.display = 'block';
  container.innerHTML = `
    <div class="pg-verdict pg-verdict-error">
      <span class="pg-verdict-icon">❌</span>
      <div><strong>Scan Failed</strong><div>${escapeHtml(message)}</div></div>
    </div>
  `;
}

async function loadStats() {
  const response = await chrome.runtime.sendMessage({ type: 'GET_STATS' });
  document.getElementById('statTotal').textContent = response.totalScans || 0;
  document.getElementById('statPhishing').textContent = response.phishingDetected || 0;
  document.getElementById('statClean').textContent = response.clean || 0;
}

async function loadRecentScans() {
  const { recentScans = [] } = await chrome.storage.local.get('recentScans');
  const container = document.getElementById('recentList');

  if (recentScans.length === 0) {
    container.innerHTML = '<div class="pg-empty">No scans yet. Click "Scan Current Page" to start.</div>';
    return;
  }

  container.innerHTML = recentScans.slice(0, 10).map(scan => {
    const time = new Date(scan.timestamp).toLocaleTimeString();
    const riskClass = `pg-recent-${scan.riskLevel}`;
    const icon = scan.isPhishing ? '🚨' : '✅';
    return `
      <div class="pg-recent-item ${riskClass}">
        <span class="pg-recent-icon">${icon}</span>
        <div class="pg-recent-info">
          <span class="pg-recent-hostname">${escapeHtml(new URL(scan.url).hostname)}</span>
          <span class="pg-recent-time">${time} • Score: ${scan.heuristicScore}</span>
        </div>
        <span class="pg-recent-risk">${scan.riskLevel.toUpperCase()}</span>
      </div>
    `;
  }).join('');
}

async function clearHistory() {
  if (!confirm('Clear all scan history and stats?')) return;
  await chrome.runtime.sendMessage({ type: 'RESET_STATS' });
  await loadStats();
  await loadRecentScans();
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}