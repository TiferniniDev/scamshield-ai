/**
 * ScamShield AI - Manifest V3 Service Worker
 * Bridges HTTPS Google Search / Maps content scripts to the local ScamShield AI API.
 * Privacy-by-Design: Only sends external link domains (never user search queries).
 */
const API_BASE = "http://127.0.0.1:8000";

async function analyzeWithBackend(url, source, deepScan, saveToDb) {
  try {
    const resp = await fetch(`${API_BASE}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        source,
        source_label: `Browser Pre-Click Guard (${source})`,
        deep_scan: deepScan,
        save_to_db: saveToDb,
      }),
    });
    if (!resp.ok) {
      return { error: `HTTP ${resp.status}` };
    }
    return await resp.json();
  } catch (err) {
    return { error: "ScamShield backend offline (start ./run.sh on port 8000)" };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "ANALYZE_LINK") {
    (async () => {
      const { url, source = "patrol_search", deepScan = false } = message;
      const cacheKey = `cache:${url}`;
      const cached = await chrome.storage.session.get(cacheKey);
      if (cached[cacheKey] && !deepScan) {
        sendResponse(cached[cacheKey]);
        return;
      }
      // Fast local ML check (<15ms); only save if flagged as FRAUD
      const result = await analyzeWithBackend(url, source, deepScan, false);
      if (!result.error) {
        await chrome.storage.session.set({ [cacheKey]: result });
        if (result.verdict === "FRAUD") {
          // Report newly spotted browser fraud to Command Center automatically
          await analyzeWithBackend(url, source, false, true);
        }
      }
      sendResponse(result);
    })();
    return true;
  }

  if (message?.type === "DEEP_SCAN_TAB") {
    (async () => {
      const result = await analyzeWithBackend(message.url, "manual_scan", true, true);
      sendResponse(result);
    })();
    return true;
  }
});

