const DEFAULT_API_BASE = "https://threatlens-backend-fzz3.onrender.com/api";
const scannedTabUrls = new Map();
const lastAlertByTab = new Map();

async function getApiBase() {
  const data = await chrome.storage.local.get(["apiBase"]);
  return (data.apiBase || DEFAULT_API_BASE).replace(/\/$/, "");
}

function isTrustedDomain(rawUrl) {
  try {
    const host = new URL(rawUrl).hostname.toLowerCase();
    const trusted = [
      "localhost",
      "127.0.0.1",
      "google.com",
      "gemini.google.com",
      "github.com",
      "wikipedia.org",
      "mozilla.org"
    ];
    return trusted.some(d => host === d || host.endsWith("." + d));
  } catch {
    return false;
  }
}

function normalizeScanResponse(raw) {
  const emailRes = raw?.email || null;
  const urlRes = raw?.url || null;

  let chosen = urlRes || emailRes || raw || {};
  if (emailRes && urlRes) {
    chosen = (emailRes.risk_score ?? 0) >= (urlRes.risk_score ?? 0) ? emailRes : urlRes;
  }

  const combinedFlags = [
    ...(urlRes?.red_flags || []),
    ...(emailRes?.red_flags || [])
  ];

  return {
    label: chosen.label || "legitimate",
    risk_score: chosen.risk_score ?? 0,
    red_flags: [...new Set(combinedFlags)]
  };
}

async function scanPayload(payload) {
  const apiBase = await getApiBase();
  const res = await fetch(`${apiBase}/scan/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      text: payload.text || "",
      url: payload.url || ""
    })
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  const raw = await res.json();
  return normalizeScanResponse(raw);
}

function updateBadgeAndNotify(tabId, result, contextLabel) {
  const label = (result.label || "legitimate").toLowerCase();
  const score = result.risk_score ?? 0;

  if (label === "phishing" || label === "suspicious") {
    const isHigh = label === "phishing";
    chrome.action.setBadgeText({ tabId, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: isHigh ? "#dc2626" : "#d97706" });

    const alertKey = `${label}:${score}:${contextLabel}`;
    if (lastAlertByTab.get(tabId) === alertKey) return;
    lastAlertByTab.set(tabId, alertKey);

    chrome.notifications.create({
      type: "basic",
      iconUrl: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII=",
      title: isHigh ? "🚨 ThreatLens: Phishing Alert!" : "⚠️ ThreatLens: Suspicious Activity",
      message: `${contextLabel} flagged as ${label.toUpperCase()} (Risk Score: ${score}/100).`,
      priority: 2
    });
  } else {
    lastAlertByTab.delete(tabId);
    chrome.action.setBadgeText({ tabId, text: "OK" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#16a34a" });
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  const saved = await chrome.storage.local.get(["apiBase"]);
  await chrome.storage.local.clear();
  if (saved.apiBase) await chrome.storage.local.set({ apiBase: saved.apiBase });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  scannedTabUrls.delete(tabId);
  lastAlertByTab.delete(tabId);
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  const currentUrl = changeInfo.url || tab.url;
  if (!currentUrl) return;
  if (!currentUrl.startsWith("http://") && !currentUrl.startsWith("https://")) return;

  const prevUrl = scannedTabUrls.get(tabId);
  if (prevUrl === currentUrl && changeInfo.status !== "complete") return;

  // If URL hasn't changed and a content threat was already found on this tab, keep it!
  const existing = await chrome.storage.local.get([`tab_${tabId}`]);
  const prevInfo = existing[`tab_${tabId}`];
  if (prevInfo && prevInfo.url === currentUrl && prevInfo.source !== "Verified Domain" && prevInfo.source !== "URL Guard") {
    return;
  }

  scannedTabUrls.set(tabId, currentUrl);

  if (isTrustedDomain(currentUrl)) {
    const safeRes = { label: "legitimate", risk_score: 0, red_flags: [] };
    await chrome.storage.local.set({ [`tab_${tabId}`]: { url: currentUrl, result: safeRes, source: "Verified Domain" } });
    updateBadgeAndNotify(tabId, safeRes, "Website URL");
    return;
  }

  try {
    const result = await scanPayload({ url: currentUrl, text: "" });
    await chrome.storage.local.set({ [`tab_${tabId}`]: { url: currentUrl, result, source: "URL Guard" } });
    updateBadgeAndNotify(tabId, result, "Website URL");

    if ((result.label || "").toLowerCase() !== "legitimate") {
      chrome.tabs.sendMessage(tabId, { type: "THREATLENS_ALERT", result, source: "Website URL" }).catch(() => {});
    }
  } catch (err) {
    console.warn("ThreatLens URL scan skipped:", err.message);
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "SCAN_CONTENT" && sender.tab?.id) {
    const tabId = sender.tab.id;
    scanPayload({ text: msg.text || "", url: msg.url || "" })
      .then(async (result) => {
        const lbl = (result.label || "legitimate").toLowerCase();
        if (lbl !== "legitimate" && lbl !== "safe") {
          await chrome.storage.local.set({ [`tab_${tabId}`]: { url: sender.tab.url, result, source: msg.source || "Page Content" } });
          updateBadgeAndNotify(tabId, result, msg.source || "Message/Email");
        }
        sendResponse({ ok: true, result });
      })
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (msg.type === "MANUAL_SCAN") {
    scanPayload({ text: msg.text || "", url: msg.url || "" })
      .then((result) => sendResponse({ ok: true, result }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }
});

// --- System Toast Notification for High-Risk / Suspicious Tabs ---
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "loading" || !tab.url || !tab.url.startsWith("http")) return;
  try {
    const host = new URL(tab.url).hostname;
    if (["google.com", "www.google.com", "github.com", "web.whatsapp.com", "phishing-detection-explainable-thre.vercel.app"].includes(host)) return;

    const stored = await chrome.storage.local.get(["apiEndpoint"]);
    const base = (stored.apiEndpoint || "https://threatlens-backend-fzz3.onrender.com/api").replace(/\/+$/, "");
    const res = await fetch(`${base}/scan/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url })
    });
    if (!res.ok) return;
    const data = await res.json();
    const score = Math.round(data.risk_score || 0);
    const label = (data.label || "legitimate").toLowerCase();

    if (label === "phishing" || label === "suspicious" || score >= 40) {
      const reasons = (data.red_flags || []).slice(0, 2).join(" • ") || "Suspicious URL indicators detected";
      chrome.notifications.create(`tl-alert-${tabId}-${Date.now()}`, {
        type: "basic",
        iconUrl: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
        title: `ThreatLens: ${label.toUpperCase()} (${score}/100)`,
        message: reasons
      });
    }
  } catch (_) {}
});
