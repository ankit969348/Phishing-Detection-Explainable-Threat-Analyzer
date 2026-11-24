const scanCache = new Map();

function instantLocalCheck(urlStr) {
  try {
    const u = new URL(urlStr);
    const reasons = [];
    let score = 0;
    if (u.protocol === "http:") { score += 35; reasons.push("Unencrypted HTTP connection (No HTTPS)"); }
    if ([".xyz", ".top", ".info", ".club", ".online", ".site", ".tk", ".ml"].some(t => u.hostname.endsWith(t))) {
      score += 35; reasons.push("High-risk / untrusted domain extension");
    }
    const hits = ["login", "verify", "secure", "update", "bank", "account", "kyc", "wallet", "reward"].filter(k => urlStr.toLowerCase().includes(k));
    if (hits.length >= 2) { score += 30; reasons.push("Phishing keywords: " + hits.slice(0, 3).join(", ")); }
    else if (hits.length === 1) { score += 15; reasons.push("Sensitive keyword: " + hits[0]); }
    const label = score >= 70 ? "phishing" : score >= 40 ? "suspicious" : "legitimate";
    return { score: Math.min(score, 99), label, reasons };
  } catch {
    return { score: 0, label: "legitimate", reasons: [] };
  }
}

function scanUrlViaBackground(urlStr) {
  if (!urlStr || !urlStr.startsWith("http")) return Promise.resolve(null);
  if (scanCache.has(urlStr)) return Promise.resolve(scanCache.get(urlStr));

  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ type: "THREATLENS_SCAN_URL", url: urlStr }, (res) => {
        if (chrome.runtime.lastError || !res) { resolve(null); return; }
        scanCache.set(urlStr, res);
        resolve(res);
      });
    } catch { resolve(null); }
  });
}

function isRisky(res) {
  return res && (res.label === "phishing" || res.label === "suspicious" || res.score >= 40);
}

(async function checkOpenedPage() {
  const currentUrl = window.location.href;
  if (!currentUrl.startsWith("http")) return;
  const local = instantLocalCheck(currentUrl);
  if (isRisky(local)) showWarningOverlay(currentUrl, local, true);
  const res = await scanUrlViaBackground(currentUrl);
  if (isRisky(res)) showWarningOverlay(currentUrl, res, true);
})();

let hoverCard = null;
let currentHoveredAnchor = null;

function ensureHoverCard() {
  if (!hoverCard || !document.documentElement.contains(hoverCard)) {
    hoverCard = document.createElement("div");
    hoverCard.style.cssText = "position:fixed;z-index:2147483647;pointer-events:none;max-width:300px;background:#0f172a;color:#f8fafc;padding:10px 12px;border-radius:10px;font-family:system-ui,sans-serif;box-shadow:0 12px 28px rgba(0,0,0,0.75);display:none;";
    document.documentElement.appendChild(hoverCard);
  }
  return hoverCard;
}

function showRiskHoverCard(x, y, result) {
  const card = ensureHoverCard();
  const isHigh = result.label === "phishing" || result.score >= 70;
  const accent = isHigh ? "#ef4444" : "#f59e0b";
  const reasonsHtml = result.reasons.length
    ? `<ul style="margin:6px 0 0;padding-left:15px;font-size:11px;color:#cbd5e1;line-height:1.4;">${result.reasons.map(r => `<li>${r}</li>`).join("")}</ul>`
    : `<div style="margin-top:4px;font-size:11px;color:#cbd5e1;">Suspicious URL indicators detected</div>`;

  card.style.border = `2px solid ${accent}`;
  card.style.left = Math.min(x + 14, window.innerWidth - 320) + "px";
  card.style.top = Math.max(10, Math.min(y - 85, window.innerHeight - 130)) + "px";
  card.style.display = "block";
  card.innerHTML = `
    <div style="font-size:11px;font-weight:800;color:${accent};">⚠️ THREATLENS ${result.label.toUpperCase()} · ${result.score}/100</div>
    ${reasonsHtml}
  `;
}

function hideHoverCard() {
  if (hoverCard) hoverCard.style.display = "none";
}

document.addEventListener("mousemove", async (e) => {
  const anchor = e.target && e.target.closest ? e.target.closest("a[href]") : null;
  if (!anchor || !anchor.href || !anchor.href.startsWith("http")) {
    currentHoveredAnchor = null;
    hideHoverCard();
    return;
  }

  const url = anchor.href;
  try {
    if (new URL(url).hostname === window.location.hostname) {
      hideHoverCard();
      return;
    }
  } catch { return; }

  currentHoveredAnchor = anchor;
  anchor.removeAttribute("title");

  const immediate = scanCache.get(url) || instantLocalCheck(url);
  if (isRisky(immediate)) {
    showRiskHoverCard(e.clientX, e.clientY, immediate);
  } else {
    hideHoverCard();
  }

  if (!scanCache.has(url)) {
    const live = await scanUrlViaBackground(url);
    if (currentHoveredAnchor === anchor && isRisky(live)) {
      showRiskHoverCard(e.clientX, e.clientY, live);
    }
  }
}, true);

document.addEventListener("click", (e) => {
  const anchor = e.target && e.target.closest ? e.target.closest("a[href]") : null;
  if (!anchor || !anchor.href || !anchor.href.startsWith("http")) return;
  if (e.ctrlKey || e.metaKey || e.shiftKey) return;
  const url = anchor.href;
  try { if (new URL(url).hostname === window.location.hostname) return; } catch { return; }

  const check = scanCache.get(url) || instantLocalCheck(url);
  if (isRisky(check)) {
    e.preventDefault();
    e.stopImmediatePropagation();
    hideHoverCard();
    showWarningOverlay(url, check, false);
  }
}, true);

function showWarningOverlay(targetUrl, result, isFullPage) {
  const existing = document.getElementById("tl-guard-banner");
  if (existing) existing.remove();

  const isHigh = result.label === "phishing" || result.score >= 70;
  const bg = isHigh ? "rgba(69, 10, 10, 0.97)" : "rgba(69, 26, 3, 0.97)";
  const accent = isHigh ? "#ef4444" : "#f59e0b";
  const reasonsList = result.reasons.length
    ? result.reasons.map(r => `<li>${r}</li>`).join("")
    : "<li>Suspicious URL pattern and phishing indicators detected by ThreatLens AI</li>";

  const overlay = document.createElement("div");
  overlay.id = "tl-guard-banner";
  overlay.style.cssText = `
    position:fixed;inset:0;z-index:2147483647;background:${bg};
    backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;
    font-family:system-ui,-apple-system,sans-serif;color:#fff;padding:24px;
  `;
  overlay.innerHTML = `
    <div style="max-width:540px;width:100%;background:#0f172a;border:2px solid ${accent};border-radius:16px;padding:28px;box-shadow:0 25px 60px rgba(0,0,0,0.75);">
      <div style="display:inline-block;background:${accent};color:#000;font-weight:800;font-size:12px;padding:4px 10px;border-radius:6px;margin-bottom:12px;">
        ⚠️ DECEPTIVE / ${result.label.toUpperCase()} SITE AHEAD · RISK ${result.score}/100
      </div>
      <h2 style="margin:0 0 10px;font-size:22px;color:#fff;">ThreatLens Stopped This Connection</h2>
      <p style="margin:0 0 14px;font-size:13px;color:#cbd5e1;line-height:1.5;">
        Attackers on this link may trick you into sharing passwords, OTPs, or banking details.
      </p>
      <div style="background:#1e293b;border-left:3px solid ${accent};padding:12px 14px;border-radius:8px;margin-bottom:16px;">
        <div style="font-size:12px;font-weight:700;color:${accent};margin-bottom:6px;">Explainable AI Findings:</div>
        <ul style="margin:0;padding-left:18px;font-size:13px;color:#f1f5f9;line-height:1.5;">
          ${reasonsList}
        </ul>
      </div>
      <p style="margin:0 0 20px;font-size:11px;color:#94a3b8;word-break:break-all;">Blocked URL: ${targetUrl}</p>
      <div style="display:flex;gap:12px;justify-content:flex-end;">
        <button id="tl-proceed-risk" style="background:transparent;color:#94a3b8;border:1px solid #475569;padding:10px 14px;border-radius:8px;cursor:pointer;font-size:13px;">
          Ignore Risk & Proceed
        </button>
        <button id="tl-back-safe" style="background:${accent};color:#000;border:none;font-weight:800;padding:10px 18px;border-radius:8px;cursor:pointer;font-size:13px;">
          Back to Safety
        </button>
      </div>
    </div>
  `;
  document.documentElement.appendChild(overlay);
  document.getElementById("tl-back-safe").onclick = () => {
    overlay.remove();
    if (isFullPage) {
      if (window.history.length > 1) window.history.back();
      else window.location.href = "https://www.google.com";
    }
  };
  document.getElementById("tl-proceed-risk").onclick = () => {
    overlay.remove();
    if (!isFullPage) window.open(targetUrl, "_blank", "noopener");
  };
}
