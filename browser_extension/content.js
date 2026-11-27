const scanCache = new Map(); // url -> { result, timestamp }
const CACHE_TTL_MS = 60 * 1000;

function instantLocalCheck(urlStr) {
  try {
    const u = new URL(urlStr);
    const reasons = [];
    let score = 0;
    if (u.protocol === "http:") {
      score += 35;
      reasons.push("Unencrypted HTTP connection (No HTTPS)");
    }
    if ([".xyz", ".top", ".info", ".club", ".online", ".site", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click"].some(t => u.hostname.endsWith(t))) {
      score += 35;
      reasons.push("High-risk / untrusted domain extension");
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname)) {
      score += 45;
      reasons.push("Direct IP address used instead of domain name");
    }
    if (urlStr.includes("@")) {
      score += 40;
      reasons.push("Deceptive '@' symbol redirect trick in URL");
    }
    const hits = ["login", "verify", "secure", "update", "bank", "account", "kyc", "wallet", "reward", "signin", "confirm", "suspend"].filter(k => urlStr.toLowerCase().includes(k));
    if (hits.length >= 2) {
      score += 30;
      reasons.push("Phishing keywords: " + hits.slice(0, 3).join(", "));
    } else if (hits.length === 1) {
      score += 15;
      reasons.push("Sensitive keyword: " + hits[0]);
    }
    const label = score >= 70 ? "phishing" : score >= 40 ? "suspicious" : "legitimate";
    return { score: Math.min(score, 99), label, reasons };
  } catch {
    return { score: 0, label: "legitimate", reasons: [] };
  }
}

function getCachedResult(urlStr) {
  const entry = scanCache.get(urlStr);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
    scanCache.delete(urlStr);
    return null;
  }
  return entry.result;
}

function scanUrlViaBackground(urlStr) {
  if (!urlStr || !urlStr.startsWith("http")) return Promise.resolve(null);
  const cached = getCachedResult(urlStr);
  if (cached) return Promise.resolve(cached);

  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ type: "THREATLENS_SCAN_URL", url: urlStr }, (res) => {
        if (chrome.runtime.lastError || !res || typeof res.score !== "number") {
          resolve(null);
          return;
        }
        scanCache.set(urlStr, { result: res, timestamp: Date.now() });
        resolve(res);
      });
    } catch {
      resolve(null);
    }
  });
}

function isRisky(res) {
  return Boolean(res && (res.label === "phishing" || res.label === "suspicious" || res.score >= 40));
}

(async function checkOpenedPage() {
  const currentUrl = window.location.href;
  if (!currentUrl.startsWith("http")) return;
  const local = instantLocalCheck(currentUrl);
  if (isRisky(local)) showWarningOverlay(currentUrl, local, true);
  const res = await scanUrlViaBackground(currentUrl);
  if (isRisky(res)) showWarningOverlay(currentUrl, res, true);
})();

let activeUrl = null;
let activeTargetEl = null;

function removeHoverCard() {
  const existing = document.getElementById("threatlens-hover-tooltip");
  if (existing) existing.remove();
}

function renderHoverCard(x, y, result, urlStr) {
  removeHoverCard();

  const card = document.createElement("div");
  card.id = "threatlens-hover-tooltip";
  const isHigh = result.label === "phishing" || result.score >= 70;
  const accent = isHigh ? "#ef4444" : "#f59e0b";

  const safeX = Math.max(12, Math.min(x + 14, window.innerWidth - 330));
  const safeY = y > 140 ? y - 115 : Math.min(y + 20, window.innerHeight - 140);

  card.style.cssText = `
    position: fixed !important;
    left: ${safeX}px !important;
    top: ${safeY}px !important;
    z-index: 2147483647 !important;
    pointer-events: none !important;
    width: 310px !important;
    background: #0f172a !important;
    color: #f8fafc !important;
    border: 2px solid ${accent} !important;
    padding: 10px 12px !important;
    border-radius: 10px !important;
    font-family: system-ui, -apple-system, sans-serif !important;
    box-shadow: 0 14px 32px rgba(0, 0, 0, 0.85) !important;
    display: block !important;
    visibility: visible !important;
    opacity: 1 !important;
  `;

  const reasonsHtml = (result.reasons && result.reasons.length)
    ? `<ul style="margin:6px 0 0;padding-left:15px;font-size:11px;color:#cbd5e1;line-height:1.4;">${result.reasons.map(r => `<li>${r}</li>`).join("")}</ul>`
    : `<div style="margin-top:4px;font-size:11px;color:#cbd5e1;">Suspicious URL indicators detected</div>`;

  card.innerHTML = `
    <div style="font-size:11px;font-weight:800;color:${accent};letter-spacing:0.3px;">
      ⚠ THREATLENS ${result.label.toUpperCase()} · RISK ${result.score}/100
    </div>
    <div style="font-size:10px;color:#94a3b8;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
      ${urlStr}
    </div>
    ${reasonsHtml}
  `;

  (document.body || document.documentElement).appendChild(card);
}

function extractUrlFromElement(target) {
  if (!target) return null;
  const el = target.nodeType === 3 ? target.parentElement : target;
  if (!el) return null;

  // 1. Standard <a> link
  const anchor = el.closest ? el.closest("a[href]") : null;
  if (anchor && anchor.href && anchor.href.startsWith("http")) {
    return { url: anchor.href, element: anchor };
  }

  // 2. Plain-text URL inside WhatsApp / Webmail spans when link is not clickable yet
  const text = (el.innerText || el.textContent || "").trim();
  if (text.length > 8 && text.length < 300) {
    const match = text.match(/https?:\/\/[^\s<>"')]+/i);
    if (match) {
      return { url: match[0], element: el };
    }
  }
  return null;
}

function handleHoverTrigger(e) {
  const found = extractUrlFromElement(e.target);
  if (!found) {
    if (activeUrl !== null) {
      activeUrl = null;
      activeTargetEl = null;
      removeHoverCard();
    }
    return;
  }

  const { url, element } = found;
  try {
    if (new URL(url).hostname === window.location.hostname) {
      activeUrl = null;
      activeTargetEl = null;
      removeHoverCard();
      return;
    }
  } catch {
    return;
  }

  if (element.removeAttribute) element.removeAttribute("title");

  const isFreshEntry = activeUrl !== url || activeTargetEl !== element;
  activeUrl = url;
  activeTargetEl = element;

  const cached = getCachedResult(url);
  const instant = instantLocalCheck(url);
  const bestKnown = (cached && cached.score >= instant.score) ? cached : instant;

  if (isRisky(bestKnown)) {
    renderHoverCard(e.clientX, e.clientY, bestKnown, url);
  } else {
    removeHoverCard();
  }

  if (isFreshEntry && !cached) {
    scanUrlViaBackground(url).then((live) => {
      if (activeUrl === url && live) {
        const merged = live.score >= instant.score ? live : instant;
        if (isRisky(merged)) {
          renderHoverCard(e.clientX, e.clientY, merged, url);
        }
      }
    });
  }
}

document.addEventListener("mouseover", handleHoverTrigger, true);
document.addEventListener("pointermove", handleHoverTrigger, true);

document.addEventListener("mouseout", (e) => {
  if (!activeTargetEl) return;
  const related = e.relatedTarget;
  if (!related || !activeTargetEl.contains(related)) {
    activeUrl = null;
    activeTargetEl = null;
    removeHoverCard();
  }
}, true);

document.addEventListener("click", (e) => {
  const found = extractUrlFromElement(e.target);
  if (!found) return;
  if (e.ctrlKey || e.metaKey || e.shiftKey) return;
  const { url } = found;
  try {
    if (new URL(url).hostname === window.location.hostname) return;
  } catch {
    return;
  }

  const cached = getCachedResult(url);
  const instant = instantLocalCheck(url);
  const check = (cached && cached.score >= instant.score) ? cached : instant;

  if (isRisky(check)) {
    e.preventDefault();
    e.stopImmediatePropagation();
    removeHoverCard();
    showWarningOverlay(url, check, false);
  }
}, true);

function showWarningOverlay(targetUrl, result, isFullPage) {
  const existing = document.getElementById("tl-guard-banner");
  if (existing) existing.remove();

  const isHigh = result.label === "phishing" || result.score >= 70;
  const bg = isHigh ? "rgba(69, 10, 10, 0.97)" : "rgba(69, 26, 3, 0.97)";
  const accent = isHigh ? "#ef4444" : "#f59e0b";
  const reasonsList = (result.reasons && result.reasons.length)
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
        ⚠ DECEPTIVE / ${result.label.toUpperCase()} SITE AHEAD · RISK ${result.score}/100
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
