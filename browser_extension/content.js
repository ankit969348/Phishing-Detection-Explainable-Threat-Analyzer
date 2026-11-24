const scanCache = new Map();

function scanUrlViaBackground(urlStr) {
  if (!urlStr || !urlStr.startsWith("http")) return Promise.resolve(null);
  if (scanCache.has(urlStr)) return Promise.resolve(scanCache.get(urlStr));

  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ type: "THREATLENS_SCAN_URL", url: urlStr }, (res) => {
        if (chrome.runtime.lastError || !res) {
          resolve(null);
          return;
        }
        scanCache.set(urlStr, res);
        resolve(res);
      });
    } catch {
      resolve(null);
    }
  });
}

function isRisky(res) {
  return res && (res.label === "phishing" || res.label === "suspicious" || res.score >= 40);
}

// 1. Direct Navigation Check (Full-Screen Warning Banner on Risky Sites)
(async function checkOpenedPage() {
  const currentUrl = window.location.href;
  if (!currentUrl.startsWith("http")) return;
  const res = await scanUrlViaBackground(currentUrl);
  if (isRisky(res)) showWarningOverlay(currentUrl, res, true);
})();

// 2. Smart Hover Card (Appears ONLY when Risky; Silent on Safe Links)
let hoverCard = null;
let activeHoverUrl = null;

function showRiskHoverCard(x, y, result) {
  if (!hoverCard) {
    hoverCard = document.createElement("div");
    hoverCard.style.cssText = "position:fixed;z-index:2147483647;pointer-events:none;max-width:300px;background:#0f172a;color:#f8fafc;padding:10px 12px;border-radius:10px;font-family:system-ui,sans-serif;box-shadow:0 12px 28px rgba(0,0,0,0.65);";
    document.documentElement.appendChild(hoverCard);
  }
  const isHigh = result.label === "phishing" || result.score >= 70;
  const accent = isHigh ? "#ef4444" : "#f59e0b";
  const reasonsHtml = result.reasons.length
    ? `<ul style="margin:6px 0 0;padding-left:15px;font-size:11px;color:#cbd5e1;line-height:1.4;">${result.reasons.map(r => `<li>${r}</li>`).join("")}</ul>`
    : `<div style="margin-top:4px;font-size:11px;color:#cbd5e1;">Suspicious URL indicators detected</div>`;

  hoverCard.style.border = `2px solid ${accent}`;
  hoverCard.style.left = Math.min(x + 14, window.innerWidth - 320) + "px";
  hoverCard.style.top = Math.max(10, Math.min(y - 75, window.innerHeight - 130)) + "px";
  hoverCard.style.display = "block";
  hoverCard.innerHTML = `
    <div style="font-size:11px;font-weight:800;color:${accent};">⚠️ THREATLENS ${result.label.toUpperCase()} · ${result.score}/100</div>
    ${reasonsHtml}
  `;
}

document.addEventListener("mouseover", async (e) => {
  const anchor = e.target.closest("a[href]");
  if (!anchor || !anchor.href.startsWith("http")) return;
  const url = anchor.href;
  try { if (new URL(url).hostname === window.location.hostname) return; } catch { return; }

  activeHoverUrl = url;
  const res = await scanUrlViaBackground(url);
  if (activeHoverUrl === url && isRisky(res)) {
    anchor.removeAttribute("title");
    showRiskHoverCard(e.clientX, e.clientY, res);
  }
}, true);

document.addEventListener("mouseout", (e) => {
  if (e.target.closest("a[href]")) {
    activeHoverUrl = null;
    if (hoverCard) hoverCard.style.display = "none";
  }
}, true);

// 3. Pre-Click Check (Silent if Safe; Full Explanation Banner if Risky)
document.addEventListener("click", async (e) => {
  const anchor = e.target.closest("a[href]");
  if (!anchor || !anchor.href.startsWith("http")) return;
  if (e.ctrlKey || e.metaKey || e.shiftKey) return;
  const url = anchor.href;
  try { if (new URL(url).hostname === window.location.hostname) return; } catch { return; }

  const cached = scanCache.get(url);
  if (cached && !isRisky(cached)) return;

  e.preventDefault();
  e.stopImmediatePropagation();
  if (hoverCard) hoverCard.style.display = "none";

  const res = cached || await scanUrlViaBackground(url);
  if (isRisky(res)) {
    showWarningOverlay(url, res, false);
  } else {
    window.open(url, anchor.target || "_blank", "noopener");
  }
}, true);

// 4. Chrome-Style Full Explanation Warning Banner
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
