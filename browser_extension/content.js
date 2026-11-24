const API_DEFAULT = "https://threatlens-backend-fzz3.onrender.com/api";
const scanCache = new Map();

const TRUSTED_DOMAINS = [
  "google.com", "github.com", "microsoft.com", "apple.com",
  "amazon.com", "wikipedia.org", "linkedin.com", "youtube.com",
  "vercel.app", "onrender.com"
];

function isTrusted(urlStr) {
  try {
    const host = new URL(urlStr).hostname.replace(/^www\./, "");
    return TRUSTED_DOMAINS.some(d => host === d || host.endsWith("." + d));
  } catch {
    return false;
  }
}

function quickHeuristic(urlStr) {
  try {
    const u = new URL(urlStr);
    let score = 0;
    const reasons = [];
    if (u.protocol === "http:") {
      score += 35;
      reasons.push("Unencrypted HTTP connection (No HTTPS)");
    }
    const suspiciousTlds = [".xyz", ".top", ".info", ".club", ".online", ".site", ".tk", ".ml", ".ga"];
    if (suspiciousTlds.some(t => u.hostname.endsWith(t))) {
      score += 25;
      reasons.push("High-risk / untrusted domain extension");
    }
    const keywords = ["login", "verify", "secure", "update", "bank", "account", "reward", "claim", "bonus", "kyc", "wallet"];
    const matched = keywords.filter(k => urlStr.toLowerCase().includes(k));
    if (matched.length >= 2) {
      score += 30;
      reasons.push("Suspicious keywords detected: " + matched.slice(0, 3).join(", "));
    } else if (matched.length === 1) {
      score += 15;
      reasons.push("Sensitive keyword in URL: " + matched[0]);
    }
    if ((u.hostname.match(/-/g) || []).length >= 2) {
      score += 15;
      reasons.push("Multiple hyphens in domain name");
    }
    const label = score >= 70 ? "phishing" : score >= 40 ? "suspicious" : "legitimate";
    return { score: Math.min(score, 99), label, reasons };
  } catch {
    return { score: 0, label: "legitimate", reasons: [] };
  }
}

async function analyzeUrl(urlStr) {
  if (!urlStr || !urlStr.startsWith("http")) return null;
  if (isTrusted(urlStr)) return { score: 0, label: "legitimate", reasons: ["Verified trusted domain"] };
  if (scanCache.has(urlStr)) return scanCache.get(urlStr);

  const local = quickHeuristic(urlStr);
  scanCache.set(urlStr, local);

  try {
    const stored = await chrome.storage.local.get(["apiEndpoint"]);
    const base = (stored.apiEndpoint || API_DEFAULT).replace(/\/+$/, "");
    const res = await fetch(`${base}/scan/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlStr })
    });
    if (res.ok) {
      const data = await res.json();
      const result = {
        score: Math.round(data.risk_score ?? local.score),
        label: (data.label || local.label).toLowerCase(),
        reasons: data.red_flags?.length ? data.red_flags : local.reasons
      };
      scanCache.set(urlStr, result);
      return result;
    }
  } catch (_) {}
  return local;
}

// 1. Instant Full-Screen Warning Overlay on Current Page Load
(async function checkCurrentPageImmediately() {
  const currentUrl = window.location.href;
  if (!currentUrl.startsWith("http") || isTrusted(currentUrl)) return;

  const instant = quickHeuristic(currentUrl);
  if (instant.score >= 40) {
    renderFullScreenWarning(currentUrl, instant);
  }
  const full = await analyzeUrl(currentUrl);
  if (full && full.score >= 40) {
    renderFullScreenWarning(currentUrl, full);
  }
})();

function renderFullScreenWarning(urlStr, result) {
  if (document.getElementById("tl-fullscreen-guard")) return;
  const mount = () => {
    if (!document.body) {
      requestAnimationFrame(mount);
      return;
    }
    const isHigh = result.label === "phishing" || result.score >= 70;
    const accent = isHigh ? "#ef4444" : "#f59e0b";
    const overlay = document.createElement("div");
    overlay.id = "tl-fullscreen-guard";
    overlay.style.cssText = `
      position:fixed;inset:0;z-index:2147483647;background:rgba(9,13,22,0.96);
      backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;
      font-family:system-ui,-apple-system,sans-serif;color:#f8fafc;padding:20px;
    `;
    overlay.innerHTML = `
      <div style="max-width:520px;width:100%;background:#111827;border:2px solid ${accent};border-radius:16px;padding:28px;box-shadow:0 25px 50px rgba(0,0,0,0.7);">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">
          <span style="background:${accent};color:#000;font-weight:800;padding:4px 10px;border-radius:6px;font-size:12px;text-transform:uppercase;">
            ${isHigh ? "PHISHING ALERT" : "SUSPICIOUS SITE"} · RISK ${result.score}/100
          </span>
        </div>
        <h2 style="margin:0 0 10px;font-size:22px;color:#fff;">ThreatLens Stopped This Page</h2>
        <p style="margin:0 0 14px;font-size:13px;color:#94a3b8;word-break:break-all;">${urlStr}</p>
        <ul style="margin:0 0 22px;padding-left:18px;font-size:13px;color:#e2e8f0;line-height:1.6;">
          ${(result.reasons.length ? result.reasons : ["Potential phishing indicators detected"]).map(r => `<li>${r}</li>`).join("")}
        </ul>
        <div style="display:flex;gap:12px;justify-content:flex-end;">
          <button id="tl-proceed-btn" style="background:transparent;border:1px solid #475569;color:#94a3b8;padding:10px 16px;border-radius:8px;cursor:pointer;font-size:13px;">
            Ignore & View Site
          </button>
          <button id="tl-goback-btn" style="background:${accent};border:none;color:#000;font-weight:700;padding:10px 18px;border-radius:8px;cursor:pointer;font-size:13px;">
            Back to Safety
          </button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    document.getElementById("tl-goback-btn").onclick = () => {
      if (window.history.length > 1) window.history.back();
      else window.location.href = "https://www.google.com";
    };
    document.getElementById("tl-proceed-btn").onclick = () => overlay.remove();
  };
  mount();
}

// 2. Hover Tooltip Before Clicking Any Link
let tooltipEl = null;
function showHoverTooltip(x, y, text, color) {
  if (!tooltipEl) {
    tooltipEl = document.createElement("div");
    tooltipEl.style.cssText = `
      position:fixed;z-index:2147483646;pointer-events:none;padding:6px 10px;
      border-radius:8px;font-family:system-ui,sans-serif;font-size:12px;font-weight:600;
      background:#0f172a;color:#fff;box-shadow:0 8px 20px rgba(0,0,0,0.45);
      transition:opacity 0.15s ease;
    `;
    document.body.appendChild(tooltipEl);
  }
  tooltipEl.style.border = `1px solid ${color}`;
  tooltipEl.style.left = Math.min(x + 14, window.innerWidth - 260) + "px";
  tooltipEl.style.top = Math.min(y + 14, window.innerHeight - 50) + "px";
  tooltipEl.style.opacity = "1";
  tooltipEl.textContent = text;
}

document.addEventListener("mouseover", async (e) => {
  const anchor = e.target.closest("a[href]");
  if (!anchor || !anchor.href.startsWith("http")) return;
  const href = anchor.href;
  const preview = isTrusted(href) ? { score: 0, label: "legitimate" } : quickHeuristic(href);
  const color = preview.score >= 70 ? "#ef4444" : preview.score >= 40 ? "#f59e0b" : "#22c55e";
  showHoverTooltip(e.clientX, e.clientY, `ThreatLens: ${preview.label.toUpperCase()} (${preview.score}/100)`, color);

  const live = await analyzeUrl(href);
  if (live && tooltipEl && tooltipEl.style.opacity === "1") {
    const liveColor = live.score >= 70 ? "#ef4444" : live.score >= 40 ? "#f59e0b" : "#22c55e";
    showHoverTooltip(e.clientX, e.clientY, `ThreatLens: ${live.label.toUpperCase()} (${live.score}/100)`, liveColor);
  }
});

document.addEventListener("mouseout", (e) => {
  if (e.target.closest("a[href]") && tooltipEl) {
    tooltipEl.style.opacity = "0";
  }
});

// 3. Intercept Click BEFORE Navigating to Dangerous Links
document.addEventListener("click", (e) => {
  const anchor = e.target.closest("a[href]");
  if (!anchor || !anchor.href.startsWith("http")) return;
  const href = anchor.href;
  if (isTrusted(href)) return;

  const check = scanCache.get(href) || quickHeuristic(href);
  if (check.score >= 40) {
    e.preventDefault();
    e.stopImmediatePropagation();
    renderPreClickModal(href, check);
  }
}, true);

function renderPreClickModal(targetUrl, result) {
  const existing = document.getElementById("tl-preclick-modal");
  if (existing) existing.remove();
  const isHigh = result.score >= 70;
  const accent = isHigh ? "#ef4444" : "#f59e0b";

  const modal = document.createElement("div");
  modal.id = "tl-preclick-modal";
  modal.style.cssText = `
    position:fixed;inset:0;z-index:2147483647;background:rgba(2,6,23,0.82);
    display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;padding:16px;
  `;
  modal.innerHTML = `
    <div style="max-width:460px;width:100%;background:#111827;border:2px solid ${accent};border-radius:14px;padding:22px;color:#f8fafc;">
      <div style="color:${accent};font-weight:800;font-size:13px;margin-bottom:6px;">
        ⚠️ PRE-CLICK WARNING · RISK SCORE ${result.score}/100
      </div>
      <h3 style="margin:0 0 8px;font-size:18px;">Are you sure you want to open this link?</h3>
      <p style="margin:0 0 12px;font-size:12px;color:#94a3b8;word-break:break-all;">${targetUrl}</p>
      <ul style="margin:0 0 18px;padding-left:18px;font-size:12px;color:#cbd5e1;">
        ${(result.reasons.length ? result.reasons : ["Suspicious URL pattern detected"]).map(r => `<li>${r}</li>`).join("")}
      </ul>
      <div style="display:flex;gap:10px;justify-content:flex-end;">
        <button id="tl-cancel-nav" style="background:${accent};color:#000;border:none;font-weight:700;padding:8px 14px;border-radius:8px;cursor:pointer;">
          Block & Stay Safe
        </button>
        <button id="tl-allow-nav" style="background:transparent;color:#94a3b8;border:1px solid #475569;padding:8px 12px;border-radius:8px;cursor:pointer;">
          Open Anyway
        </button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
  document.getElementById("tl-cancel-nav").onclick = () => modal.remove();
  document.getElementById("tl-allow-nav").onclick = () => {
    modal.remove();
    window.open(targetUrl, "_blank", "noopener");
  };
}
