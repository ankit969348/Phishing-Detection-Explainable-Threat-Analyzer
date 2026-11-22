let lastScannedSignature = "";
let scanCooldown = false;

const SUSPICIOUS_TRIGGER = /(https?:\/\/|www\.|verify|urgent|suspend|account|password|otp|bank|kyc|lottery|prize|click here|login|bet|betting|casino|bonus)/i;

function showThreatBanner(result, source) {
  const label = (result.label || "legitimate").toLowerCase();
  if (label === "legitimate" || label === "safe") return;

  const existing = document.getElementById("threatlens-warning-banner");
  if (existing) existing.remove();

  const isPhishing = label === "phishing";
  const banner = document.createElement("div");
  banner.id = "threatlens-warning-banner";
  banner.style.cssText = `
    position: fixed;
    top: 14px;
    right: 14px;
    z-index: 2147483647;
    max-width: 390px;
    background: ${isPhishing ? "#7f1d1d" : "#78350f"};
    color: #ffffff;
    border: 2px solid ${isPhishing ? "#ef4444" : "#f59e0b"};
    border-radius: 12px;
    padding: 14px 16px;
    font-family: system-ui, -apple-system, sans-serif;
    box-shadow: 0 12px 30px rgba(0,0,0,0.45);
    line-height: 1.4;
  `;

  const indicators = (result.red_flags || []).slice(0, 4);
  const reasonsHtml = indicators.length
    ? `<ul style="margin: 8px 0 0 16px; padding: 0; font-size: 12px; color: #fecaca;">${indicators.map(i => `<li>${i}</li>`).join("")}</ul>`
    : "";

  banner.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">
      <strong style="font-size:14px;">
        ${isPhishing ? "🚨 ThreatLens: PHISHING DETECTED" : "⚠️ ThreatLens: SUSPICIOUS CONTENT"}
      </strong>
      <button id="threatlens-close-btn" style="background:rgba(255,255,255,0.18); border:none; color:#fff; border-radius:6px; padding:2px 8px; cursor:pointer; font-weight:bold;">✕</button>
    </div>
    <div style="font-size:12px; margin-top:4px; opacity:0.95;">
      Source: <b>${source}</b> · Risk Score: <b>${result.risk_score ?? 0}/100</b>
    </div>
    ${reasonsHtml}
  `;

  document.body.appendChild(banner);
  document.getElementById("threatlens-close-btn").onclick = () => banner.remove();
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "THREATLENS_ALERT" && msg.result) {
    showThreatBanner(msg.result, msg.source || "Website URL");
  }
});

function isIgnoredHost(host) {
  const safeHosts = ["localhost", "127.0.0.1", "gemini.google.com", "github.com", "wikipedia.org"];
  return safeHosts.some(h => host === h || host.endsWith("." + h));
}

function extractRelevantPageText() {
  const host = window.location.hostname;
  if (host.includes("web.whatsapp.com")) {
    const bubbles = Array.from(document.querySelectorAll("div.copyable-text, span.selectable-text"));
    const recent = bubbles.slice(-4).map(el => el.innerText).join(" \n ");
    return { source: "WhatsApp Web", text: recent.slice(0, 1500), url: "" };
  }
  if (host.includes("mail.google.com")) {
    const mailBody = document.querySelector("div.a3s.aiL");
    if (!mailBody) return { source: "Gmail Web", text: "", url: "" };
    return { source: "Gmail Web", text: (mailBody.innerText || "").slice(0, 2000), url: "" };
  }
  if (host.includes("www.google.com")) {
    const topResultLink = document.querySelector("#search a[href^='http']:not([href*='google.com'])");
    if (!topResultLink) return { source: "Google Search", text: "", url: "" };
    const resultBlock = topResultLink.closest("div.g") || topResultLink.parentElement;
    return {
      source: "Google Search Result",
      text: (resultBlock?.innerText || "").slice(0, 800),
      url: topResultLink.href
    };
  }
  return { source: "Webpage Content", text: (document.body?.innerText || "").slice(0, 1500), url: "" };
}

function inspectDomForThreats() {
  if (scanCooldown) return;
  const host = window.location.hostname;
  if (isIgnoredHost(host)) return;

  const { source, text, url } = extractRelevantPageText();
  if (!text || text.length < 15) return;
  if (!SUSPICIOUS_TRIGGER.test(text + " " + url)) return;

  const signature = `${source}:${url}:${text.slice(0, 150)}`;
  if (signature === lastScannedSignature) return;
  lastScannedSignature = signature;
  scanCooldown = true;
  setTimeout(() => { scanCooldown = false; }, 5000);

  const urlMatch = url || (text.match(/https?:\/\/[^\s"'<>]+/i)?.[0] || "");
  chrome.runtime.sendMessage(
    { type: "SCAN_CONTENT", source, text, url: urlMatch },
    (resp) => {
      if (resp?.ok && resp.result) {
        const lbl = (resp.result.label || "legitimate").toLowerCase();
        if (lbl !== "legitimate" && lbl !== "safe") {
          showThreatBanner(resp.result, source);
        }
      }
    }
  );
}

const observer = new MutationObserver(() => {
  inspectDomForThreats();
});

if (document.body) {
  observer.observe(document.body, { childList: true, subtree: true });
  setTimeout(inspectDomForThreats, 1800);
}
