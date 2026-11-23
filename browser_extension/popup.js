const DEFAULT_API = "https://threatlens-backend-fzz3.onrender.com/api";

function badgeClass(label) {
  const l = (label || "legitimate").toLowerCase();
  if (l === "phishing") return "phishing";
  if (l === "suspicious") return "suspicious";
  return "safe";
}

document.addEventListener("DOMContentLoaded", async () => {
  const apiInput = document.getElementById("api-input");
  const statusBody = document.getElementById("status-body");
  const quickInput = document.getElementById("quick-input");
  const quickResult = document.getElementById("quick-result");

  const stored = await chrome.storage.local.get(["apiBase"]);
  apiInput.value = stored.apiBase || DEFAULT_API;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id) {
    const tabData = await chrome.storage.local.get([`tab_${tab.id}`]);
    const info = tabData[`tab_${tab.id}`];
    if (info?.result) {
      const lbl = info.result.label || "legitimate";
      statusBody.innerHTML = `
        <span class="badge ${badgeClass(lbl)}">${lbl.toUpperCase()}</span>
        <strong style="margin-left:6px;">Risk: ${info.result.risk_score ?? 0}/100</strong>
        <div style="margin-top:4px; font-size:11px; color:#cbd5e1;">Source: ${info.source}</div>
      `;
    }
  }

  document.getElementById("save-api-btn").onclick = async () => {
    const val = apiInput.value.trim() || DEFAULT_API;
    await chrome.storage.local.set({ apiBase: val });
    quickResult.innerHTML = `<span style="color:#86efac;">Saved API endpoint!</span>`;
  };

  document.getElementById("scan-btn").onclick = () => {
    const raw = quickInput.value.trim();
    if (!raw) return;
    quickResult.textContent = "Scanning...";
    const urlMatch = raw.match(/https?:\/\/[^\s"'<>]+/i);
    const extractedUrl = urlMatch ? urlMatch[0] : "";
    const textPart = raw === extractedUrl ? "" : raw;

    chrome.runtime.sendMessage(
      { type: "MANUAL_SCAN", url: extractedUrl, text: textPart },
      (resp) => {
        if (!resp?.ok) {
          quickResult.innerHTML = `<span style="color:#fca5a5;">Error: ${resp?.error || "Backend unreachable"}</span>`;
          return;
        }
        const r = resp.result;
        const lbl = r.label || "legitimate";
        const flags = (r.red_flags || []).length
          ? `<ul style="margin:6px 0 0 14px; padding:0; font-size:11px; color:#fca5a5;">${r.red_flags.map(f => `<li>${f}</li>`).join("")}</ul>`
          : "";
        quickResult.innerHTML = `
          <span class="badge ${badgeClass(lbl)}">${lbl.toUpperCase()}</span>
          <strong style="margin-left:6px;">Score: ${r.risk_score ?? 0}/100</strong>
          ${flags}
        `;
      }
    );
  };
});
