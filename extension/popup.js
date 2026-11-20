document.addEventListener("DOMContentLoaded", async () => {
  const urlEl = document.getElementById("tab-url");
  const btn = document.getElementById("btn-scan");
  const resEl = document.getElementById("result");

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const currentUrl = tab?.url || "";
  urlEl.textContent = currentUrl || "No active web page";

  btn.addEventListener("click", async () => {
    if (!currentUrl.startsWith("http")) {
      resEl.style.display = "block";
      resEl.textContent = "Open any website (http/https) to scan it.";
      return;
    }
    btn.disabled = true;
    btn.textContent = "⏳ Scanning...";
    try {
      const res = await chrome.runtime.sendMessage({
        type: "DEEP_SCAN_TAB",
        url: currentUrl,
      });
      resEl.style.display = "block";
      if (!res || res.error) {
        resEl.textContent = res?.error || "Unable to connect to local ScamShield API.";
        return;
      }
      resEl.textContent = "";
      const title = document.createElement("div");
      title.style.fontWeight = "800";
      title.style.marginBottom = "6px";
      title.style.color = res.verdict === "FRAUD" ? "#f87171" : res.verdict === "SUSPICIOUS" ? "#fbbf24" : "#34d399";
      title.textContent = res.verdict === "FRAUD"
        ? "Fraud — High Risk"
        : res.verdict === "SUSPICIOUS"
          ? "Suspicious — Use Caution"
          : "Safe — Verified Link";

      const en = document.createElement("div");
      en.textContent = (res.reasons_en && res.reasons_en[0]) || "";

      const ar = document.createElement("div");
      ar.className = "ar";
      ar.textContent = (res.reasons_ar && res.reasons_ar[0]) || "";

      resEl.appendChild(title);
      resEl.appendChild(en);
      resEl.appendChild(ar);
    } finally {
      btn.disabled = false;
      btn.textContent = "🔍 Deep Scan Current Page";
    }
  });
});

