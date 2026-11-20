/**
 * ScamShield AI - Pre-Click Content Script for Google Search & Google Maps
 * Injects real-time SAFE / SUSPICIOUS / FRAUD badges beside links BEFORE the user clicks,
 * and intercepts clicks on high-risk FRAUD links with a warning confirmation.
 */
(function () {
  const PROCESSED_ATTR = "data-scamshield-checked";
  const IGNORED_HOSTS = [
    "google.com",
    "google.ae",
    "gstatic.com",
    "googleapis.com",
    "googleusercontent.com",
    "accounts.google.com",
    "support.google.com",
    "policies.google.com",
    "bing.com",
    "microsoft.com",
  ];

  function isMapsPage() {
    return window.location.pathname.startsWith("/maps") || window.location.hostname.startsWith("maps.");
  }

  function extractExternalUrl(anchor) {
    const raw = anchor.getAttribute("href") || "";
    if (!raw || raw.startsWith("#") || raw.startsWith("javascript:")) return null;

    let href = raw;
    try {
      const parsed = new URL(href, window.location.origin);
      // Unwrap Google redirect URLs (/url?q=https://...)
      if ((parsed.hostname.includes("google.") && parsed.pathname === "/url") || parsed.searchParams.get("q")) {
        const q = parsed.searchParams.get("q") || parsed.searchParams.get("url");
        if (q && q.startsWith("http")) {
          href = q;
        }
      }
      const target = new URL(href);
      if (target.protocol !== "http:" && target.protocol !== "https:") return null;
      const host = target.hostname.toLowerCase();
      if (IGNORED_HOSTS.some((h) => host === h || host.endsWith("." + h))) return null;
      return target.href;
    } catch {
      return null;
    }
  }

  function createBadge(result) {
    const span = document.createElement("span");
    span.style.display = "inline-flex";
    span.style.alignItems = "center";
    span.style.gap = "4px";
    span.style.marginLeft = "8px";
    span.style.padding = "2px 8px";
    span.style.borderRadius = "999px";
    span.style.fontSize = "11px";
    span.style.fontWeight = "700";
    span.style.fontFamily = "-apple-system, BlinkMacSystemFont, sans-serif";
    span.style.verticalAlign = "middle";
    span.style.lineHeight = "1.4";
    span.style.cursor = "help";

    const reason = (result.reasons_en && result.reasons_en[0]) || "";
    span.title = `ScamShield AI (${result.risk_score}/100): ${reason}`;

    if (result.verdict === "FRAUD") {
      span.style.background = "#dc2626";
      span.style.color = "#ffffff";
      span.style.border = "1px solid #fecaca";
      span.textContent = `🔴 FRAUD (${result.risk_score}/100)`;
    } else if (result.verdict === "SUSPICIOUS") {
      span.style.background = "#d97706";
      span.style.color = "#ffffff";
      span.style.border = "1px solid #fde68a";
      span.textContent = `🟡 Suspicious (${result.risk_score}/100)`;
    } else {
      span.style.background = "#065f46";
      span.style.color = "#d1fae5";
      span.style.border = "1px solid #10b981";
      span.textContent = "🟢 Safe";
    }
    return span;
  }

  async function processCandidateLinks() {
    const onMaps = isMapsPage();
    const selectors = onMaps
      ? 'a[data-item-id="authority"], a[aria-label*="Website"], a[href^="http"]'
      : 'div#search a[href^="http"], div#tads a[href^="http"], a[href^="/url?"]';

    const anchors = Array.from(document.querySelectorAll(selectors))
      .filter((a) => !a.hasAttribute(PROCESSED_ATTR))
      .slice(0, 25);

    const source = onMaps ? "patrol_maps" : "patrol_search";

    for (const anchor of anchors) {
      anchor.setAttribute(PROCESSED_ATTR, "1");
      const targetUrl = extractExternalUrl(anchor);
      if (!targetUrl) continue;

      // Only badge visible meaningful links (headings on Search or Website buttons on Maps)
      if (!onMaps && !anchor.querySelector("h3") && !anchor.closest("#tads")) continue;

      try {
        const res = await chrome.runtime.sendMessage({
          type: "ANALYZE_LINK",
          url: targetUrl,
          source,
          deepScan: false,
        });
        if (!res || res.error) continue;

        await new Promise((resolve) =>
          requestAnimationFrame(() => {
            const badge = createBadge(res);
            const h3 = anchor.querySelector("h3");
            if (h3) {
              h3.appendChild(badge);
            } else {
              anchor.insertAdjacentElement("afterend", badge);
            }

            if (res.verdict === "FRAUD") {
              anchor.addEventListener(
                "click",
                (ev) => {
                  const reason = (res.reasons_en && res.reasons_en[0]) || "High-risk financial fraud detected.";
                  const proceed = window.confirm(
                    `⚠️ SCAMSHIELD AI PRE-CLICK WARNING\n\n` +
                    `This link (${res.host}) is flagged as FRAUD (${res.risk_score}/100).\n` +
                    `Reason: ${reason}\n\n` +
                    `Click Cancel to stay safe, or OK to open anyway.`
                  );
                  if (!proceed) {
                    ev.preventDefault();
                    ev.stopPropagation();
                  }
                },
                true
              );
            }
            resolve();
          })
        );
      } catch {
        // Ignore transient extension context invalidation
      }
    }
  }

  let debounceTimer = null;
  function scheduleScan() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(processCandidateLinks, 450);
  }

  scheduleScan();
  const observer = new MutationObserver(scheduleScan);
  observer.observe(document.body, { childList: true, subtree: true });
})();

