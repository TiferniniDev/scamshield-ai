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

  function extractExternalUrl(anchor, onMaps) {
    const raw = anchor.getAttribute("href") || "";
    const aria = anchor.getAttribute("aria-label") || "";

    // 1. Try parsing href and unwrapping Google /url and Sponsored /aclk ad redirects
    if (raw && !raw.startsWith("#") && !raw.startsWith("javascript:")) {
      let href = raw;
      try {
        const parsed = new URL(href, window.location.origin);
        if (parsed.hostname.includes("google.") || parsed.hostname.includes("googleadservices.")) {
          const unwrapped =
            parsed.searchParams.get("adurl") ||
            parsed.searchParams.get("q") ||
            parsed.searchParams.get("url") ||
            parsed.searchParams.get("dest_url");
          if (unwrapped && unwrapped.startsWith("http")) {
            href = unwrapped;
          }
        }
        const target = new URL(href);
        if (target.protocol === "http:" || target.protocol === "https:") {
          const host = target.hostname.toLowerCase();
          if (!IGNORED_HOSTS.some((h) => host === h || host.endsWith("." + h))) {
            return target.href;
          }
        }
      } catch {
        // Fall through to Maps aria-label/text domain fallback
      }
    }

    // 2. Fallback for Google Maps Sponsored pins (which often hide the domain in aria-label or row text)
    if (onMaps) {
      const mAria = aria.match(/Website:\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
      if (mAria) return `https://${mAria[1]}`;
      const txt = (anchor.textContent || "").trim();
      const mTxt = txt.match(/^([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)$/);
      if (mTxt && !IGNORED_HOSTS.some((h) => mTxt[1].toLowerCase().endsWith(h))) {
        return `https://${mTxt[1]}`;
      }
    }

    return null;
  }

  function createBadge(result) {
    const span = document.createElement("span");
    span.className = "scamshield-badge";
    span.style.display = "inline-flex";
    span.style.alignItems = "center";
    span.style.gap = "4px";
    span.style.marginLeft = "8px";
    span.style.marginRight = "6px";
    span.style.padding = "2px 9px";
    span.style.borderRadius = "999px";
    span.style.fontSize = "11px";
    span.style.fontWeight = "700";
    span.style.fontFamily = "-apple-system, BlinkMacSystemFont, sans-serif";
    span.style.verticalAlign = "middle";
    span.style.lineHeight = "1.4";
    span.style.flexShrink = "0";
    span.style.whiteSpace = "nowrap";
    span.style.cursor = "help";

    const reason = (result.reasons_en && result.reasons_en[0]) || "";
    span.title = `ScamShield AI (${result.verdict}): ${reason}`;

    if (result.verdict === "FRAUD") {
      span.style.background = "#dc2626";
      span.style.color = "#ffffff";
      span.style.border = "1px solid #fecaca";
      span.textContent = "Fraud";
    } else if (result.verdict === "SUSPICIOUS") {
      span.style.background = "#d97706";
      span.style.color = "#ffffff";
      span.style.border = "1px solid #fde68a";
      span.textContent = "Suspicious";
    } else {
      span.style.background = "#059669";
      span.style.color = "#ecfdf5";
      span.style.border = "1px solid #34d399";
      span.textContent = "Safe";
    }
    return span;
  }

  async function processCandidateLinks() {
    const onMaps = isMapsPage();
    // On Google Maps, match both organic (data-item-id="authority") AND Sponsored Website rows
    const selectors = onMaps
      ? 'a[data-item-id="authority"], button[data-item-id="authority"], a[aria-label^="Website:"], a[aria-label*="Website"], button[aria-label^="Website:"]'
      : 'div#search a[href^="http"], div#tads a[href^="http"], a[href^="/url?"], a[href*="/aclk"]';

    const anchors = Array.from(document.querySelectorAll(selectors))
      .filter((a) => !a.hasAttribute(PROCESSED_ATTR))
      .slice(0, 25);

    const source = onMaps ? "patrol_maps" : "patrol_search";

    for (const anchor of anchors) {
      anchor.setAttribute(PROCESSED_ATTR, "1");
      const targetUrl = extractExternalUrl(anchor, onMaps);
      if (!targetUrl) continue;

      // Prevent duplicate badges inside the same Maps row (e.g. main row + circular open-website button)
      const rowContainer = onMaps
        ? (anchor.closest(".RcCsl, .AeaXub, .CsEnBe") || anchor.parentElement?.parentElement || anchor.parentElement)
        : anchor.parentElement;
      if (rowContainer && rowContainer.querySelector(".scamshield-badge")) continue;

      // On Maps, skip tiny circular icon-only buttons when a text label row exists
      if (onMaps && !(anchor.textContent || "").trim()) continue;

      // Only badge visible meaningful links on Search
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
            if (rowContainer && rowContainer.querySelector(".scamshield-badge")) {
              resolve();
              return;
            }
            const badge = createBadge(res);
            const h3 = anchor.querySelector("h3");
            if (h3) {
              h3.appendChild(badge);
            } else if (onMaps) {
              const textEl = anchor.querySelector(".Io6YTe, .rogA2c") || anchor;
              textEl.appendChild(badge);
            } else {
              anchor.insertAdjacentElement("afterend", badge);
            }

            if (res.verdict === "FRAUD") {
              anchor.addEventListener(
                "click",
                (ev) => {
                  const reason = (res.reasons_en && res.reasons_en[0]) || "High-risk financial fraud detected.";
                  const proceed = window.confirm(
                    `SCAMSHIELD AI WARNING\n\n` +
                    `This website (${res.host}) is flagged as FRAUD.\n` +
                    `Reason: ${reason}\n\n` +
                    `Click Cancel to stay safe, or OK to continue anyway.`
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

