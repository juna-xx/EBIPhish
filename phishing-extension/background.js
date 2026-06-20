// background.js, the service worker
// Two-stage check:
//   1. onBeforeNavigate: fast URL-only check, block if HIGH RISK
//   2. onCompleted: full scan including page link extraction

const BACKEND_CHECK = "http://localhost:8080/api/check";
const BACKEND_PAGE  = "http://localhost:8080/api/check-page";
const WARNING_PAGE  = chrome.runtime.getURL("warning.html");

function shouldSkip(url) {
  if (!url) return true;
  const skip = ["chrome://", "chrome-extension://", "about:", "file://", "data:"];
  return skip.some(prefix => url.startsWith(prefix));
}

// ─────────────────────────────────────────────────────────────
// Stage 1: URL check before page loads, blocks if HIGH RISK
// ─────────────────────────────────────────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener(async ({ tabId, url, frameId }) => {
  if (frameId !== 0) return;
  if (shouldSkip(url)) return;
  if (url.startsWith(WARNING_PAGE)) return;

  // set loading state so popup shows something immediately
  await chrome.storage.session.set({
    [`result_${tabId}`]: { status: "loading", url }
  });

  try {
    const response = await fetch(
      `${BACKEND_CHECK}?url=${encodeURIComponent(url)}`,
      { signal: AbortSignal.timeout(10000) }
    );

    if (!response.ok) return; // fail open if backend error

    const data = await response.json();

    // block if HIGH RISK
    if (data.warningCount > 2) {
      await chrome.storage.session.set({
        [`result_${tabId}`]: { status: "blocked", url, data }
      });

      updateBadge(tabId, data.warningCount);

      chrome.tabs.update(tabId, {
        url: `${WARNING_PAGE}?blocked=${encodeURIComponent(url)}`
      });
      return;
    }

    // not blocked: store preliminary result
    // (will be overwritten by the fuller result from Stage 2)
    await chrome.storage.session.set({
      [`result_${tabId}`]: { status: "done", url, data }
    });

    updateBadge(tabId, data.warningCount);

  } catch (err) {
    // backend unreachable: fail open, don't block navigation
    console.warn("[PhishingDetector] Stage 1 failed:", err.message);
  }
});

// ─────────────────────────────────────────────────────────────
// Stage 2 — full scan after page loads, including link extraction
// ─────────────────────────────────────────────────────────────
chrome.webNavigation.onCompleted.addListener(async ({ tabId, url, frameId }) => {
  if (frameId !== 0) return;
  if (shouldSkip(url)) return;
  if (url.startsWith(WARNING_PAGE)) return;

  // don't overwrite a blocked result
  const stored = await chrome.storage.session.get(`result_${tabId}`);
  const entry  = stored[`result_${tabId}`];
  if (entry?.status === "blocked") return;

  try {
    // extracting all external links from the page DOM
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => Array.from(document.querySelectorAll("a[href]"))
        .map(a => a.href)
        .filter(href => href && href.startsWith("http"))
        .slice(0, 200)
    });

    const pageLinks = results[0]?.result ?? [];

    const response = await fetch(BACKEND_PAGE, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, pageLinks }),
      signal: AbortSignal.timeout(20000)
    });

    if (!response.ok) return;

    const data = await response.json();

    await chrome.storage.session.set({
      [`result_${tabId}`]: { status: "done", url, data }
    });

    updateBadge(tabId, data.warningCount);

  } catch (err) {
    console.warn("[PhishingDetector] Stage 2 failed:", err.message);
  }
});


// badge
// ..........
function updateBadge(tabId, warningCount) {
  if (warningCount === 0) {
    chrome.action.setBadgeText({ tabId, text: "✓" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#16a34a" });
  } else if (warningCount <= 2) {
    chrome.action.setBadgeText({ tabId, text: warningCount.toString() });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#d97706" });
  } else {
    chrome.action.setBadgeText({ tabId, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#dc2626" });
  }
}
