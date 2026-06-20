document.addEventListener("DOMContentLoaded", async () => {

  const urlBarEl   = document.getElementById("url-bar");
  const footerTime = document.getElementById("footer-time");

  footerTime.textContent = new Date().toLocaleTimeString();

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) {
    renderError("Could not read current tab.");
    return;
  }

  urlBarEl.textContent = tab.url || "—";

  const key    = `result_${tab.id}`;
  const stored = await chrome.storage.session.get(key);
  const entry  = stored[key];

  if (!entry) {
    renderMessage("ℹ️", "No result yet", "Navigate to a page to trigger a check.");
    return;
  }

  if (entry.status === "loading") {
    renderMessage("⏳", "Analysing…", "Check in progress — try again in a moment.");
    return;
  }

  if (entry.status === "blocked") {
    renderBlocked(entry.url);
    return;
  }

  if (entry.status === "error") {
    renderError(entry.message || "Unknown error.");
    return;
  }

  renderResult(entry.data);
});

// ....................
// Human-readable tooltip explanations for checks
// ..............

const CHECK_TIPS = {
  // Reputation Feeds
  "openphish":      "Compares the site against known lists of dangerous or fraudulent websites. If it's on a blacklist, it has already been reported by someone.",
  "google safe":    "Checks Google's database of unsafe websites. Google flags sites that are known to distribute malware or run phishing scams.",
  "phishtank":      "Checks PhishTank, a community-maintained database of confirmed phishing websites submitted and verified by real users.",
  "virustotal":     "Queries VirusTotal, which scans the site with 70+ security engines simultaneously to look for malware or phishing activity.",

  // HTTPS, SSL, and Cryptography
  "not using https": "Checks if the site uses a secure, encrypted connection (HTTPS). Failing to use HTTPS means your data travels over the web in plain text.",
  "certificate":    "Verifies the site's security certificate is genuine, unexpired, and issued by a trusted authority. Fake certificates can be used by scammers.",
  "cipher suite":   "Identifies the specific bundle of cryptographic algorithms used to encrypt the connection between your browser and the server.",
  "tls version":    "Checks the version of Transport Layer Security (TLS). Modern versions ensure your encrypted data cannot be easily broken by modern eavesdroppers.",
  "encryption quality": "Evaluates the overall cipher implementation. Modern networks should use GCM or ChaCha20 algorithms to guarantee privacy.",
  "broken encryption": "Looks for obsolete encryption algorithms like RC4 or DES that have known security flaws and are easily cracked.",
  "weak cipher":    "Identifies vulnerable encryption patterns (like 3DES) that no longer meet modern internet safety compliance standards.",
  "insecure hash":  "Checks for broken data-hashing algorithms like MD5 that allow attackers to tamper with supposedly encrypted traffic.",
  "weak hash":      "Detects outdated hashing standards like SHA-1 that are vulnerable to collision attacks.",
  "insecure protocol": "Checks if the site forces archaic fallback standards like SSLv2 or SSLv3, which lack modern privacy safeguards.",
  "forward secrecy": "Verifies if the connection renegotiates cryptographic keys continuously. Forward secrecy prevents a stolen server key from unlocking past traffic logs.",

  // Domain & WHOIS Metadata
  "registrar":      "Displays the official commercial entity where the domain name was purchased and verified.",
  "domain created": "Newly registered domains are often used by scammers because they're cheap and disposable. Older, established domains are generally more trustworthy.",
  "domain age":     "Newly registered domains are often used by scammers because they're cheap and disposable. Older, established domains are generally more trustworthy.",

  // Defensive URL Heuristics & Obfuscation
  "unicode":        "Scans for hidden, invisible, or unexpected Unicode symbols meant to alter the look of a text line without your knowledge.",
  "control char":   "Checks for hidden execution commands baked directly into the URL text block to hijack application behavior.",
  "homoglyph":      "Looks for character spoofing, where look-alike symbols from non-Latin scripts are used to visually impersonate familiar company brands.",
  "mixed latin":    "Detects dangerous IDN homograph setups where a scammer blends distinct character sets to trick you into visiting an unrecognized server destination.",
  "ip address":     "Using a raw string of numbers (like an IP address) instead of a human-readable domain layout is highly unusual and a strong indicator of a phishing server.",
  "subdomain":      "Counts structural dot-delimiters. Phishing pages frequently chain multiple subdomains together to masquerade as an established portal (e.g., brand.com.login.evil.com).",
  "url length":     "Excessively long web strings are frequently used to push the real, malicious root domain structure completely off-screen on compact mobile viewports.",

  // Page Content Fallbacks
  "forms":          "Checks if the page contains data-entry blocks where a malicious actor might attempt credential harvesting.",
  "password field": "Detects input vectors designed to capture login information.",
  
  // Base Fallback
  "default":        "This check looks at one specific property of the URL or page to help determine whether the site may be dangerous."
};

/**
 * return an explanation for a given check label.
 * fully case-insensitive and robust against multi-word strings.
 */
function getTip(label) {
  if (!label) return CHECK_TIPS["default"];
  
  const normalizedLabel = label.toLowerCase();

  // look for a key that is contained within the backend label text
  const matchedKey = Object.keys(CHECK_TIPS).find(key => 
    normalizedLabel.includes(key)
  );

  return matchedKey ? CHECK_TIPS[matchedKey] : CHECK_TIPS["default"];
}

async function fetchAISummary(data) {
  const prompt = `
    You are a security assistant. A phishing detection system analyzed a URL and returned these results:
    - URL: ${data.url}
    - Verdict: ${data.verdict}
    - Warnings detected: ${data.warningCount}
    - Findings: ${JSON.stringify(data.findings)}
    
IMPORTANT RULES:
- Do NOT override or reinterpret the system verdict or findings.
- Do NOT add new risks that are not present in the findings.
- Do NOT claim the site is completely safe if warnings exist.
- Do NOT use fear, panic, or exaggerated language.
- Do NOT include technical details that are not relevant to user safety (e.g. cipher suites, TLS versions, WHOIS).

OUTPUT RULES:
- Use ONLY the most important 2–4 findings.
- Summarize technical details into simple language.
- Keep response between 3–5 sentences (maximum 6 only if absolutely necessary).
- Do NOT repeat the verdict more than once.
- Do NOT list findings as a long bullet list.

SAFE MODE RULE:
If Verdict = SAFE AND Warnings detected = 0:
- Be concise and factual only
- Do NOT use cautionary words like "however", "but", "may", "still"
- Do NOT imply hidden risks

RESPONSE FORMAT:
1. Start with the verdict in one sentence
2. Briefly explain the most important findings in simple language
3. End only if necessary with a neutral statement (no advice unless danger exists)
  `;

  const YOUR_API_KEY = await fetch(
    "http://localhost:8080/api/config/groq-key"
  ).then(res => res.text());

  const response = await fetch(
    "https://api.groq.com/openai/v1/chat/completions",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${YOUR_API_KEY}`
      },
      body: JSON.stringify({
        model: "llama-3.1-8b-instant",
        messages: [
          {
            role: "system",
            content: "You are a calm cybersecurity assistant. Be clear and factual."
          },
          {
            role: "user",
            content: prompt
          }
        ],
        temperature: 0.3
      })
    }
  );

  const result = await response.json();

  console.log("Groq response:", result);

  return result.choices?.[0]?.message?.content || null;
}

// .................
// Render helpers
// ..................

function renderResult(data) {
  const contentEl = document.getElementById("content");
  const verdictClass = verdictToClass(data.warningCount);
  const verdictIcon  = verdictToIcon(data.warningCount);

  let html = `
    <div class="verdict-banner ${verdictClass}">
      <div class="verdict-dot"></div>
      <div class="verdict-text">
        <div class="verdict-label">${verdictIcon} ${escHtml(data.verdict)}</div>
        <div class="verdict-sub">${data.warningCount} warning${data.warningCount !== 1 ? "s" : ""} detected</div>
      </div>
    </div>
  `;

  const tableFindings = (data.findings || []).filter(f => f.severity !== "BLOCK");

  if (tableFindings.length > 0) {
    html += `<div class="section-title">Check Results</div><div class="findings">`;
    for (const f of tableFindings) {
      const cls = f.severity.toLowerCase();
      const tip = escHtml(getTip(f.label));
      html += `
        <div class="finding-row">
          <div class="finding-label-wrap">
            <button class="tip-btn" data-tip="${tip}" aria-label="What does this mean?">i</button>
            <span class="finding-label">${escHtml(f.label)}</span>
          </div>
          <span class="finding-value ${cls}">${escHtml(f.value)}</span>
        </div>
      `;
    }
    html += `</div>`;
  }

  contentEl.innerHTML = html;
  
  // After: contentEl.innerHTML = html;
// then asynchronously fetch and inject the AI summary

fetchAISummary(data).then(summaryText => {
  if (summaryText) {
    const summaryBox = document.createElement("div");
    summaryBox.className = "ai-summary-box";
    summaryBox.innerHTML = `
      <div class="ai-summary-title">🤖 AI Analysis Summary</div>
      <div class="ai-summary-text">${escHtml(summaryText)}</div>
    `;
    document.getElementById("content").appendChild(summaryBox);
  }
}).catch(() => {
  // silently fail if Gemini is unavailable
});
}

function renderBlocked(url) {
  document.getElementById("content").innerHTML = `
    <div class="verdict-banner blocked">
      <div class="verdict-dot"></div>
      <div class="verdict-text">
        <div class="verdict-label">✕ Page Blocked</div>
        <div class="verdict-sub">This URL was flagged as HIGH RISK and blocked.</div>
      </div>
    </div>
    <div style="height:14px"></div>
  `;
}

function renderMessage(icon, title, sub) {
  document.getElementById("content").innerHTML = `
    <div class="verdict-banner loading">
      <div class="verdict-dot"></div>
      <div class="verdict-text">
        <div class="verdict-label">${icon} ${title}</div>
        <div class="verdict-sub">${sub}</div>
      </div>
    </div>
    <div style="height:14px"></div>
  `;
}

function renderError(message) {
  document.getElementById("content").innerHTML = `
    <div class="verdict-banner error">
      <div class="verdict-dot"></div>
      <div class="verdict-text">
        <div class="verdict-label">⚠ Backend unreachable</div>
        <div class="verdict-sub">${escHtml(message)}</div>
      </div>
    </div>
    <div style="height:14px"></div>
  `;
}

function verdictToClass(warningCount) {
  if (warningCount === 0) return "safe";
  if (warningCount <= 2)  return "warn";
  return "danger";
}

function verdictToIcon(warningCount) {
  if (warningCount === 0) return "✓";
  if (warningCount <= 2)  return "⚠";
  return "✕";
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
