<div align="center">

<!-- Logo / ASCII banner -->
<pre style="font-family: monospace; color: #e8187c;">
 ███████╗██████╗ ██╗██████╗ ██╗  ██╗██╗███████╗██╗  ██╗
 ██╔════╝██╔══██╗██║██╔══██╗██║  ██║██║██╔════╝██║  ██║
 █████╗  ██████╔╝██║██████╔╝███████║██║███████╗███████║
 ██╔══╝  ██╔══██╗██║██╔═══╝ ██╔══██║██║╚════██║██╔══██║
 ███████╗██████╔╝██║██║     ██║  ██║██║███████║██║  ██║
 ╚══════╝╚═════╝ ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝
</pre>

# EBIPhish — Evidence-Based Inspection for Phishing

**A real-time, multi-layer phishing URL detection system**  
Chrome Extension · Java Spring Boot · AI-Powered Analysis


</div>


## What is EBIPhish?

**EBIPhish** is a browser-integrated phishing detection system that analyzes any URL in real time using five independent evidence layers, before you ever click. It combines classical heuristics with AI-generated explanations to give users both a verdict and a reason.

> *"Phishing remains the #1 initial attack vector — 36% of all breaches begin with it."*  
> — Verizon DBIR 2025

---

## Features

| Feature | Description |
|---|---|
| 🔴 **Real-time detection** | Analyzes the current tab's URL instantly and shows results on popup open |
| 🧠 **AI summary** | Groq (Llama 3.1 8B) generates a plain-language explanation of the verdict |
| 🛡️ **5-layer analysis** | Each URL passes through five independent inspection modules |
| 🎨 **Aesthetic UI** | Dark popup with pink accent, Space Mono + Syne typography |
| ⚡ **Lightweight** | All analysis runs server-side |

---

## Detection Layers

EBIPhish evaluates every URL through five independent modules:

```
Layer 1 — 🗂️  Blacklist Feeds        OpenPhish + Google Safe Browsing (also applied to external links)
Layer 2 — 🔐  SSL/TLS Inspection     Certificate validity, issuer, age
Layer 3 — 🕐  WHOIS Domain Age       Newly registered domains flagged
Layer 4 — 🔠  Unicode / Homoglyph    Detects lookalike character attacks (e.g. pаypal.com) (also applied to external links)
Layer 5 — 🧮  Structural Heuristics  URL length, subdomains, suspicious tokens, IP-based hosts
```

Results are aggregated into one of three verdicts:

| Verdict | Meaning |
|---|---|
| ✅ **Likely Safe** | No phishing signals detected across layers |
| ⚠️ **Suspicious** | One or more phishing signals detected |
| 🚨 **High Risk** | Strong indicators of phishing |

---

## Getting Started

### Prerequisites

- Java 17+
- Maven
- Google Chrome

---

### 1. Start the Backend

```bash
cd url-phishing-detector
mvn spring-boot:run
```

The backend starts on `http://localhost:8080`.

---

### 2. Load the Extension in Chrome

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `phishing-extension/` folder

---

### 3. Use It

Click the EBIPhish icon in your Chrome toolbar while on any webpage.  
The popup will analyze the current URL and display a verdict with an AI-generated explanation.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Browser Extension | HTML/CSS, JavaScript, Chrome Extensions Manifest V3 |
| Backend | Java 17, Spring Boot |
| AI / LLM | Groq Cloud API — Llama 3.1 8B Instant |
| Blacklists | OpenPhish Feed, Google Safe Browsing API |
| Domain Intel | WHOIS API from API Ninjas |

---

## Academic Context

EBIPhish was developed as a **B.Sc. Graduation Project** at the  
**University of New York Tirana — Faculty of Engineering and Architecture**, June 2026 .

The project contributes to the applied cybersecurity domain by combining evidence-based multi-layer inspection with AI-assisted user communication — addressing the gap between detection accuracy and user comprehension in anti-phishing tools.

