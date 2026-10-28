# LinkLens — Suspicious Link Awareness Checker

> **Tagline:** *"Pause before you click."*

LinkLens is a Google-inspired, client-side cybersecurity utility that inspects suspicious URLs before users click them. It deconstructs URL components, identifies deceptive structural patterns, computes a transparent heuristic risk score (0–100), and presents actionable security recommendations—all entirely within the browser.

---

## 1. Core Principles & Privacy Safeguards

- **Zero-Network Local Processing:** LinkLens never fetches, opens, previews, or establishes a network socket to any submitted link.
- **Privacy First:** No URLs, parameters, or scan logs are transmitted to external servers, cloud databases, or third-party APIs.
- **Sensitive Data Redaction:** Credentials embedded in user-info authority segments (`user:pass@`) and sensitive authentication tokens in query parameters are masked and redacted from reports.
- **Honest Communication of Uncertainty:** Detecting no warning signs does **not** prove a website is safe. LinkLens explicitly communicates the boundaries of static structural heuristics.

---

## 2. Technology Stack

- **HTML5:** Semantic, accessible page layout with WCAG-compliant landmarks.
- **CSS3:** Custom property design tokens, dark/light theme switching, responsive grid, and fluid typography.
- **Vanilla JavaScript (ES Modules):** Clean, modular application code without heavy framework overhead.
- **Vite:** High-performance local development server and optimized production bundler.
- **tldts:** Public-suffix-aware registrable domain, subdomain, and TLD extraction.
- **Vitest:** Automated unit and regression test suite.

---

## 3. Architecture

```
linklens/
├── index.html                   # Semantic single-page layout
├── package.json                 # Project dependencies & scripts
├── vite.config.js               # Bundler & test configuration
├── README.md                    # System documentation
├── src/
│   ├── main.js                  # Application controller & event wiring
│   ├── styles/
│   │   └── main.css             # Google-inspired design tokens & styles
│   ├── analyzer/
│   │   ├── parseUrl.js          # Normalization & standard URL / tldts parsing
│   │   ├── detectSignals.js     # 11 isolated structural heuristic detectors
│   │   ├── scoreRisk.js         # Configurable scoring & verdict thresholds
│   │   └── analyzeUrl.js        # Central pipeline coordinator & limitations
│   ├── ui/
│   │   ├── renderReport.js      # Results report, circular gauge, findings cards
│   │   ├── scanAnimation.js     # Radar & moving-beam 5-stage pipeline animation
│   │   ├── theme.js             # Light/dark mode manager with persistence
│   │   └── notifications.js     # Accessible toast alerts
│   ├── utils/
│   │   ├── dom.js               # DOM query, element helpers, copy fallback
│   │   └── redaction.js         # Credential masking & query parameter sanitization
│   └── data/
│       └── sampleUrls.js        # RFC 2606 / RFC 5737 safe demonstration patterns
└── tests/
    ├── parseUrl.test.js         # URL parsing & scheme rejection tests
    ├── detectSignals.test.js    # Signal detection unit tests
    ├── scoreRisk.test.js        # Scoring algorithm & verdict tests
    └── analyzeUrl.test.js       # End-to-end analyzer test suite
```

---

## 4. Detection Signals & Heuristics

LinkLens analyzes 11 distinct structural signals:

| # | Signal | Severity | Default Weight | Description |
|---|---|---|---|---|
| 1 | **User-Info Deception (`@`)** | High | 35 | Detects credentials or brand masquerading placed before the `@` symbol, which browsers ignore when contacting the host. |
| 2 | **IP-Address Host** | Moderate | 20 | Identifies direct IPv4 and IPv6 literal destinations commonly used to bypass domain reputation systems. |
| 3 | **Punycode Hostname (`xn--`)** | Moderate | 15 | Detects Internationalized Domain Names (IDN) that may facilitate Cyrillic/Greek homoglyph impersonation. |
| 4 | **Hostname Complexity** | Moderate / Low | 10–15 | Flags deep subdomain nesting (≥ 3 levels) mimicking security login paths or verification portals. |
| 5 | **Known URL Shorteners** | Moderate | 20 | Matches registrable domains against known shortening services (`bit.ly`, `tinyurl.com`, `t.co`, etc.) that conceal destinations. |
| 6 | **Redirect Parameters** | Moderate / Low | 10–20 | Inspects parameters (`url`, `redirect`, `dest`, `next`) containing potential external redirect URLs. |
| 7 | **URL Percent-Encoding** | Moderate / Low | 10–15 | Detects double-encoding (`%25xx`) or excessive encoding used to evade basic string filters. |
| 8 | **Suspicious Wording** | Low | 10 | Identifies contextual urgency and credential patterns (`verify`, `urgent`, `recover-access`) in paths and subdomains. |
| 9 | **Unencrypted HTTP** | Informational | 5 | Flags plain `http:` connections lacking transport-layer encryption. |
| 10 | **Length & Complexity** | Informational | 5 | Identifies excessively long URLs (> 255 chars) or deeply nested path hierarchies (> 7 segments). |
| 11 | **Local / Private Subnets** | Informational | 10 | Flags localhost, loopback, or private RFC 1918 addresses not reachable on the public internet. |

---

## 5. Risk Scoring & Verdicts

Scores range from **0 to 100**, capped strictly at 100:

- **0–24: No Obvious Warning Signs Detected**  
  *Visual:* Neutral slate grey.  
  *Meaning:* No structural red flags were found in the URL syntax. **Note:** This is not proof of safety.
- **25–54: Some Warning Signs**  
  *Visual:* Amber status.  
  *Meaning:* Non-standard elements detected (such as shortened destinations or redirect parameters).
- **55–100: High Concern**  
  *Visual:* Red status.  
  *Meaning:* Significant deceptive indicators detected (e.g. `@` authority masquerade, direct IP targets, or multiple combined indicators).

---

## 6. Installation & Commands

### Prerequisites
Node.js 18+ and npm.

### Install Dependencies
```bash
npm install
```

### Run Unit Tests
```bash
npm run test
```

### Launch Development Server
```bash
npm run dev
```

### Build Production Bundle
```bash
npm run build
```

---

## 7. Scope & Limitations

Version 1 operates purely on client-side structural heuristics. Explicit limitations include:
1. **No External Threat Feeds:** Does not query live commercial blacklist APIs or malware databases.
2. **Content-Unaware:** Does not download, inspect, or execute destination HTML, JavaScript, or binaries.
3. **No Domain Age Check:** Does not perform live WHOIS or DNS lookups.
4. **No SSL/TLS Validation:** Does not inspect live certificate chains or validity.
5. **Heuristic Nature:** Scores represent structural deviation and anomaly density, not statistically calibrated probabilities of malware.
