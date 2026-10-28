/**
 * LinkLens — Security Report Renderer
 * Clean, readable, and actionable cyber threat analysis report.
 */

import { copyToClipboard } from '../utils/dom.js';
import { escapeHtml, sanitizeQueryParams, redactUrlCredentials } from '../utils/redaction.js';
import { showToast } from './notifications.js';

export function renderEmptyState(container) {
  container.innerHTML = `
    <div class="standby-chamber">
      <div class="standby-radar-target" aria-hidden="true">
        <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="22" y1="12" x2="18" y2="12"></line>
          <line x1="6" y1="12" x2="2" y2="12"></line>
          <line x1="12" y1="6" x2="12" y2="2"></line>
          <line x1="12" y1="22" x2="12" y2="18"></line>
        </svg>
      </div>
      <h3 class="standby-title">RADAR READY</h3>
      <p class="standby-desc">
        Paste a link on the left to inspect its structure. LinkLens will check for deceptive authority, IP hosts, punycode lookalikes, and redirect traps locally in your browser.
      </p>
      <div class="standby-specs-row">
        <span class="spec-badge">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          100% Client-Side
        </span>
        <span class="spec-badge">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          Analyzed Locally
        </span>
        <span class="spec-badge">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          No External Lookup
        </span>
      </div>
    </div>
  `;
}

export function renderReport(container, report) {
  const { score, verdict, parsed, checksPerformed = [], explicitLimitations = [] } = report;

  // Prioritize findings by weight descending
  const findings = [...(report.findings || [])].sort((a, b) => (b.weight || 0) - (a.weight || 0));

  const threatClass = verdict.code === 'HIGH_CONCERN'
    ? 'threat-high'
    : verdict.code === 'SOME_WARNINGS'
      ? 'threat-moderate'
      : 'threat-low';

  const plainVerdictText = verdict.code === 'HIGH_CONCERN'
    ? 'High concern — several suspicious signs detected.'
    : verdict.code === 'SOME_WARNINGS'
      ? 'Some warning signs — review this link carefully.'
      : 'No obvious warning signs detected — this does not guarantee safety.';

  const sanitizedQuery = parsed.searchParams ? sanitizeQueryParams(parsed.searchParams) : [];
  const safeRedactedUrl = redactUrlCredentials(report.rawInput || report.normalizedUrl || '');

  // Highlighted URL breakdown representation
  const highlightedUrl = buildSyntaxHighlightedUrl(parsed);

  // Recommendations tailored to findings
  const recommendedActions = getRecommendedActions(findings, parsed);

  // Check encoding observations
  const encodingNote = getEncodingObservation(report.rawInput || '');

  container.innerHTML = `
    <div class="results-dossier-screen">
      
      <!-- 1. OVERALL RESULT -->
      <section class="threat-verdict-box ${threatClass}" aria-label="Overall analysis result">
        <div class="threat-top-row">
          <div class="threat-title-group">
            <div class="threat-banner-badge">${escapeHtml(verdict.label.toUpperCase())}</div>
            <h2 class="threat-verdict-heading">${escapeHtml(plainVerdictText)}</h2>
            <div class="threat-target-host">
              <span class="host-label">HOST:</span>
              <span class="host-value">${escapeHtml(parsed.hostname)}</span>
            </div>
            <p class="threat-summary-text">${escapeHtml(verdict.summary)}</p>
            <p class="threat-limitation-note">
              <strong>Scope notice:</strong> Analyzed locally in your browser. Live server content, real-time threat blacklists, and SSL certificates were not checked.
            </p>
          </div>

          <!-- Risk Score Gauge -->
          <div class="threat-gauge-cluster" aria-label="Heuristic risk score: ${score} out of 100">
            <div class="gauge-svg-wrapper">
              <svg viewBox="0 0 100 100" width="88" height="88" aria-hidden="true">
                <circle class="gauge-circle-bg" cx="50" cy="50" r="40" stroke-width="7" />
                <circle class="gauge-circle-meter" id="gauge-circle-meter" cx="50" cy="50" r="40" stroke-width="7"
                  stroke-dasharray="251.3"
                  stroke-dashoffset="251.3"
                />
              </svg>
              <div class="gauge-digital-readout">
                <span class="gauge-number" id="gauge-animated-num">0</span>
                <span class="gauge-sublabel">/ 100</span>
              </div>
            </div>
            <div class="gauge-caption">RISK SCORE</div>
          </div>
        </div>

        <!-- Quick Action Buttons Bar -->
        <div class="report-action-bar">
          <button type="button" class="btn-report-action" id="btn-copy-url" title="Copy clean URL to clipboard">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
            </svg>
            <span>Copy URL</span>
          </button>

          <button type="button" class="btn-report-action" id="btn-copy-report" title="Copy full security report to clipboard">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <rect width="14" height="14" x="8" y="8" rx="2" ry="2"></rect>
              <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"></path>
            </svg>
            <span>Copy Report</span>
          </button>
        </div>
      </section>

      <!-- 2. MOST IMPORTANT WARNING SIGNS -->
      <section class="report-section" aria-label="Warning signs">
        <div class="tactical-section-label section-header-row">
          <span>Warning signs (${findings.length})</span>
          ${findings.length > 0 ? `
            <button type="button" class="btn-collapse-toggle" id="btn-toggle-findings" aria-expanded="true">
              Collapse all
            </button>
          ` : ''}
        </div>

        ${findings.length > 0 ? `
          <div class="findings-dossier-list" id="findings-dossier-list">
            ${findings.map((f, idx) => renderDossierCard(f, idx)).join('')}
          </div>
        ` : `
          <div class="clean-dossier-box">
            <div class="clean-dossier-icon" aria-hidden="true">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--threat-nominal)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                <polyline points="9 12 11 14 15 10"></polyline>
              </svg>
            </div>
            <div class="clean-dossier-body">
              <h4>No Obvious Warning Signs Detected</h4>
              <p>
                LinkLens evaluated <strong>${checksPerformed.length} structural heuristic checks</strong> and detected zero authority deceptions, raw IP literal destinations, homoglyph punycode labels, or suspicious redirect parameters.
              </p>
              <p class="clean-dossier-disclaimer">
                <strong>Important:</strong> Absence of structural warning signs does not guarantee that this link is safe. Compromised legitimate websites and live malicious downloads cannot be identified through URL structure alone. Always verify the sender before entering credentials.
              </p>
              <details class="checks-performed-disclosure">
                <summary class="checks-summary-toggle">View all ${checksPerformed.length} checks performed</summary>
                <ul class="checks-list">
                  ${checksPerformed.map(c => `<li>${escapeHtml(c)}</li>`).join('')}
                </ul>
              </details>
            </div>
          </div>
        `}
      </section>

      <!-- 3. RECOMMENDED ACTIONS -->
      <section class="report-section" aria-label="Recommended actions">
        <div class="tactical-section-label">
          <span>Recommended actions</span>
        </div>
        <div class="recommendations-card">
          <ul class="recommendations-list">
            ${recommendedActions.map(act => `
              <li class="recommendation-item">
                <span class="recommendation-icon" aria-hidden="true">${act.icon}</span>
                <div class="recommendation-text-group">
                  <strong>${escapeHtml(act.title)}</strong>
                  <span>${escapeHtml(act.text)}</span>
                </div>
              </li>
            `).join('')}
          </ul>
        </div>
      </section>

      <!-- 4. EXPANDABLE TECHNICAL URL DETAILS -->
      <section class="report-section" aria-label="Technical URL details">
        <details class="technical-details-panel" id="technical-details-panel">
          <summary class="technical-details-header">
            <div class="tech-header-left">
              <span class="tech-toggle-icon">▶</span>
              <span class="tech-title">URL details</span>
              <span class="tech-sublabel">// breakdown & attributes</span>
            </div>
            <span class="tech-badge">[ Technical breakdown ]</span>
          </summary>
          
          <div class="technical-details-body">
            <!-- Syntax Highlighted Deconstructed URL Block -->
            <div class="deconstructed-url-wrapper">
              <div class="deconstructed-label">// STRUCTURED_SYNTAX_BREAKDOWN</div>
              <div class="deconstructed-url-block">
                <div class="deconstructed-url-content">
                  ${highlightedUrl}
                </div>
              </div>
            </div>

            <!-- Attribute Matrix -->
            <div class="tech-matrix-grid">
              <div class="tech-matrix-row">
                <span class="matrix-key">Scheme / Protocol:</span>
                <span class="matrix-val"><code>${escapeHtml(parsed.scheme)}</code> ${parsed.assumedScheme ? '<em class="dim-note">(Assumed HTTPS)</em>' : ''}</span>
              </div>
              <div class="tech-matrix-row">
                <span class="matrix-key">Destination Host:</span>
                <span class="matrix-val"><code>${escapeHtml(parsed.hostname)}</code></span>
              </div>
              <div class="tech-matrix-row">
                <span class="matrix-key">Registrable Domain:</span>
                <span class="matrix-val"><code>${escapeHtml(parsed.registrableDomain || 'N/A')}</code></span>
              </div>
              <div class="tech-matrix-row">
                <span class="matrix-key">Subdomain:</span>
                <span class="matrix-val"><code>${escapeHtml(parsed.subdomain || 'None (root)')}</code></span>
              </div>
              <div class="tech-matrix-row">
                <span class="matrix-key">Public Suffix (TLD):</span>
                <span class="matrix-val"><code>${escapeHtml(parsed.publicSuffix || 'Internal/IP')}</code></span>
              </div>
              <div class="tech-matrix-row">
                <span class="matrix-key">Port:</span>
                <span class="matrix-val"><code>${escapeHtml(String(parsed.port))}</code></span>
              </div>
              <div class="tech-matrix-row">
                <span class="matrix-key">Path:</span>
                <span class="matrix-val"><code>${escapeHtml(parsed.pathname || '/')}</code></span>
              </div>
              <div class="tech-matrix-row">
                <span class="matrix-key">Encoding Observation:</span>
                <span class="matrix-val">${escapeHtml(encodingNote)}</span>
              </div>
              <div class="tech-matrix-row">
                <span class="matrix-key">Authority Credentials (@):</span>
                <span class="matrix-val">${parsed.hasUserInfo ? '<span class="status-alert-text">DETECTED (REDACTED)</span>' : '<span class="status-ok-text">None</span>'}</span>
              </div>
              <div class="tech-matrix-row">
                <span class="matrix-key">Query Parameters (${sanitizedQuery.length}):</span>
                <div class="matrix-val">
                  ${sanitizedQuery.length === 0 ? '<span class="status-ok-text">None</span>' : `
                    <ul class="matrix-params-list">
                      ${sanitizedQuery.map(q => `
                        <li><code>${escapeHtml(q.key)}</code>: <span class="param-val">${escapeHtml(q.summary)}</span></li>
                      `).join('')}
                    </ul>
                  `}
                </div>
              </div>
            </div>
          </div>
        </details>
      </section>

    </div>
  `;

  // Attach interactions and animate gauge
  setupReportInteractions(container, report, safeRedactedUrl);
  animateGauge(container, score);
}

function renderDossierCard(finding, index) {
  const sevKey = finding.severity === 'High'
    ? 'sev-high'
    : finding.severity === 'Moderate'
      ? 'sev-moderate'
      : finding.severity === 'Low'
        ? 'sev-low'
        : 'sev-info';

  // Details collapsed by default if explanation or evidence is lengthy
  const isLengthy = (finding.explanation && finding.explanation.length > 110) || (finding.evidence && finding.evidence.length > 70);
  const collapsedClass = isLengthy ? 'collapsed' : '';

  return `
    <article class="dossier-card ${sevKey} ${collapsedClass}" id="dossier-card-${index}">
      <header class="dossier-header" data-toggle-index="${index}" role="button" tabindex="0" aria-expanded="${!isLengthy}">
        <div class="dossier-title-row">
          <span class="dossier-sev-tag">${escapeHtml(finding.severity)}</span>
          <h4 class="dossier-title">${escapeHtml(finding.title)}</h4>
        </div>
        <div class="dossier-header-right">
          <span class="dossier-weight">+${finding.weight} pts</span>
          <span class="dossier-chevron" aria-hidden="true">▾</span>
        </div>
      </header>
      <div class="dossier-body" id="dossier-body-${index}">
        <div class="dossier-field">
          <span class="field-label">Observed evidence:</span>
          <code class="field-evidence">${escapeHtml(finding.evidence)}</code>
        </div>
        <div class="dossier-field">
          <span class="field-label">Threat explanation:</span>
          <span class="field-desc">${escapeHtml(finding.explanation)}</span>
        </div>
        <div class="dossier-field">
          <span class="field-label">Recommended action:</span>
          <span class="field-action">${escapeHtml(finding.recommendation)}</span>
        </div>
      </div>
    </article>
  `;
}

function buildSyntaxHighlightedUrl(parsed) {
  const scheme = `<span class="token-scheme">${escapeHtml(parsed.scheme)}//</span>`;
  const auth = parsed.hasUserInfo
    ? `<span class="token-auth" title="Redacted authority credentials">${escapeHtml(parsed.username ? parsed.username + '@' : 'user:***@')}</span>`
    : '';
  const host = `<span class="token-host">${escapeHtml(parsed.hostname)}</span>`;
  const port = parsed.port && !parsed.port.includes('default')
    ? `<span class="token-port">:${escapeHtml(parsed.port)}</span>`
    : '';
  const path = `<span class="token-path">${escapeHtml(parsed.pathname || '/')}</span>`;
  const query = parsed.search
    ? `<span class="token-param">${escapeHtml(parsed.search)}</span>`
    : '';
  const hash = parsed.hash
    ? `<span class="token-hash">${escapeHtml(parsed.hash)}</span>`
    : '';

  return `${scheme}${auth}${host}${port}${path}${query}${hash}`;
}

function getEncodingObservation(rawInput) {
  if (/%25[0-9a-fA-F]{2}/i.test(rawInput)) {
    return 'Nested double percent-encoding (%25) detected (potential evasion indicator)';
  }
  const count = (rawInput.match(/%[0-9a-fA-F]{2}/g) || []).length;
  if (count > 6) {
    return `Extensive percent-encoding (${count} encoded sequences observed)`;
  }
  if (count > 0) {
    return `Standard percent-encoding (${count} encoded sequence${count === 1 ? '' : 's'})`;
  }
  return 'Standard ASCII characters — no percent-encoding';
}

function getRecommendedActions(findings = [], parsed = {}) {
  const actions = [];

  if (findings.length === 0) {
    actions.push({
      icon: '🛡️',
      title: 'Verify the sender and context',
      text: 'Even though local checks found no suspicious URL patterns, ensure you recognize the sender before interacting with the site or entering credentials.'
    });
    actions.push({
      icon: '🔍',
      title: 'Navigate directly when uncertain',
      text: 'For banking, corporate, or account management portals, type the organization\'s official address directly into your browser rather than clicking email or chat links.'
    });
    return actions;
  }

  // Deceptive authority prefix
  if (findings.some(f => f.id === 'user-info-deception')) {
    actions.push({
      icon: '⚠️',
      title: 'Disregard any brand name before the "@" sign',
      text: `Any name appearing before the "@" character is user credentials, not the destination server. Browsers will connect strictly to "${parsed.hostname}". Do not click this link.`
    });
  }

  // Raw IP destination
  if (findings.some(f => f.id === 'ip-host')) {
    actions.push({
      icon: '🌐',
      title: 'Avoid submitting credentials to IP addresses',
      text: 'Legitimate public services use registered domain names. Confirm who operates this server before providing passwords or confidential details.'
    });
  }

  // Punycode homoglyph
  if (findings.some(f => f.id === 'punycode-hostname')) {
    actions.push({
      icon: '🔤',
      title: 'Check for lookalike characters (Punycode)',
      text: 'This domain uses internationalized characters that can mimic standard brand spellings. Manually enter the official website name instead.'
    });
  }

  // URL Shortener
  if (findings.some(f => f.id === 'url-shortener')) {
    actions.push({
      icon: '🔗',
      title: 'Expand the shortened link before opening',
      text: 'This short link conceals its final destination. Use a link-unshortener tool to inspect the real target URL before visiting.'
    });
  }

  // Redirect parameter
  if (findings.some(f => f.id === 'redirect-parameter')) {
    actions.push({
      icon: '↗️',
      title: 'Inspect the onward redirect target',
      text: 'This URL contains an external destination parameter that may redirect you to a third-party webpage. Verify the final landing site.'
    });
  }

  // Insecure HTTP
  if (findings.some(f => f.id === 'insecure-http')) {
    actions.push({
      icon: '🔓',
      title: 'Do not enter passwords over unencrypted HTTP',
      text: 'Unencrypted HTTP sends information in plain text across the network. Avoid providing sensitive personal or financial information.'
    });
  }

  // Urgency keywords or deep subdomains
  if (findings.some(f => f.id === 'suspicious-wording' || f.id === 'hostname-complexity')) {
    actions.push({
      icon: '🏷️',
      title: 'Focus strictly on the root domain',
      text: `Verify that "${parsed.registrableDomain || parsed.hostname}" is the legitimate organization you intended to visit, ignoring deceptive subdomains or urgency words.`
    });
  }

  // Fallback general recommendation
  if (actions.length < 2) {
    actions.push({
      icon: '🏢',
      title: 'Use official websites reached through trusted bookmarks',
      text: 'When in doubt, avoid clicking unexpected links in messages. Reach the service directly through a bookmark or official search result.'
    });
  }

  return actions;
}

function setupReportInteractions(container, report, safeRedactedUrl) {
  // Individual card accordion toggles
  const headers = container.querySelectorAll('.dossier-header[data-toggle-index]');
  headers.forEach(h => {
    const handleToggle = () => {
      const idx = h.getAttribute('data-toggle-index');
      const card = container.querySelector(`#dossier-card-${idx}`);
      if (card) {
        const isCollapsed = card.classList.toggle('collapsed');
        h.setAttribute('aria-expanded', String(!isCollapsed));
      }
    };

    h.addEventListener('click', handleToggle);
    h.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        handleToggle();
      }
    });
  });

  // Toggle all findings
  const toggleBtn = container.querySelector('#btn-toggle-findings');
  if (toggleBtn) {
    let allCollapsed = false;
    toggleBtn.addEventListener('click', () => {
      allCollapsed = !allCollapsed;
      toggleBtn.textContent = allCollapsed ? 'Expand all' : 'Collapse all';
      toggleBtn.setAttribute('aria-expanded', String(!allCollapsed));
      const cards = container.querySelectorAll('.dossier-card');
      cards.forEach(c => {
        c.classList.toggle('collapsed', allCollapsed);
        const header = c.querySelector('.dossier-header');
        if (header) header.setAttribute('aria-expanded', String(!allCollapsed));
      });
    });
  }

  // Copy URL button
  const copyUrlBtn = container.querySelector('#btn-copy-url');
  if (copyUrlBtn) {
    copyUrlBtn.addEventListener('click', async () => {
      const success = await copyToClipboard(safeRedactedUrl);
      if (success) {
        showToast('Clean URL copied to clipboard', 'success');
      } else {
        showToast('Clipboard access denied', 'error');
      }
    });
  }

  // Copy Report button
  const copyReportBtn = container.querySelector('#btn-copy-report');
  if (copyReportBtn) {
    copyReportBtn.addEventListener('click', async () => {
      const text = generateReportText(report, safeRedactedUrl);
      const success = await copyToClipboard(text);
      if (success) {
        showToast('Security report copied to clipboard', 'success');
      } else {
        showToast('Clipboard access denied', 'error');
      }
    });
  }

  // Technical details panel disclosure rotation
  const techDetails = container.querySelector('#technical-details-panel');
  if (techDetails) {
    techDetails.addEventListener('toggle', () => {
      const icon = techDetails.querySelector('.tech-toggle-icon');
      if (icon) {
        icon.textContent = techDetails.open ? '▼' : '▶';
      }
    });
  }
}

function animateGauge(container, targetScore) {
  const circle = container.querySelector('#gauge-circle-meter');
  const numberEl = container.querySelector('#gauge-animated-num');
  if (!circle || !numberEl) return;

  const circumference = 2 * Math.PI * 40; // ~251.3
  const offset = circumference - (targetScore / 100) * circumference;

  if (typeof requestAnimationFrame !== 'function') {
    if (circle.style) circle.style.strokeDashoffset = String(offset);
    numberEl.textContent = String(targetScore);
    return;
  }

  requestAnimationFrame(() => {
    circle.style.strokeDashoffset = String(offset);
  });

  const duration = 600;
  const start = performance.now();

  function tick(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    numberEl.textContent = String(Math.round(eased * targetScore));

    if (progress < 1) {
      requestAnimationFrame(tick);
    } else {
      numberEl.textContent = String(targetScore);
    }
  }

  requestAnimationFrame(tick);
}

function generateReportText(report, safeRedactedUrl) {
  const { score, verdict, parsed, findings = [], checksPerformed = [], explicitLimitations = [], timestamp } = report;

  const plainVerdictText = verdict.code === 'HIGH_CONCERN'
    ? 'High concern — several suspicious signs detected.'
    : verdict.code === 'SOME_WARNINGS'
      ? 'Some warning signs — review this link carefully.'
      : 'No obvious warning signs detected — this does not guarantee safety.';

  const recommendedActions = getRecommendedActions(findings, parsed);

  return [
    '==================================================',
    'LINKLENS SECURITY ANALYSIS REPORT',
    'Analyzed locally in your browser — zero external lookups',
    '==================================================',
    `Timestamp: ${timestamp}`,
    `Target URL: ${safeRedactedUrl}`,
    `Destination Host: ${parsed.hostname}`,
    `Registrable Root: ${parsed.registrableDomain || 'N/A'}`,
    `Scheme: ${parsed.scheme}`,
    `Path: ${parsed.pathname || '/'}`,
    '--------------------------------------------------',
    `VERDICT: ${plainVerdictText}`,
    `HEURISTIC RISK SCORE: ${score} / 100`,
    `Summary: ${verdict.summary}`,
    '--------------------------------------------------',
    `WARNING SIGNS DETECTED (${findings.length}):`,
    findings.length === 0
      ? '  • None detected. No common deceptive structural patterns were identified.'
      : findings.map((f, idx) => [
          `  ${idx + 1}. [${f.severity}] ${f.title} (+${f.weight} pts)`,
          `     Evidence: ${f.evidence}`,
          `     Explanation: ${f.explanation}`,
          `     Action: ${f.recommendation}`
        ].join('\n')).join('\n\n'),
    '--------------------------------------------------',
    'RECOMMENDED ACTIONS:',
    recommendedActions.map((a, idx) => `  ${idx + 1}. ${a.title}: ${a.text}`).join('\n'),
    '--------------------------------------------------',
    `CHECKS PERFORMED (${checksPerformed.length}):`,
    checksPerformed.map(c => `  - ${c}`).join('\n'),
    '--------------------------------------------------',
    'ANALYSIS LIMITATIONS & SCOPE:',
    explicitLimitations.map(l => `  * ${l}`).join('\n'),
    '=================================================='
  ].join('\n');
}
