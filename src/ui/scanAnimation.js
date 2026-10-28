/**
 * Manages the tactical cyber URL scanning animation and telemetry pipeline.
 * Performs real local URL analysis across 5 sequential diagnostic stages.
 */

import { parseUrl } from '../analyzer/parseUrl.js';
import { detectAllSignals } from '../analyzer/detectSignals.js';
import { calculateRiskScore } from '../analyzer/scoreRisk.js';
import { CHECKS_PERFORMED, EXPLICIT_LIMITATIONS } from '../analyzer/analyzeUrl.js';

export const SCAN_STAGES = [
  { id: 'stage-parse', label: 'Reading the URL' },
  { id: 'stage-host', label: 'Checking its structure' },
  { id: 'stage-patterns', label: 'Inspecting suspicious patterns' },
  { id: 'stage-risk', label: 'Calculating risk indicators' },
  { id: 'stage-report', label: 'Preparing the report' }
];

let activeScanId = 0;

export function prefersReducedMotion() {
  return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

export function renderScanUI(container, targetUrl) {
  container.innerHTML = `
    <div class="tactical-scan-screen" role="status" aria-live="polite">
      <!-- Top HUD Telemetry Row -->
      <div class="scan-hud-top-bar">
        <span class="scan-status-alert">
          <span class="status-beacon"></span>
          Analyzing locally in your browser
        </span>
        <span class="scan-telemetry-percent" id="scan-percentage-text">0%</span>
      </div>

      <!-- Radar HUD Reticle with Rotating Scan Ring & Core Lens/Shield -->
      <div class="tactical-radar-chamber" aria-hidden="true">
        <div class="radar-outer-grid"></div>
        <div class="radar-crosshair-x"></div>
        <div class="radar-crosshair-y"></div>
        <div class="radar-scan-ring"></div>
        <div class="radar-sweep-beam"></div>
        <div class="radar-center-core">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <circle cx="12" cy="11" r="3"></circle>
          </svg>
        </div>
      </div>

      <!-- Laser Scan Target Box -->
      <div class="laser-target-preview">
        <div class="laser-target-label">// URL INSPECTION STREAM</div>
        <div class="laser-target-scroll">
          <span class="laser-target-text">${escapeText(targetUrl)}</span>
        </div>
        <div class="laser-scan-beam" aria-hidden="true"></div>
      </div>

      <!-- Linear Diagnostic Progress Bar -->
      <div class="diagnostic-bar-track" aria-hidden="true">
        <div class="diagnostic-bar-fill" id="scan-progress-fill" style="width: 0%;"></div>
      </div>

      <!-- Sequential Terminal Pipeline Stream -->
      <div class="scan-pipeline-stream" id="scan-pipeline-list">
        ${SCAN_STAGES.map((stage, idx) => `
          <div class="pipeline-step-node pending" id="stage-row-${idx}">
            <div class="step-label-group">
              <span class="step-index">0${idx + 1}</span>
              <span class="step-text">${stage.label}</span>
            </div>
            <span class="step-status-chip">[ PENDING ]</span>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

export function startScanPipeline(rawInput, container, onComplete, onError) {
  const currentId = ++activeScanId;
  const isReduced = prefersReducedMotion();
  const stepDelay = isReduced ? 0 : 85;

  renderScanUI(container, rawInput);

  const fillEl = container.querySelector('#scan-progress-fill');
  const percentEl = container.querySelector('#scan-percentage-text');

  const updateStageUI = (index, state, statusText) => {
    const row = container.querySelector(`#stage-row-${index}`);
    if (!row) return;

    row.classList.remove('pending', 'active', 'completed', 'error');
    row.classList.add(state);

    const chip = row.querySelector('.step-status-chip');
    if (chip) chip.textContent = statusText;

    const percent = Math.min(100, Math.round(((index + (state === 'completed' ? 1 : 0.5)) / SCAN_STAGES.length) * 100));
    if (fillEl) fillEl.style.width = `${percent}%`;
    if (percentEl) percentEl.textContent = `${percent}%`;
  };

  const delay = (ms) => ms > 0 ? new Promise((resolve) => setTimeout(resolve, ms)) : Promise.resolve();

  (async () => {
    try {
      // Stage 1: Reading the URL
      updateStageUI(0, 'active', '[ READING ]');
      if (stepDelay > 0) await delay(stepDelay);
      if (activeScanId !== currentId) return;

      const parsed = parseUrl(rawInput);
      if (!parsed.isValid) {
        updateStageUI(0, 'error', '[ REJECTED ]');
        onError(parsed.error || 'Failed to parse URL.');
        return;
      }
      updateStageUI(0, 'completed', '[ OK: READ ]');

      // Stage 2: Checking its structure
      updateStageUI(1, 'active', '[ CHECKING ]');
      if (stepDelay > 0) await delay(stepDelay);
      if (activeScanId !== currentId) return;
      const hostLabel = parsed.hostname.length > 20 ? `${parsed.hostname.slice(0, 18)}...` : parsed.hostname;
      updateStageUI(1, 'completed', `[ HOST: ${hostLabel} ]`);

      // Stage 3: Inspecting suspicious patterns
      updateStageUI(2, 'active', '[ INSPECTING ]');
      if (stepDelay > 0) await delay(stepDelay);
      if (activeScanId !== currentId) return;
      const findings = detectAllSignals(parsed);
      updateStageUI(2, 'completed', `[ ${findings.length} WARNING${findings.length === 1 ? '' : 'S'} ]`);

      // Stage 4: Calculating risk indicators
      updateStageUI(3, 'active', '[ CALCULATING ]');
      if (stepDelay > 0) await delay(stepDelay);
      if (activeScanId !== currentId) return;
      const { score, verdict, breakdown } = calculateRiskScore(findings);
      updateStageUI(3, 'completed', `[ RISK: ${score}/100 ]`);

      // Stage 5: Preparing the report
      updateStageUI(4, 'active', '[ PREPARING ]');
      if (stepDelay > 0) await delay(stepDelay);
      if (activeScanId !== currentId) return;
      updateStageUI(4, 'completed', '[ COMPLETE ]');

      if (fillEl) fillEl.style.width = '100%';
      if (percentEl) percentEl.textContent = '100%';

      if (stepDelay > 0) await delay(isReduced ? 0 : 75);
      if (activeScanId !== currentId) return;

      const finalReport = {
        isValid: true,
        rawInput: parsed.rawInput,
        normalizedUrl: parsed.normalizedUrl,
        parsed: {
          scheme: parsed.scheme,
          assumedScheme: parsed.assumedScheme,
          hostname: parsed.hostname,
          port: parsed.port || (parsed.scheme === 'https:' ? '443 (default)' : '80 (default)'),
          pathname: parsed.pathname || '/',
          search: parsed.search || '',
          hash: parsed.hash || '',
          searchParams: parsed.searchParams,
          hasUserInfo: parsed.hasUserInfo,
          username: parsed.username || '',
          password: parsed.password || '',
          registrableDomain: parsed.registrableDomain,
          subdomain: parsed.subdomain,
          publicSuffix: parsed.publicSuffix,
          isIp: parsed.isIp,
          isIpv4: parsed.isIpv4,
          isIpv6: parsed.isIpv6,
          isPunycode: parsed.isPunycode,
          isLocalOrPrivate: parsed.isLocalOrPrivate
        },
        findings,
        score,
        verdict,
        scoreBreakdown: breakdown,
        checksPerformed: CHECKS_PERFORMED,
        explicitLimitations: EXPLICIT_LIMITATIONS,
        timestamp: new Date().toISOString()
      };

      onComplete(finalReport);
    } catch (err) {
      if (activeScanId === currentId) {
        console.error('Scan error:', err);
        onError('An error occurred during local URL parsing.');
      }
    }
  })();

  return currentId;
}

export function cancelActiveScan() {
  activeScanId++;
}

function escapeText(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
