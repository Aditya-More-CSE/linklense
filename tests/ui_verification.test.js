import { describe, it, expect } from 'vitest';
import { SAMPLE_URLS } from '../src/data/sampleUrls.js';
import { SCAN_STAGES } from '../src/ui/scanAnimation.js';
import { analyzeUrl, CHECKS_PERFORMED } from '../src/analyzer/analyzeUrl.js';
import { renderReport, renderEmptyState } from '../src/ui/renderReport.js';

function createMockContainer() {
  return {
    _html: '',
    set innerHTML(val) {
      this._html = val;
    },
    get innerHTML() {
      return this._html;
    },
    querySelector(selector) {
      // Basic mock for test assertions
      if (this._html.includes(selector.replace(/^[#.\[\]]/, '')) || this._html.includes(selector.replace('#', 'id="'))) {
        return {
          addEventListener: () => {},
          setAttribute: () => {},
          getAttribute: () => null,
          classList: { toggle: () => {}, add: () => {}, remove: () => {} }
        };
      }
      return null;
    },
    querySelectorAll() {
      return [];
    }
  };
}

describe('UI & Functional Polish Verification', () => {
  it('verifies the 3 initial prominent examples are correctly defined', () => {
    expect(SAMPLE_URLS.length).toBeGreaterThanOrEqual(8);
    expect(SAMPLE_URLS[0].label).toBe('Normal-looking URL');
    expect(SAMPLE_URLS[1].label).toBe('Suspicious URL structure');
    expect(SAMPLE_URLS[2].label).toBe('Unusual hostname');

    // Harmless RFC reserved domains
    expect(SAMPLE_URLS[0].url).toContain('example.com');
    expect(SAMPLE_URLS[1].url).toContain('example.net');
    expect(SAMPLE_URLS[2].url).toContain('192.0.2.');
  });

  it('verifies the 5 scanning stages match plain-language requirements exactly', () => {
    expect(SCAN_STAGES).toHaveLength(5);
    expect(SCAN_STAGES[0].label).toBe('Reading the URL');
    expect(SCAN_STAGES[1].label).toBe('Checking its structure');
    expect(SCAN_STAGES[2].label).toBe('Inspecting suspicious patterns');
    expect(SCAN_STAGES[3].label).toBe('Calculating risk indicators');
    expect(SCAN_STAGES[4].label).toBe('Preparing the report');
  });

  it('renders report in correct order: overall result, warning signs, recommendations, URL details', () => {
    const container = createMockContainer();
    const report = analyzeUrl('https://account.bank.example.com@credential-harvest.example.net/auth');
    renderReport(container, report);

    const html = container.innerHTML;

    // 1. Overall result
    expect(html).toContain('threat-verdict-box');
    expect(html).toContain('Some warning signs — review this link carefully.');
    expect(html).toContain('HOST:');
    expect(html).toContain('credential-harvest.example.net');
    expect(html).toContain('RISK SCORE');

    // Copy buttons
    expect(html).toContain('id="btn-copy-url"');
    expect(html).toContain('id="btn-copy-report"');

    // 2. Warning signs
    expect(html).toContain('Warning signs (');
    expect(html).toContain('Misleading User-Info (@) Structure');
    expect(html).toContain('Observed evidence:');
    expect(html).toContain('Recommended action:');

    // 3. Recommended actions
    expect(html).toContain('Recommended actions');
    expect(html).toContain('recommendation-item');

    // 4. Expandable technical URL details
    expect(html).toContain('id="technical-details-panel"');
    expect(html).toContain('URL details');
    expect(html).toContain('token-scheme');
    expect(html).toContain('Destination Host:');
  });

  it('renders High Concern plain-language verdict for combined severe structural findings', () => {
    const container = createMockContainer();
    const extremeUrl = 'http://bank.security.verify.urgent.auth@192.0.2.1:8080/login/verify/update?url=https%3A%2F%2Fother.com&q=%2520test';
    const report = analyzeUrl(extremeUrl);
    renderReport(container, report);

    const html = container.innerHTML;
    expect(html).toContain('High concern — several suspicious signs detected.');
    expect(html).toContain('threat-high');
  });

  it('renders neutral concise report for normal URLs without claiming it is safe', () => {
    const container = createMockContainer();
    const report = analyzeUrl('https://docs.example.com/resources/getting-started');
    renderReport(container, report);

    const html = container.innerHTML;
    expect(html).toContain('No obvious warning signs detected — this does not guarantee safety.');
    expect(html).toContain(`evaluated <strong>${CHECKS_PERFORMED.length} structural heuristic checks</strong>`);
    expect(html).toContain('Absence of structural warning signs does not guarantee that this link is safe');
    expect(html).toContain('View all ' + CHECKS_PERFORMED.length + ' checks performed');
  });

  it('renders empty standby state with clear plain-language badges', () => {
    const container = createMockContainer();
    renderEmptyState(container);
    const html = container.innerHTML;
    expect(html).toContain('RADAR READY');
    expect(html).toContain('100% Client-Side');
    expect(html).toContain('Analyzed Locally');
    expect(html).toContain('No External Lookup');
  });
});
