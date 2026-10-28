import { describe, it, expect } from 'vitest';
import { SAMPLE_URLS } from '../src/data/sampleUrls.js';
import { redactUrlCredentials, sanitizeQueryParams, escapeHtml } from '../src/utils/redaction.js';
import { RISK_CONFIG, calculateRiskScore } from '../src/analyzer/scoreRisk.js';
import { SCAN_STAGES } from '../src/ui/scanAnimation.js';

describe('Module and Data Integrity Tests', () => {
  it('provides safe demonstration URLs covering expected test scenarios', () => {
    expect(SAMPLE_URLS.length).toBeGreaterThanOrEqual(8);
    for (const sample of SAMPLE_URLS) {
      expect(sample.id).toBeDefined();
      expect(sample.label).toBeDefined();
      expect(sample.url).toBeDefined();
      // Ensure none point to live malicious domains
      expect(
        sample.url.includes('example.com') ||
        sample.url.includes('example.org') ||
        sample.url.includes('example.net') ||
        sample.url.includes('192.0.2.') ||
        sample.url.includes('bit.ly')
      ).toBe(true);
    }
  });

  it('redacts credentials from URLs effectively', () => {
    const raw = 'https://admin:superSecret123@secure.portal.example.com/dashboard';
    const redacted = redactUrlCredentials(raw);
    expect(redacted).not.toContain('superSecret123');
    expect(redacted).toContain('REDACTED_PASS');
    expect(redacted).toContain('REDACTED_USER');
  });

  it('sanitizes query parameters to protect sensitive tokens', () => {
    const searchParams = new URLSearchParams('token=eyJhbGciOiJIUzI1NiJ9.test&user=alice&public_page=faq');
    const sanitized = sanitizeQueryParams(searchParams);
    
    const tokenParam = sanitized.find(p => p.key === 'token');
    expect(tokenParam.isPotentiallySensitive).toBe(true);
    expect(tokenParam.summary).toContain('[Hidden: sensitive key');

    const userParam = sanitized.find(p => p.key === 'user');
    expect(userParam.isPotentiallySensitive).toBe(false);
  });

  it('properly escapes HTML entities to prevent XSS injection', () => {
    const malicious = '<script>alert("xss")</script>&"\'';
    const escaped = escapeHtml(malicious);
    expect(escaped).not.toContain('<script>');
    expect(escaped).toContain('&lt;script&gt;');
    expect(escaped).toContain('&amp;');
    expect(escaped).toContain('&quot;');
    expect(escaped).toContain('&#039;');
  });

  it('verifies scan pipeline stages have 5 discrete steps', () => {
    expect(SCAN_STAGES.length).toBe(5);
  });
});
