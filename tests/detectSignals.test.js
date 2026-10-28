import { describe, it, expect } from 'vitest';
import { parseUrl } from '../src/analyzer/parseUrl.js';
import {
  detectUserInfoDeception,
  detectIpHost,
  detectPunycode,
  detectHostnameComplexity,
  detectUrlShortener,
  detectRedirectParameters,
  detectUrlEncoding,
  detectSuspiciousWording,
  detectInsecureScheme,
  detectAllSignals
} from '../src/analyzer/detectSignals.js';

describe('detectSignals', () => {
  it('flags user-info deception trick', () => {
    const parsed = parseUrl('https://mybank.com@evil.example.net/login');
    const finding = detectUserInfoDeception(parsed);
    expect(finding).not.toBeNull();
    expect(finding.severity).toBe('High');
    expect(finding.id).toBe('user-info-deception');
  });

  it('flags IP literal hosts with Moderate severity', () => {
    const parsed = parseUrl('http://192.0.2.1/status');
    const finding = detectIpHost(parsed);
    expect(finding).not.toBeNull();
    expect(finding.severity).toBe('Moderate');
  });

  it('flags Punycode IDN labels', () => {
    const parsed = parseUrl('https://xn--e1afmkfd.example.com/');
    const finding = detectPunycode(parsed);
    expect(finding).not.toBeNull();
    expect(finding.id).toBe('punycode-hostname');
  });

  it('flags deep subdomain nesting (>= 3 levels)', () => {
    const parsed = parseUrl('https://a.b.c.target.example.org/path');
    const finding = detectHostnameComplexity(parsed);
    expect(finding).not.toBeNull();
    expect(finding.id).toBe('hostname-complexity');
  });

  it('flags known shortener domains', () => {
    const parsed = parseUrl('https://bit.ly/3xSample');
    const finding = detectUrlShortener(parsed);
    expect(finding).not.toBeNull();
    expect(finding.id).toBe('url-shortener');
  });

  it('flags redirect query parameters pointing to external URLs', () => {
    const parsed = parseUrl('https://portal.example.com/login?dest=https%3A%2F%2Fexternal.net%2Fauth');
    const finding = detectRedirectParameters(parsed);
    expect(finding).not.toBeNull();
    expect(finding.id).toBe('redirect-parameter');
  });

  it('flags nested/double URL encoding', () => {
    const parsed = parseUrl('https://example.com/search?q=%2520test');
    const finding = detectUrlEncoding(parsed);
    expect(finding).not.toBeNull();
    expect(finding.id).toBe('url-encoding-double');
  });

  it('flags plain HTTP as informational finding', () => {
    const parsed = parseUrl('http://example.com/guide');
    const finding = detectInsecureScheme(parsed);
    expect(finding).not.toBeNull();
    expect(finding.severity).toBe('Informational');
  });

  it('does NOT falsely flag benign standard HTTPS links', () => {
    const parsed = parseUrl('https://docs.example.com/about/company');
    const findings = detectAllSignals(parsed);
    expect(findings.length).toBe(0);
  });
});
