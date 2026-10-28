import { describe, it, expect } from 'vitest';
import { analyzeUrl, CHECKS_PERFORMED, EXPLICIT_LIMITATIONS } from '../src/analyzer/analyzeUrl.js';

describe('analyzeUrl - Full System Verification', () => {
  it('analyzes standard HTTPS URL with zero warning signs', () => {
    const res = analyzeUrl('https://docs.example.com/resources/getting-started');
    expect(res.isValid).toBe(true);
    expect(res.score).toBe(0);
    expect(res.verdict.code).toBe('NONE_DETECTED');
    expect(res.findings.length).toBe(0);
    expect(res.checksPerformed.length).toBe(CHECKS_PERFORMED.length);
    expect(res.explicitLimitations.length).toBe(EXPLICIT_LIMITATIONS.length);
  });

  it('analyzes HTTP URL without falsely classifying as malicious', () => {
    const res = analyzeUrl('http://info.example.org/about');
    expect(res.isValid).toBe(true);
    expect(res.score).toBe(5);
    expect(res.verdict.code).toBe('NONE_DETECTED');
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0].id).toBe('insecure-http');
    expect(res.findings[0].severity).toBe('Informational');
  });

  it('normalizes URL entered without scheme', () => {
    const res = analyzeUrl('example.org/welcome');
    expect(res.isValid).toBe(true);
    expect(res.parsed.assumedScheme).toBe(true);
    expect(res.parsed.scheme).toBe('https:');
  });

  it('rejects empty input with helpful error', () => {
    const res = analyzeUrl('');
    expect(res.isValid).toBe(false);
    expect(res.error).toBeDefined();
  });

  it('rejects malformed input', () => {
    const res = analyzeUrl('http://');
    expect(res.isValid).toBe(false);
    expect(res.error).toBeDefined();
  });

  it('rejects unsupported javascript: and data: schemes', () => {
    const resJs = analyzeUrl('javascript:alert(1)');
    expect(resJs.isValid).toBe(false);
    expect(resJs.error).toContain('javascript:');

    const resData = analyzeUrl('data:text/html,test');
    expect(resData.isValid).toBe(false);
    expect(resData.error).toContain('data:');
  });

  it('detects user-info authority deception with High severity', () => {
    const res = analyzeUrl('https://trusted.example.test@evil.example.test/portal');
    expect(res.isValid).toBe(true);
    expect(res.parsed.hostname).toBe('evil.example.test');
    expect(res.parsed.hasUserInfo).toBe(true);
    expect(res.findings.some(f => f.id === 'user-info-deception')).toBe(true);
    expect(res.score).toBeGreaterThanOrEqual(35);
  });

  it('detects IPv4 and IPv6 literal hosts', () => {
    const res4 = analyzeUrl('http://192.0.2.88:8080/admin');
    expect(res4.parsed.isIpv4).toBe(true);
    expect(res4.findings.some(f => f.id === 'ip-host')).toBe(true);

    const res6 = analyzeUrl('http://[2001:db8::1]/index');
    expect(res6.parsed.isIpv6).toBe(true);
    expect(res6.findings.some(f => f.id === 'ip-host')).toBe(true);
  });

  it('detects punycode hostnames', () => {
    const res = analyzeUrl('https://xn--pple-43d.example.com/');
    expect(res.parsed.isPunycode).toBe(true);
    expect(res.findings.some(f => f.id === 'punycode-hostname')).toBe(true);
  });

  it('detects multi-part public suffixes correctly', () => {
    const res = analyzeUrl('https://login.service.co.uk/auth');
    expect(res.parsed.registrableDomain).toBe('service.co.uk');
    expect(res.parsed.subdomain).toBe('login');
    expect(res.parsed.publicSuffix).toBe('co.uk');
  });

  it('detects encoded redirect parameters', () => {
    const res = analyzeUrl('https://auth.example.com/login?dest=https%3A%2F%2Fexternal-scam.example.net%2Fclaim');
    expect(res.findings.some(f => f.id === 'redirect-parameter')).toBe(true);
  });

  it('detects known shorteners', () => {
    const res = analyzeUrl('https://bit.ly/sample-short');
    expect(res.findings.some(f => f.id === 'url-shortener')).toBe(true);
  });

  it('caps score at 100 and avoids duplicate findings', () => {
    const extremeUrl = 'http://bank.security.verify.urgent.auth@192.0.2.1:8080/login/verify/update?url=https%3A%2F%2Fother.com&q=%2520test';
    const res = analyzeUrl(extremeUrl);
    expect(res.score).toBeLessThanOrEqual(100);
    expect(res.verdict.code).toBe('HIGH_CONCERN');

    const ids = res.findings.map(f => f.id);
    const uniqueIds = new Set(ids);
    expect(ids.length).toBe(uniqueIds.size);
  });
});
