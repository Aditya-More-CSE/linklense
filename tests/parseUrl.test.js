import { describe, it, expect } from 'vitest';
import { parseUrl, MAX_URL_LENGTH } from '../src/analyzer/parseUrl.js';

describe('parseUrl', () => {
  it('parses a standard HTTPS URL correctly', () => {
    const result = parseUrl('https://docs.example.com/guides/setup?ver=1');
    expect(result.isValid).toBe(true);
    expect(result.scheme).toBe('https:');
    expect(result.hostname).toBe('docs.example.com');
    expect(result.registrableDomain).toBe('example.com');
    expect(result.subdomain).toBe('docs');
    expect(result.pathname).toBe('/guides/setup');
    expect(result.hasUserInfo).toBe(false);
  });

  it('normalizes URLs without explicit scheme assuming HTTPS', () => {
    const result = parseUrl('example.org/path/resource');
    expect(result.isValid).toBe(true);
    expect(result.assumedScheme).toBe(true);
    expect(result.scheme).toBe('https:');
    expect(result.hostname).toBe('example.org');
  });

  it('handles double-slash scheme normalization', () => {
    const result = parseUrl('//sub.example.com/test');
    expect(result.isValid).toBe(true);
    expect(result.scheme).toBe('https:');
    expect(result.hostname).toBe('sub.example.com');
  });

  it('rejects empty or whitespace-only inputs with helpful error', () => {
    const emptyResult = parseUrl('');
    expect(emptyResult.isValid).toBe(false);
    expect(emptyResult.error).toContain('Please enter a URL');

    const spaceResult = parseUrl('   ');
    expect(spaceResult.isValid).toBe(false);
    expect(spaceResult.error).toContain('Please enter a URL');
  });

  it('rejects input exceeding MAX_URL_LENGTH', () => {
    const hugeInput = 'https://example.com/' + 'a'.repeat(MAX_URL_LENGTH + 10);
    const result = parseUrl(hugeInput);
    expect(result.isValid).toBe(false);
    expect(result.error).toContain('exceeds maximum supported length');
  });

  it('rejects unsupported and dangerous non-web schemes', () => {
    const jsResult = parseUrl('javascript:alert(1)');
    expect(jsResult.isValid).toBe(false);
    expect(jsResult.error).toContain('javascript:');

    const dataResult = parseUrl('data:text/html;base64,PHNjcmlwdD4=');
    expect(dataResult.isValid).toBe(false);
    expect(dataResult.error).toContain('data:');

    const fileResult = parseUrl('file:///etc/passwd');
    expect(fileResult.isValid).toBe(false);
    expect(fileResult.error).toContain('file:');

    const mailtoResult = parseUrl('mailto:user@example.com');
    expect(mailtoResult.isValid).toBe(false);
    expect(mailtoResult.error).toContain('mailto:');
  });

  it('correctly extracts userinfo authority before @', () => {
    const result = parseUrl('https://trusted.bank.com:secret@phishing-target.net/login');
    expect(result.isValid).toBe(true);
    expect(result.hasUserInfo).toBe(true);
    expect(result.hostname).toBe('phishing-target.net');
    expect(result.username).toBe('trusted.bank.com');
    expect(result.password).toBe('secret');
  });

  it('detects IPv4 literal hostnames', () => {
    const result = parseUrl('http://192.0.2.1:8080/admin');
    expect(result.isValid).toBe(true);
    expect(result.isIp).toBe(true);
    expect(result.isIpv4).toBe(true);
    expect(result.hostname).toBe('192.0.2.1');
  });

  it('detects punycode hostnames', () => {
    const result = parseUrl('https://xn--pple-43d.example.com/');
    expect(result.isValid).toBe(true);
    expect(result.isPunycode).toBe(true);
  });

  it('identifies local, loopback, and private addresses', () => {
    expect(parseUrl('http://localhost:3000').isLocalOrPrivate).toBe(true);
    expect(parseUrl('http://127.0.0.1/status').isLocalOrPrivate).toBe(true);
    expect(parseUrl('http://192.168.1.1/admin').isLocalOrPrivate).toBe(true);
    expect(parseUrl('http://10.0.5.20').isLocalOrPrivate).toBe(true);
  });

  it('handles multi-part public suffixes gracefully via tldts', () => {
    const result = parseUrl('https://portal.service.co.uk/account');
    expect(result.isValid).toBe(true);
    expect(result.publicSuffix).toBe('co.uk');
    expect(result.registrableDomain).toBe('service.co.uk');
    expect(result.subdomain).toBe('portal');
  });
});
