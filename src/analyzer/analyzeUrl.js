import { parseUrl } from './parseUrl.js';
import { detectAllSignals } from './detectSignals.js';
import { calculateRiskScore } from './scoreRisk.js';

export const CHECKS_PERFORMED = [
  'Web scheme validation (strict HTTP/HTTPS enforcement)',
  'User-info authority deception check (@ credential trick)',
  'Direct IP-address host inspection (IPv4 / IPv6 literals)',
  'Internationalized Punycode homograph detection (xn-- labels)',
  'Hostname complexity and subdomain depth analysis',
  'Known URL shortening service domain match',
  'External redirect query parameter inspection',
  'Nested and excessive percent-encoding analysis',
  'Credential harvesting & urgency keyword contextual scan',
  'Transport layer encryption status (HTTPS vs plain HTTP)',
  'Localhost and private/reserved RFC network checks'
];

export const EXPLICIT_LIMITATIONS = [
  'Zero-network local analysis: LinkLens never fetches, opens, or visits submitted URLs.',
  'No live threat feeds: Checks do not query real-time blacklist databases, malware sandboxes, or DNS records.',
  'Content unaware: The server response body, page DOM, JavaScript scripts, and downloaded binaries are not inspected.',
  'Certificate blind: Local static parsing cannot verify SSL/TLS certificate validity, issuer, or revocation.',
  'Heuristic assessment: Low scores indicate structural conformity, not definitive proof of site safety or trustworthiness.'
];

/**
 * Centrally executes full URL inspection returning a structured result object.
 * @param {string} rawInput 
 * @returns {object}
 */
export function analyzeUrl(rawInput) {
  const parsed = parseUrl(rawInput);

  if (!parsed.isValid) {
    return {
      isValid: false,
      error: parsed.error,
      rawInput: parsed.rawInput,
      timestamp: new Date().toISOString()
    };
  }

  const findings = detectAllSignals(parsed);
  const { score, verdict, breakdown } = calculateRiskScore(findings);

  return {
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
}
