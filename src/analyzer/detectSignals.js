/**
 * Detection engine containing isolated, testable signal detectors.
 * Each detector returns either null (if not flagged) or a structured finding object:
 * {
 *   id: string,
 *   title: string,
 *   severity: 'High' | 'Moderate' | 'Low' | 'Informational',
 *   evidence: string,
 *   explanation: string,
 *   recommendation: string,
 *   weight: number
 * }
 */

const KNOWN_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'is.gd',
  'buff.ly',
  'ow.ly',
  'tiny.cc',
  'rebrand.ly',
  'cutt.ly',
  'rb.gy',
  'shorturl.at',
  'goo.gl',
  'v.gd',
  'snip.ly',
  'bl.ink',
  'qr.net',
  'bc.vc',
  'adf.ly'
]);

const SENSITIVE_REDIRECT_PARAMS = new Set([
  'url',
  'redirect',
  'redirect_to',
  'redirect_uri',
  'next',
  'continue',
  'return',
  'return_to',
  'dest',
  'destination',
  'target',
  'r',
  'link',
  'out',
  'goto',
  'forward'
]);

const CREDENTIAL_URGENCY_KEYWORDS = [
  'verify',
  'verification',
  'security-update',
  'secure-login',
  'signin',
  'sign-in',
  'login',
  'account-update',
  'confirm-identity',
  'billing-update',
  'suspend',
  'urgent',
  'wallet',
  'credential',
  'recover-access'
];

/**
 * Signal 1: URL user-info deception trick (text before @)
 */
export function detectUserInfoDeception(parsed) {
  if (!parsed.hasUserInfo) return null;

  const user = parsed.username || '';
  const pass = parsed.password ? ':******' : '';
  const fullUserInfo = `${user}${pass}`;

  return {
    id: 'user-info-deception',
    title: 'Misleading User-Info (@) Structure',
    severity: 'High',
    evidence: `Authority prefix "${user}@" precedes the actual hostname "${parsed.hostname}".`,
    explanation: 'In standard URL syntax, any text before the "@" character represents authentication credentials, not the host server. Attackers frequently embed trusted brands before "@" so casual readers mistake it for the destination website.',
    recommendation: 'Do not click this link. Any apparent company name before the "@" character is completely ignored by web browsers; you will connect to the server following "@".',
    weight: 35
  };
}

/**
 * Signal 2: IP-address destination host
 */
export function detectIpHost(parsed) {
  if (!parsed.isIp) return null;

  const ipType = parsed.isIpv6 ? 'IPv6' : 'IPv4';
  return {
    id: 'ip-host',
    title: `Direct ${ipType} Address Destination`,
    severity: 'Moderate',
    evidence: `Destination host is an explicit IP address ("${parsed.hostname}") rather than a registered domain name.`,
    explanation: 'Legitimate consumer web services rarely direct public visitors to raw IP addresses instead of registered domain names. While common for local routers or private servers, public IP links are frequently used by attackers to bypass domain-based reputation filters.',
    recommendation: 'Verify the intended service. Avoid entering credentials or confidential information on direct IP web addresses unless you administer the system.',
    weight: 20
  };
}

/**
 * Signal 3: Internationalized / Punycode hostname (xn--)
 */
export function detectPunycode(parsed) {
  if (!parsed.isPunycode) return null;

  const punycodeLabels = parsed.hostname
    .split('.')
    .filter(label => label.toLowerCase().startsWith('xn--'));

  return {
    id: 'punycode-hostname',
    title: 'Internationalized Punycode Hostname (IDN)',
    severity: 'Moderate',
    evidence: `Contains punycode label(s): ${punycodeLabels.join(', ')}.`,
    explanation: 'Punycode enables non-ASCII Unicode characters in domain names. While essential for global languages, homoglyph attacks use visually identical characters (e.g., Cyrillic "а" replacing Latin "a") to impersonate legitimate brand domains.',
    recommendation: 'Check the exact characters carefully or navigate to the intended organization through a trusted bookmark or primary search.',
    weight: 15
  };
}

/**
 * Signal 4: Deep or confusing hostname complexity
 */
export function detectHostnameComplexity(parsed) {
  if (!parsed.hostname || parsed.isIp) return null;

  const subdomain = parsed.subdomain || '';
  const subParts = subdomain.split('.').filter(Boolean);

  // Depth threshold: 3 or more subdomain levels (e.g., a.b.c.domain.com)
  if (subParts.length >= 3) {
    return {
      id: 'hostname-complexity',
      title: 'Deep Subdomain Nesting',
      severity: 'Moderate',
      evidence: `Contains ${subParts.length} subdomain levels: "${subdomain}".`,
      explanation: 'Unusually deep subdomain structures can mimic full domain names or security verification paths to deceive users glancing at the address bar.',
      recommendation: 'Look strictly at the registrable root domain (the last two segments before the suffix) rather than the preceding subdomains.',
      weight: 15
    };
  }

  // Check for excessive total dot count in hostname
  const dotCount = (parsed.hostname.match(/\./g) || []).length;
  if (dotCount >= 5) {
    return {
      id: 'hostname-complexity',
      title: 'Excessive Hostname Segments',
      severity: 'Low',
      evidence: `Hostname contains ${dotCount} dots across its labels.`,
      explanation: 'Complex multi-segmented hostnames make determining the actual responsible domain difficult for users.',
      recommendation: 'Confirm that the root domain matches your expected destination.',
      weight: 10
    };
  }

  return null;
}

/**
 * Signal 5: Known URL shortener service
 */
export function detectUrlShortener(parsed) {
  if (!parsed.registrableDomain) return null;

  const regDomain = parsed.registrableDomain.toLowerCase();
  if (KNOWN_SHORTENERS.has(regDomain)) {
    return {
      id: 'url-shortener',
      title: 'Known URL Shortener Service',
      severity: 'Moderate',
      evidence: `Domain "${regDomain}" is a recognized URL shortening service.`,
      explanation: 'URL shorteners compress links for sharing, but completely mask the true final destination from the user. Phishing campaigns frequently leverage shorteners to conceal malicious landing domains.',
      recommendation: 'Do not click blindly. Use a dedicated preview or URL expander tool to inspect the final target address before visiting.',
      weight: 20
    };
  }

  return null;
}

/**
 * Signal 6: Redirect query parameters
 */
export function detectRedirectParameters(parsed) {
  if (!parsed.searchParams) return null;

  const flagged = [];
  for (const [key, value] of parsed.searchParams.entries()) {
    const lowerKey = key.toLowerCase();
    if (SENSITIVE_REDIRECT_PARAMS.has(lowerKey)) {
      // Check if value looks like a URL or external protocol
      const trimmedVal = value.trim();
      const hasUrlTarget = /^https?:\/\//i.test(trimmedVal) ||
        trimmedVal.startsWith('//') ||
        /^https?%3A%2F%2F/i.test(trimmedVal);

      if (hasUrlTarget) {
        flagged.push({ key, hasUrlTarget: true });
      } else if (trimmedVal.length > 5) {
        flagged.push({ key, hasUrlTarget: false });
      }
    }
  }

  if (flagged.length === 0) return null;

  const directExternal = flagged.some(f => f.hasUrlTarget);
  const paramNames = flagged.map(f => `"${f.key}"`).join(', ');

  return {
    id: 'redirect-parameter',
    title: directExternal ? 'External Destination Parameter Detected' : 'Potential Redirect Parameter',
    severity: directExternal ? 'Moderate' : 'Low',
    evidence: `Identified potential redirect parameter(s): ${paramNames}.`,
    explanation: directExternal
      ? 'The URL contains a query parameter that specifies an external web target. This pattern is commonly exploited in open-redirect attacks where a trusted site inadvertently bounces users to an attacker site.'
      : 'Query parameter names match common redirect or onward navigation patterns.',
    recommendation: 'Inspect the destination embedded within the query parameter. Ensure the final destination is reputable.',
    weight: directExternal ? 20 : 10
  };
}

/**
 * Signal 7: Unusual or nested URL percent-encoding
 */
export function detectUrlEncoding(parsed) {
  const full = parsed.rawInput;
  // Count percent-encoded sequences (%XX)
  const percentMatches = full.match(/%[0-9a-fA-F]{2}/g) || [];
  const doubleEncoded = /%25[0-9a-fA-F]{2}/i.test(full);

  if (doubleEncoded) {
    return {
      id: 'url-encoding-double',
      title: 'Nested (Double) Percent-Encoding',
      severity: 'Moderate',
      evidence: 'Detected nested percent-encoding sequences (e.g. "%25xx").',
      explanation: 'Double encoding is an obfuscation method sometimes used to bypass web application firewalls and security filters by masking characters during initial parsing.',
      recommendation: 'Treat URLs containing double-encoding with caution, as it is non-standard for public web links.',
      weight: 15
    };
  }

  if (percentMatches.length >= 8) {
    return {
      id: 'url-encoding-heavy',
      title: 'Extensive Percent-Encoding',
      severity: 'Low',
      evidence: `URL contains ${percentMatches.length} percent-encoded character sequences.`,
      explanation: 'Heavy URL encoding obscures text and paths, making human visual inspection of the target difficult.',
      recommendation: 'Verify the decoded destination to confirm the true file or resource being requested.',
      weight: 10
    };
  }

  return null;
}

/**
 * Signal 8: Contextual credential or urgency keywords
 */
export function detectSuspiciousWording(parsed) {
  const host = (parsed.subdomain || '') + '.' + (parsed.registrableDomain || '');
  const path = parsed.pathname || '';
  const combined = `${host}/${path}`.toLowerCase();

  const matchedKeywords = CREDENTIAL_URGENCY_KEYWORDS.filter(kw => {
    // Word boundary or hyphen/underscore/dot delimiter
    const escaped = kw.replace(/-/g, '[-_.]?');
    const regex = new RegExp(`(?:^|[/._-])${escaped}(?:$|[/._-])`, 'i');
    return regex.test(combined);
  });

  if (matchedKeywords.length >= 2) {
    return {
      id: 'suspicious-wording',
      title: 'Urgency & Credential Keywords in Structure',
      severity: 'Low',
      evidence: `Observed patterns: ${matchedKeywords.slice(0, 3).map(k => `"${k}"`).join(', ')}.`,
      explanation: 'Words related to authentication, account recovery, or security verification are frequently combined in deceptive URLs to create false urgency. Legitimate service portals also utilize these terms, so this is a contextual indicator rather than proof of malice.',
      recommendation: 'If you received this link in an unsolicited email or message, do not enter credentials. Access your account directly from your browser bookmark or app.',
      weight: 10
    };
  }

  return null;
}

/**
 * Signal 9: Unencrypted HTTP connection
 */
export function detectInsecureScheme(parsed) {
  if (parsed.scheme === 'http:') {
    return {
      id: 'insecure-http',
      title: 'Unencrypted HTTP Transport',
      severity: 'Informational',
      evidence: 'Protocol is plain "http:" without TLS/SSL transport encryption.',
      explanation: 'HTTP data travels in cleartext across network hops. While standard for legacy informational documents or local testbeds, it does not encrypt data in transit or guarantee server identity.',
      recommendation: 'Do not submit sensitive credentials, personal details, or financial data over an unencrypted connection.',
      weight: 5
    };
  }
  return null;
}

/**
 * Signal 10: Unusual URL length and complexity
 */
export function detectLengthAndComplexity(parsed) {
  const length = parsed.rawInput.length;
  const pathSegments = (parsed.pathname || '').split('/').filter(Boolean).length;

  if (length > 255 || pathSegments > 7) {
    return {
      id: 'url-length-complexity',
      title: 'High URL Length & Structure Complexity',
      severity: 'Informational',
      evidence: `Length is ${length} characters with ${pathSegments} path segments.`,
      explanation: 'Excessively long URLs with deeply nested structures are commonly used by tracking systems or phishing toolkits to distract from the root domain.',
      recommendation: 'Focus on the verified root domain rather than the lengthy path or tracking parameters.',
      weight: 5
    };
  }
  return null;
}

/**
 * Signal 11: Local / Private / Reserved Network Destinations
 */
export function detectLocalOrPrivateDestination(parsed) {
  if (!parsed.isLocalOrPrivate) return null;

  return {
    id: 'local-private-destination',
    title: 'Local / Reserved Network Destination',
    severity: 'Informational',
    evidence: `Destination "${parsed.hostname}" points to a local, loopback, or reserved network scope.`,
    explanation: 'This address is intended for local private networks or system testing and is not reachable across the public internet. Legitimate external links do not point to private network spaces.',
    recommendation: 'Ensure you understand whether this link is intended for an internal network resource.',
    weight: 10
  };
}

/**
 * Runs all detectors against parsed URL data and returns a de-duplicated array of findings.
 * @param {object} parsed 
 * @returns {Array<object>}
 */
export function detectAllSignals(parsed) {
  if (!parsed || !parsed.isValid) return [];

  const detectors = [
    detectUserInfoDeception,
    detectIpHost,
    detectPunycode,
    detectHostnameComplexity,
    detectUrlShortener,
    detectRedirectParameters,
    detectUrlEncoding,
    detectSuspiciousWording,
    detectInsecureScheme,
    detectLengthAndComplexity,
    detectLocalOrPrivateDestination
  ];

  const findings = [];
  const seenIds = new Set();

  for (const detector of detectors) {
    try {
      const result = detector(parsed);
      if (result && !seenIds.has(result.id)) {
        findings.push(result);
        seenIds.add(result.id);
      }
    } catch (err) {
      // Defensive: do not let an individual detector crash the analyzer
      console.error('Detector error:', err);
    }
  }

  return findings;
}
