import { parse as parseDomain } from 'tldts';

export const MAX_URL_LENGTH = 4096;

/**
 * Validates and parses a URL input safely using the standard URL API and tldts.
 * Never executes, fetches, or navigates to the URL.
 * 
 * @param {string} rawInput 
 * @returns {{
 *   isValid: boolean,
 *   error?: string,
 *   rawInput: string,
 *   normalizedUrl?: string,
 *   urlObj?: URL,
 *   scheme?: string,
 *   assumedScheme?: boolean,
 *   hostname?: string,
 *   port?: string,
 *   pathname?: string,
 *   search?: string,
 *   hash?: string,
 *   searchParams?: URLSearchParams,
 *   hasUserInfo?: boolean,
 *   username?: string,
 *   password?: string,
 *   registrableDomain?: string | null,
 *   subdomain?: string | null,
 *   publicSuffix?: string | null,
 *   isIp?: boolean,
 *   isIpv4?: boolean,
 *   isIpv6?: boolean,
 *   isLocalOrPrivate?: boolean,
 *   isPunycode?: boolean
 * }}
 */
export function parseUrl(rawInput) {
  if (typeof rawInput !== 'string') {
    return { isValid: false, error: 'URL input must be a text string.', rawInput: '' };
  }

  const trimmed = rawInput.trim();

  if (!trimmed) {
    return { isValid: false, error: 'Please enter a URL to inspect.', rawInput: trimmed };
  }

  if (trimmed.length > MAX_URL_LENGTH) {
    return {
      isValid: false,
      error: `URL exceeds maximum supported length (${MAX_URL_LENGTH} characters). Input was ${trimmed.length} characters.`,
      rawInput: trimmed
    };
  }

  // Quick check for dangerous non-web schemes before normalization
  const schemeMatch = trimmed.match(/^([a-zA-Z0-9+.-]+):/);
  if (schemeMatch) {
    const identifiedScheme = schemeMatch[1].toLowerCase();
    if (identifiedScheme !== 'http' && identifiedScheme !== 'https') {
      const unsupportedReasons = {
        javascript: 'JavaScript execution pseudocode (javascript:) is not a valid web URL and presents security risks.',
        data: 'Data URLs (data:) contain inline media or documents rather than a remote web destination.',
        file: 'Local file links (file:) reference internal host filesystem paths.',
        blob: 'Blob URLs (blob:) represent local browser memory handles.',
        mailto: 'Email links (mailto:) open mail clients rather than web links.'
      };
      const detail = unsupportedReasons[identifiedScheme] || `The "${identifiedScheme}:" scheme is not supported. Only http:// and https:// links are analyzed.`;
      return {
        isValid: false,
        error: `Unsupported scheme "${identifiedScheme}:". ${detail}`,
        rawInput: trimmed
      };
    }
  }

  let normalized = trimmed;
  let assumedScheme = false;

  // If user pasted without protocol (e.g. "example.com/login" or "//example.com")
  if (!/^https?:\/\//i.test(normalized)) {
    if (normalized.startsWith('//')) {
      normalized = `https:${normalized}`;
    } else {
      normalized = `https://${normalized}`;
    }
    assumedScheme = true;
  }

  let parsed;
  try {
    parsed = new URL(normalized);
  } catch (err) {
    return {
      isValid: false,
      error: 'Malformed URL: The input could not be parsed into a standard web URL structure.',
      rawInput: trimmed
    };
  }

  // Ensure scheme is strictly http or https
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      isValid: false,
      error: `Unsupported scheme "${parsed.protocol}". Only HTTP and HTTPS target URLs are accepted.`,
      rawInput: trimmed
    };
  }

  // Validate hostname
  if (!parsed.hostname || parsed.hostname.length === 0) {
    return {
      isValid: false,
      error: 'Malformed URL: Missing valid hostname destination.',
      rawInput: trimmed
    };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Inspect user-info credentials (@ symbol in authority)
  const hasUserInfo = Boolean(parsed.username || parsed.password);

  // Use tldts for robust domain parsing
  const tldResult = parseDomain(hostname);

  // IP address checks
  const ipv4Regex = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const isIpv4 = ipv4Regex.test(hostname);
  const isIpv6 = hostname.startsWith('[') || /^[0-9a-f:]+$/i.test(hostname) && hostname.includes(':');
  const isIp = isIpv4 || isIpv6 || Boolean(tldResult.isIp);

  // Punycode check (xn--)
  const isPunycode = hostname.split('.').some(part => part.toLowerCase().startsWith('xn--'));

  // Local/Private destination checks
  const isLocalOrPrivate = checkIsLocalOrPrivate(hostname, isIpv4, isIpv6);

  return {
    isValid: true,
    rawInput: trimmed,
    normalizedUrl: parsed.toString(),
    urlObj: parsed,
    scheme: parsed.protocol,
    assumedScheme,
    hostname,
    port: parsed.port,
    pathname: parsed.pathname,
    search: parsed.search,
    hash: parsed.hash,
    searchParams: parsed.searchParams,
    hasUserInfo,
    username: parsed.username,
    password: parsed.password,
    registrableDomain: tldResult.domain || (isIp ? hostname : null),
    subdomain: tldResult.subdomain || null,
    publicSuffix: tldResult.publicSuffix || null,
    isIp,
    isIpv4,
    isIpv6,
    isLocalOrPrivate,
    isPunycode
  };
}

/**
 * Checks if the hostname targets local, loopback, or private RFC 1918/RFC 4193 subnets.
 * @param {string} hostname 
 * @param {boolean} isIpv4 
 * @param {boolean} isIpv6 
 * @returns {boolean}
 */
function checkIsLocalOrPrivate(hostname, isIpv4, isIpv6) {
  const lower = hostname.toLowerCase();
  
  if (lower === 'localhost' || lower.endsWith('.local') || lower.endsWith('.internal') || lower.endsWith('.test') || lower.endsWith('.example')) {
    return true;
  }

  if (isIpv4) {
    const parts = lower.split('.').map(Number);
    // 127.0.0.0/8 (Loopback)
    if (parts[0] === 127) return true;
    // 10.0.0.0/8 (Private)
    if (parts[0] === 10) return true;
    // 172.16.0.0/12 (Private)
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // 192.168.0.0/16 (Private)
    if (parts[0] === 192 && parts[1] === 168) return true;
    // 169.254.0.0/16 (Link-local)
    if (parts[0] === 169 && parts[1] === 254) return true;
    // 0.0.0.0
    if (parts[0] === 0) return true;
  }

  if (isIpv6) {
    const clean = lower.replace(/[[\]]/g, '');
    if (clean === '::1' || clean === '::' || clean.startsWith('fe80:') || clean.startsWith('fc00:') || clean.startsWith('fd00:')) {
      return true;
    }
  }

  return false;
}
