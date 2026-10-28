/**
 * Utilities for redacting sensitive URL details, credentials, and query values.
 */

/**
 * Escapes characters for safe DOM/HTML injection
 * @param {string} str 
 * @returns {string}
 */
export function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Redacts username and password from a URL string or userinfo string
 * @param {string} urlString 
 * @returns {string}
 */
export function redactUrlCredentials(urlString) {
  if (!urlString || typeof urlString !== 'string') return '';
  try {
    const url = new URL(urlString);
    if (url.username || url.password) {
      url.username = url.username ? 'REDACTED_USER' : '';
      url.password = url.password ? 'REDACTED_PASS' : '';
    }
    return decodeURI(url.toString());
  } catch {
    // If not parseable via new URL, regex fallback for user:pass@
    return urlString.replace(/:\/\/[^@/\s]+@/, '://REDACTED_CREDENTIALS@');
  }
}

/**
 * Sanitizes query parameter objects by showing keys and masked/summarized values
 * Avoids exposing session tokens, credentials, or personal data.
 * @param {URLSearchParams} searchParams 
 * @returns {Array<{ key: string, summary: string, isPotentiallySensitive: boolean }>}
 */
export function sanitizeQueryParams(searchParams) {
  if (!searchParams) return [];
  const sensitiveKeyPatterns = /token|auth|key|secret|password|passwd|session|bearer|jwt|id_token|access_token|credential|api_key|hash/i;
  
  const results = [];
  for (const [key, val] of searchParams.entries()) {
    const isSensitive = sensitiveKeyPatterns.test(key);
    let summary = '';
    if (val.length === 0) {
      summary = '(empty value)';
    } else if (isSensitive) {
      summary = `[Hidden: sensitive key (${val.length} chars)]`;
    } else if (val.length > 40) {
      summary = `[${val.slice(0, 10)}... (${val.length} chars)]`;
    } else {
      // For general non-sensitive parameters, show value masked or truncated
      summary = val;
    }
    results.push({ key, summary, isPotentiallySensitive: isSensitive });
  }
  return results;
}
