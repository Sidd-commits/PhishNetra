import { domainToASCII, domainToUnicode } from 'url';

export interface CanonicalUrlResult {
  rawUrl: string;
  canonicalUrl: string;
  protocol: string;
  hostname: string;
  port: number | null;
  pathname: string;
  search: string;
  hash: string;
  isPunycode: boolean;
  unicodeHostname: string | null;
}

/**
 * Normalizes and canonicalizes target URLs deterministically.
 * - Handles missing protocol
 * - Lowercases hostname
 * - Converts IDN / Unicode hostnames to Punycode
 * - Strips standard default ports (:80, :443)
 * - Normalizes trailing slashes and percent encoding
 */
export function canonicalizeUrl(rawInput: string): CanonicalUrlResult {
  let urlStr = rawInput.trim();

  // 1. Ensure scheme is present
  if (!/^https?:\/\//i.test(urlStr)) {
    urlStr = 'http://' + urlStr;
  }

  try {
    const parsed = new URL(urlStr);
    const protocol = parsed.protocol.toLowerCase();
    let hostname = parsed.hostname.toLowerCase();

    // Remove trailing dot in hostname if present (e.g. example.com.)
    if (hostname.endsWith('.')) {
      hostname = hostname.slice(0, -1);
    }

    // Punycode & IDN conversion
    let isPunycode = false;
    let unicodeHostname: string | null = null;
    try {
      if (hostname.startsWith('xn--') || /[^\u0000-\u007F]/.test(hostname)) {
        isPunycode = true;
        unicodeHostname = domainToUnicode(hostname);
        hostname = domainToASCII(hostname);
      }
    } catch {
      // ignore punycode parsing error
    }

    // Default port stripping
    let port: number | null = null;
    if (parsed.port) {
      const portNum = parseInt(parsed.port, 10);
      if ((protocol === 'http:' && portNum !== 80) || (protocol === 'https:' && portNum !== 443)) {
        port = portNum;
      }
    }

    // Path normalization
    let pathname = parsed.pathname || '/';
    // Collapse duplicate slashes in pathname except root
    pathname = pathname.replace(/\/+/g, '/');

    // Query string
    const search = parsed.search || '';
    const hash = parsed.hash || '';

    const hostHeader = port ? `${hostname}:${port}` : hostname;
    const canonicalUrl = `${protocol}//${hostHeader}${pathname}${search}${hash}`;

    return {
      rawUrl: rawInput.trim(),
      canonicalUrl,
      protocol,
      hostname,
      port,
      pathname,
      search,
      hash,
      isPunycode,
      unicodeHostname
    };
  } catch {
    // If URL constructor fails, return sanitized string fallback
    return {
      rawUrl: rawInput.trim(),
      canonicalUrl: rawInput.trim(),
      protocol: 'http:',
      hostname: rawInput.trim(),
      port: null,
      pathname: '/',
      search: '',
      hash: '',
      isPunycode: false,
      unicodeHostname: null
    };
  }
}
