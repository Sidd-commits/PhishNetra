/**
 * PhishNetra - IP Intelligence & SSRF Security Utilities
 * Module: apps.api.src.services.analysis.ipUtils
 * 
 * Provides unified detection for RFC1918 private IP ranges, loopback,
 * cloud metadata endpoints (169.254.169.254, 100.100.100.200), carrier-grade NAT,
 * and IPv6 local/unspecified/mapped addresses.
 */

export function isPrivateOrReservedIp(ipStr: string): boolean {
  if (!ipStr) return false;
  const ip = ipStr.trim().toLowerCase();

  // IPv6 checks (loopback, unspecified, unique local, link local, mapped)
  if (
    ip === '::1' ||
    ip === '::' ||
    ip.startsWith('fe80:') ||
    ip.startsWith('fc00:') ||
    ip.startsWith('fd00:') ||
    ip.startsWith('::ffff:127.') ||
    ip.startsWith('::ffff:10.') ||
    ip.startsWith('::ffff:192.168.') ||
    ip.startsWith('::ffff:169.254.')
  ) {
    return true;
  }

  // IPv4 Loopback (127.0.0.0/8)
  if (ip.startsWith('127.')) return true;
  // IPv4 Unspecified (0.0.0.0/8)
  if (ip.startsWith('0.')) return true;
  // IPv4 Private Class A (10.0.0.0/8)
  if (ip.startsWith('10.')) return true;
  // IPv4 Private Class C (192.168.0.0/16)
  if (ip.startsWith('192.168.')) return true;
  // IPv4 Link-Local & Cloud Instance Metadata (169.254.0.0/16)
  if (ip.startsWith('169.254.')) return true;

  // IPv4 Private Class B: 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
  const m172 = ip.match(/^172\.(\d{1,3})\./);
  if (m172) {
    const octet = parseInt(m172[1], 10);
    if (octet >= 16 && octet <= 31) return true;
  }

  // Carrier-Grade NAT & Cloud Provider Shared Space: 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
  // e.g. Alibaba Cloud metadata 100.100.100.200
  const m100 = ip.match(/^100\.(\d{1,3})\./);
  if (m100) {
    const octet = parseInt(m100[1], 10);
    if (octet >= 64 && octet <= 127) return true;
  }

  return false;
}
