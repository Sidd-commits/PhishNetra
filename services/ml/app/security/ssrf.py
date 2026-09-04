"""
PhishNetra - SSRF & DNS Rebinding Protection Engine
Module: services.ml.app.security.ssrf
Milestone: 3
"""

import socket
import ipaddress
import urllib.parse
import re
from typing import Tuple, Optional, List


# Prohibited CIDR Ranges (IPv4 and IPv6)
PROHIBITED_NETWORKS = [
    # IPv4 Loopback & Local
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    # IPv4 Private RFC 1918
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # IPv4 Link-Local & Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("169.254.0.0/16"),
    # Carrier-Grade NAT / Shared Space (e.g. Alibaba metadata 100.100.100.200)
    ipaddress.ip_network("100.64.0.0/10"),
    # Documentation / Test Networks
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    # Multicast & Reserved
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 Loopback & Unspecified
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    # IPv6 Link-Local
    ipaddress.ip_network("fe80::/10"),
    # IPv6 Unique Local / Private
    ipaddress.ip_network("fc00::/7"),
    # IPv6 Multicast
    ipaddress.ip_network("ff00::/8"),
    # IPv6 Documentation
    ipaddress.ip_network("2001:db8::/32"),
    # IPv6 Discard
    ipaddress.ip_network("100::/64"),
    # IPv4-Mapped IPv6 loopback / private prefix handled by ipaddress
]

PROHIBITED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "local",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
    "169.254.169.254",
    "100.100.100.200",
}


class SSRFValidator:
    """
    Multi-layer SSRF, DNS Rebinding, and Prohibited IP Shield for PhishNetra.
    """

    @staticmethod
    def is_ip_prohibited(ip_obj: ipaddress._BaseAddress) -> Tuple[bool, str]:
        """
        Checks if an IP address falls into private, loopback, link-local, or cloud metadata ranges.
        """
        # Check IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped

        for net in PROHIBITED_NETWORKS:
            if ip_obj in net:
                return True, f"Target IP {ip_obj} falls within prohibited network range ({net})"

        if ip_obj.is_loopback:
            return True, f"Target IP {ip_obj} is a loopback address"
        if ip_obj.is_private:
            return True, f"Target IP {ip_obj} is a private RFC1918 address"
        if ip_obj.is_link_local:
            return True, f"Target IP {ip_obj} is a link-local address"
        if ip_obj.is_multicast:
            return True, f"Target IP {ip_obj} is a multicast address"
        if ip_obj.is_reserved:
            return True, f"Target IP {ip_obj} is a reserved address"
        if ip_obj.is_unspecified:
            return True, f"Target IP {ip_obj} is an unspecified address"

        return False, ""

    @staticmethod
    def parse_alternative_ip(hostname: str) -> Optional[ipaddress._BaseAddress]:
        """
        Detects and decodes alternative IP representations:
        - Decimal notation (e.g., 2130706433 -> 127.0.0.1)
        - Hexadecimal notation (e.g., 0x7f000001 or 0x7f.0x0.0x0.0x1)
        - Octal notation (e.g., 0177.0.0.1)
        - Raw IPv4 / IPv6 strings
        """
        clean = hostname.strip().strip("[]").lower()

        # Try standard ipaddress parsing first
        try:
            return ipaddress.ip_address(clean)
        except ValueError:
            pass

        # Check pure integer / decimal IP (e.g. 2130706433)
        if clean.isdigit():
            try:
                val = int(clean)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
            except (ValueError, OverflowError):
                pass

        # Check pure hex integer (e.g. 0x7f000001)
        if clean.startswith("0x") and len(clean) <= 10:
            try:
                val = int(clean, 16)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
            except (ValueError, OverflowError):
                pass

        # Check dot-separated mixed hex/octal/dec (e.g. 0177.0.0.1 or 0x7f.0.0.1)
        parts = clean.split(".")
        if len(parts) == 4:
            try:
                octets = []
                for p in parts:
                    if p.startswith("0x") or p.startswith("0X"):
                        octets.append(int(p, 16))
                    elif p.startswith("0") and len(p) > 1 and p.isdigit():
                        octets.append(int(p, 8))
                    elif p.isdigit():
                        octets.append(int(p, 10))
                    else:
                        raise ValueError("Invalid octet")
                if all(0 <= o <= 255 for o in octets):
                    return ipaddress.IPv4Address(".".join(str(o) for o in octets))
            except (ValueError, OverflowError):
                pass

        return None

    @classmethod
    def validate_url(cls, url: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validates URL scheme, hostname, and direct IP representation.
        Returns: (is_safe, block_reason, hostname)
        """
        if not url or not url.strip():
            return False, "URL cannot be empty", None

        try:
            parsed = urllib.parse.urlsplit(url.strip())
        except Exception as e:
            return False, f"Malformed URL syntax: {str(e)}", None

        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            return False, f"Prohibited scheme '{scheme}'. Only http:// and https:// are permitted.", None

        hostname = parsed.hostname
        if not hostname:
            return False, "URL hostname is missing or invalid", None

        hostname_lower = hostname.lower().strip(".")

        # Check prohibited hostname list
        if hostname_lower in PROHIBITED_HOSTNAMES or hostname_lower.endswith(".localhost") or hostname_lower.endswith(".local") or hostname_lower.endswith(".internal"):
            return False, f"Target hostname '{hostname}' is a prohibited local/internal host", hostname_lower

        # Check alternative IP encoding
        alt_ip = cls.parse_alternative_ip(hostname_lower)
        if alt_ip is not None:
            prohibited, reason = cls.is_ip_prohibited(alt_ip)
            if prohibited:
                return False, f"Prohibited destination IP: {reason}", str(alt_ip)

        return True, None, hostname_lower

    @classmethod
    def resolve_and_validate(cls, hostname: str, port: int = 80) -> Tuple[bool, Optional[str], List[str]]:
        """
        Resolves DNS for the hostname and validates all resolved IP addresses.
        Guards against DNS Rebinding attacks.
        Returns: (is_safe, block_reason, resolved_ips)
        """
        # If hostname itself is an IP, validate it directly
        direct_ip = cls.parse_alternative_ip(hostname)
        if direct_ip is not None:
            prohibited, reason = cls.is_ip_prohibited(direct_ip)
            if prohibited:
                return False, f"DNS validation failed: {reason}", [str(direct_ip)]
            return True, None, [str(direct_ip)]

        try:
            # Resolve both IPv4 and IPv6
            addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as gai:
            return False, f"DNS resolution failed for '{hostname}': {gai.strerror}", []
        except Exception as ex:
            return False, f"DNS resolution error for '{hostname}': {str(ex)}", []

        resolved_ips: List[str] = []
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip_str = sockaddr[0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)

        if not resolved_ips:
            return False, f"DNS resolution returned no records for '{hostname}'", []

        for ip_str in resolved_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                prohibited, reason = cls.is_ip_prohibited(ip_obj)
                if prohibited:
                    return False, f"DNS Rebinding Defense: Hostname '{hostname}' resolved to prohibited address ({reason})", resolved_ips
            except ValueError:
                return False, f"Invalid resolved IP format '{ip_str}'", resolved_ips

        return True, None, resolved_ips


ssrf_validator = SSRFValidator()
