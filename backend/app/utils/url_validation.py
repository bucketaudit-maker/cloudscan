"""
URL validation utilities — SSRF protection for outbound HTTP requests.
"""
import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Private/reserved IP ranges that should not be reachable from server-side requests
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / AWS metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped IPv6
]


def _is_ip_blocked(ip_str: str) -> bool:
    """Check if an IP address falls within a blocked/private range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in _BLOCKED_NETWORKS)


def validate_url(url: str) -> str:
    """Validate a URL is safe for server-side requests (SSRF protection).

    Returns the validated URL string.
    Raises ValueError if the URL is unsafe.
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL is required")

    parsed = urlparse(url.strip())

    # Only allow http and https schemes
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are allowed")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must include a hostname")

    # Block obvious internal hostnames
    blocked_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "[::1]", "metadata.google.internal"}
    if hostname.lower() in blocked_hosts:
        raise ValueError("URLs pointing to localhost or internal services are not allowed")

    # Resolve hostname and check all resulting IPs
    try:
        addr_infos = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {hostname}")

    for family, _type, _proto, _canonname, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        if _is_ip_blocked(ip_str):
            raise ValueError("URL resolves to a private or reserved IP address")

    return url.strip()
