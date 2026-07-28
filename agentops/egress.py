"""SSRF guard for connector HTTP egress.

Connectors are created by org admins (not just the platform superadmin), so a
tenant could point one at an internal address (``169.254.169.254`` cloud
metadata, ``10.x``, ``localhost``) and coerce the server into fetching it via the
connector test endpoint or an agent execute. When enabled (see
``Settings.egress_guard_enabled``) this rejects requests whose host resolves to a
private / loopback / link-local / reserved / metadata address.

Residual risk: a DNS-rebinding host could pass this check and then resolve to an
internal IP at request time. Pair this with network egress controls for full
protection.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from .config import get_settings

# Hostnames used by cloud metadata services (some resolve to public-looking IPs).
_BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "metadata",
}


def _host_is_internal(host: str) -> bool:
    if not host:
        return True
    if host.lower() in _BLOCKED_HOSTNAMES:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True  # unresolvable -> fail closed
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return True
    return False


def check_egress(url: str) -> None:
    """Raise ``ValueError`` if egress to ``url`` is blocked (when the guard is on)."""
    if not get_settings().egress_guard_enabled():
        return
    host = urlparse(url).hostname
    if _host_is_internal(host or ""):
        raise ValueError(
            f"egress to '{host}' is blocked (private/internal address; "
            "set AGENTOPS_BLOCK_PRIVATE_EGRESS=false to allow)"
        )
