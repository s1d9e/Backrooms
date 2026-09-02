"""Network utilities: IP/subnet helpers, interface discovery."""

import ipaddress
import socket
from collections.abc import Iterable

import netifaces

from backrooms.core.exceptions import HostUnreachableError, NetworkError


def resolve_hosts(target: str) -> list[str]:
    """Expand a target (single IP, hostname, or CIDR) into a list of IPs.

    Args:
        target: A single IP, hostname, or CIDR block.

    Returns:
        A list of IPv4 addresses, including network/broadcast for CIDRs
        unless they fall in the subnet.
    """
    candidate = target.strip()

    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        network = None

    if network is not None:
        return [str(ip) for ip in network.hosts()]

    try:
        resolved = ipaddress.ip_address(candidate)
    except ValueError:
        try:
            resolved = ipaddress.ip_address(socket.gethostbyname(candidate))
        except OSError as exc:
            raise HostUnreachableError(f"Cannot resolve target {target!r}") from exc

    return [str(resolved)]


def iter_hosts(targets: Iterable[str]) -> list[str]:
    """Flatten multiple targets into a deduplicated host list."""
    seen: set[str] = set()
    for target in targets:
        for host in resolve_hosts(target):
            seen.add(host)
    return sorted(seen, key=lambda ip: int(ipaddress.ip_address(ip)))


def get_default_interface() -> str:
    """Return the default network interface name."""
    gateways = netifaces.gateways()
    default = gateways.get("default", {})
    if "default" in default:
        iface = default["default"][1]
    else:
        sorted_keys = sorted(default, key=str)
        if sorted_keys:
            iface = default[sorted_keys[0]][1]
        else:
            raise NetworkError("No default route found; specify an interface explicitly")
    return str(iface)


def get_interface_ips(interface: str) -> list[str]:
    """Return the IPv4 addresses bound to a network interface."""
    addrs = netifaces.ifaddresses(interface)
    if netifaces.AF_INET not in addrs:
        return []
    return [entry["addr"] for entry in addrs[netifaces.AF_INET] if "addr" in entry]


def ip_to_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


def checksum(data: bytes) -> int:
    """Compute internet checksum for packet construction (TCP/UDP/IP)."""
    if len(data) % 2:
        data += b"\x00"
    total = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF
