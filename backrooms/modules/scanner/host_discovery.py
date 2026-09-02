"""Host discovery via ARP sweep and TCP ping."""

import asyncio
from dataclasses import dataclass

from backrooms.utils.network import ip_to_int


@dataclass
class DiscoveryResult:
    """A host discovered on the network."""

    ip: str
    mac: str | None = None
    latency_ms: float | None = None


async def arp_sweep(hosts: list[str], timeout: float = 1.0, concurrent: int = 100) -> list[DiscoveryResult]:
    """Discover active hosts using an ARP sweep.

    Relies on Scapy's asynchronous sendp and prnp. Falls back gracefully
    when running privileged operations are unavailable.

    Args:
        hosts: List of IPs to probe.
        timeout: Per-probe timeout in seconds.
        concurrent: Max in-flight probes.

    Returns:
        List of discovered hosts.

    Note:
        Requires root for raw ARP packets. When unavailable, an empty
        list is returned (TCP ping can be used instead).
    """
    semaphore = asyncio.Semaphore(concurrent)
    results: list[DiscoveryResult] = []

    async def probe(ip: str) -> None:
        async with semaphore:
            await asyncio.to_thread(_arp_probe, ip, timeout, results)

    await asyncio.gather(*(probe(ip) for ip in hosts))
    results.sort(key=lambda r: ip_to_int(r.ip))
    return results


def _arp_probe(ip: str, timeout: float, results: list[DiscoveryResult]) -> None:
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore[attr-defined]
    except ImportError:
        return
    try:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        answered, _ = srp(packet, timeout=timeout, verbose=False)
        for _, received in answered:
            results.append(DiscoveryResult(ip=ip, mac=received.hwsrc))
    except (OSError, PermissionError):
        return


async def tcp_ping(
    hosts: list[str],
    port: int = 80,
    timeout: float = 1.0,
    concurrent: int = 100,
) -> list[DiscoveryResult]:
    """Discover active hosts by attempting a TCP connect to a port."""
    semaphore = asyncio.Semaphore(concurrent)
    results: list[DiscoveryResult] = []

    async def probe(ip: str) -> None:
        async with semaphore:
            writer = None
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                )
            except (TimeoutError, OSError):
                return
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, RuntimeError):
                pass
            results.append(DiscoveryResult(ip=ip))

    await asyncio.gather(*(probe(ip) for ip in hosts))
    results.sort(key=lambda r: ip_to_int(r.ip))
    return results


async def discover(
    hosts: list[str],
    timeout: float = 1.0,
    concurrent: int = 100,
) -> list[DiscoveryResult]:
    """Run ARP sweep, falling back to TCP ping if no ARP results."""
    arp = await arp_sweep(hosts, timeout, concurrent)
    if arp:
        return arp
    return await tcp_ping(hosts, timeout=timeout, concurrent=concurrent)
