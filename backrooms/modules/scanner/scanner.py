"""High-level scan orchestration.

Ties together host discovery, port scanning, service detection and
OS fingerprinting into a single async pipeline.
"""

import asyncio
from dataclasses import dataclass

from backrooms.core.models import (
    Host,
    Port,
    PortState,
    ScanType,
    ServiceProtocol,
)
from backrooms.modules.scanner.host_discovery import (
    DiscoveryResult,
    discover,
)
from backrooms.modules.scanner.os_fingerprint import fingerprint
from backrooms.modules.scanner.port_scan import PortResult, PortScanner, ScannerOptions
from backrooms.modules.scanner.service_detect import match_banner
from backrooms.utils.network import resolve_hosts


@dataclass
class ScanReport:
    """Complete result of a scan run."""

    target: str
    hosts: list[Host]

    @property
    def total_hosts(self) -> int:
        return len(self.hosts)

    @property
    def total_open_ports(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)


class NetworkScanner:
    """Facade that runs a full or partial scan over targets."""

    def __init__(self, options: ScannerOptions | None = None) -> None:
        self.options = options or ScannerOptions()
        self.scanner = PortScanner(self.options)

    async def scan_hosts(
        self,
        targets: list[str],
        scan_type: ScanType = ScanType.SYN,
        port_range: list[int] | None = None,
        discovery: bool = True,
        fingerprint_os: bool = True,
    ) -> ScanReport:
        """Scan target IPs/CIDRs, discovering and profiling hosts."""
        if port_range is not None:
            self.options.ports = port_range
            self.scanner = PortScanner(self.options)

        hosts: list[Host] = []
        semaphore = asyncio.Semaphore(self.options.concurrent)

        for target in targets:
            if discovery:
                discovered = await discover(
                    resolve_hosts(target),
                    timeout=self.options.timeout,
                    concurrent=self.options.concurrent,
                )
            else:
                discovered = [DiscoveryResult(ip=ip) for ip in resolve_hosts(target)]

            if not discovered:
                continue

            results = await asyncio.gather(
                *(self._profile(entry, semaphore, scan_type, fingerprint_os) for entry in discovered)
            )
            hosts.extend(h for h in results if h is not None)

        return ScanReport(target=", ".join(targets), hosts=hosts)

    async def _profile(
        self,
        entry: DiscoveryResult,
        semaphore: asyncio.Semaphore,
        scan_type: ScanType,
        fingerprint_os: bool,
    ) -> Host | None:
        async with semaphore:
            return await self._profile_host(
                entry,
                scan_type=scan_type,
                fingerprint_os=fingerprint_os,
            )

    async def _profile_host(
        self,
        entry: DiscoveryResult,
        scan_type: ScanType,
        fingerprint_os: bool,
    ) -> Host:
        port_results = await self.scanner.scan(entry.ip, scan_type)
        open_ports = [p for p in port_results if p.state is PortState.OPEN]

        ports = await self._build_ports(entry.ip, open_ports)
        os_name = None
        if fingerprint_os and open_ports:
            os_name = await self._safe_fingerprint(entry.ip, open_ports)

        return Host(
            ip=entry.ip,
            mac=entry.mac,
            os=os_name,
            ports=ports,
        )

    async def _build_ports(self, host: str, open_ports: list[PortResult]) -> list[Port]:
        ports: list[Port] = []
        for result in open_ports:
            banner = await self.scanner.grab_banner(host, result.port)
            ports.append(
                Port(
                    port=result.port,
                    protocol=ServiceProtocol.TCP,
                    state=PortState.OPEN,
                    service=match_banner(banner, result.service),
                    banner=banner,
                )
            )
        return ports

    async def _safe_fingerprint(self, ip: str, open_ports: list[PortResult]) -> str | None:
        target_port = open_ports[0].port
        try:
            return await fingerprint(ip, target_port, self.options.timeout)
        except Exception:
            return None
