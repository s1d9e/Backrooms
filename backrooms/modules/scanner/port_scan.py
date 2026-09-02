"""Port scanning: SYN (default), CONNECT, ACK and UDP techniques."""

import asyncio
import random
import socket
import struct
from dataclasses import dataclass, field

from backrooms.core.exceptions import ScanError
from backrooms.core.models import Port, PortState, ScanType, ServiceProtocol
from backrooms.utils.network import checksum


@dataclass
class PortResult:
    """Result of a single port probe."""

    port: int
    state: PortState
    service: str | None = None
    banner: str | None = None


@dataclass
class ScannerOptions:
    """Tuning knobs for the scanner."""

    timeout: float = 1.0
    concurrent: int = 100
    retries: int = 1
    ports: list[int] = field(default_factory=lambda: list(range(1, 1024)))


_SERVICE_PORT_HINTS: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "sun-answerbook",
    27017: "mongod",
}


class PortScanner:
    """Port scanner supporting SYN, CONNECT, ACK and UDP scans."""

    def __init__(self, options: ScannerOptions | None = None) -> None:
        self.options = options or ScannerOptions()

    async def grab_banner(self, host: str, port: int) -> str | None:
        """Grab a banner from a single open port."""
        return await self._grab_banner(host, port, self.options.timeout)

    async def scan(self, host: str, scan_type: ScanType = ScanType.SYN) -> list[PortResult]:
        """Scan the given host for open ports."""
        if scan_type == ScanType.SYN:
            return await self._scan_syn(host)
        if scan_type == ScanType.CONNECT:
            return await self._scan_connect(host)
        if scan_type == ScanType.ACK:
            return await self._scan_ack(host)
        if scan_type == ScanType.UDP:
            return await self._scan_udp(host)
        raise ScanError(f"Unsupported scan type: {scan_type}")

    def _classify(self, port: int, protocol: ServiceProtocol) -> Port:
        return Port(
            port=port,
            protocol=protocol,
            state=PortState.CLOSED,
            service=_SERVICE_PORT_HINTS.get(port),
        )

    async def _scan_connect(self, host: str) -> list[PortResult]:
        semaphore = asyncio.Semaphore(self.options.concurrent)
        results: list[PortResult] = []

        async def probe(port: int) -> None:
            async with semaphore:
                state = await self._connect_probe(host, port)
                if state is PortState.OPEN:
                    banner = await self._grab_banner(host, port, self.options.timeout)
                else:
                    banner = None
                results.append(PortResult(port=port, state=state, banner=banner))

        await asyncio.gather(*(probe(p) for p in self.options.ports))
        results.sort(key=lambda r: r.port)
        return results

    async def _connect_probe(self, host: str, port: int) -> PortState:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.options.timeout
            )
        except (TimeoutError, OSError):
            return PortState.CLOSED
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, RuntimeError):
            pass
        return PortState.OPEN

    async def _grab_banner(self, host: str, port: int, timeout: float) -> str | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
        except (TimeoutError, OSError):
            return None
        try:
            banner = await asyncio.wait_for(reader.read(256), timeout=min(timeout, 2.0))
        except (TimeoutError, OSError):
            banner = b""
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, RuntimeError):
            pass
        if not banner:
            return None
        return banner.decode(errors="replace").strip()[:256]

    async def _scan_syn(self, host: str) -> list[PortResult]:
        try:
            from scapy.all import IP, TCP, sr  # type: ignore[attr-defined]
        except ImportError as exc:  # pragma: no cover
            raise ScanError("Scapy is required for SYN scans") from exc

        sport = random.randint(49152, 65535)
        packets = [IP(dst=host) / TCP(sport=sport, dport=p, flags="S") for p in self.options.ports]
        try:
            answered, _ = await asyncio.to_thread(
                sr, packets, timeout=self.options.timeout, verbose=False
            )
        except (OSError, PermissionError) as exc:
            raise ScanError(
                "SYN scan requires root privileges and raw socket access"
            ) from exc

        open_set: set[int] = set()
        for _, received in answered:
            if received.haslayer(TCP):
                open_set.add(int(received.sport))
        results: list[PortResult] = []
        for port in self.options.ports:
            if port in open_set:
                results.append(PortResult(port=port, state=PortState.OPEN))
            else:
                results.append(PortResult(port=port, state=PortState.CLOSED))
        results.sort(key=lambda r: r.port)
        return results

    async def _scan_ack(self, host: str) -> list[PortResult]:
        try:
            from scapy.all import IP, TCP, sr  # type: ignore[attr-defined]
        except ImportError as exc:  # pragma: no cover
            raise ScanError("Scapy is required for ACK scans") from exc

        sport = random.randint(49152, 65535)
        packets = [IP(dst=host) / TCP(sport=sport, dport=p, flags="A") for p in self.options.ports]
        try:
            answered, _ = await asyncio.to_thread(
                sr, packets, timeout=self.options.timeout, verbose=False
            )
        except (OSError, PermissionError) as exc:
            raise ScanError(
                "ACK scan requires root privileges and raw socket access"
            ) from exc

        unfiltered: set[int] = set()
        for _, received in answered:
            if received.haslayer(TCP):
                unfiltered.add(int(received.sport))
        results: list[PortResult] = []
        for port in self.options.ports:
            if port in unfiltered:
                results.append(PortResult(port=port, state=PortState.OPEN))
            else:
                results.append(PortResult(port=port, state=PortState.FILTERED))
        results.sort(key=lambda r: r.port)
        return results

    async def _scan_udp(self, host: str) -> list[PortResult]:
        semaphore = asyncio.Semaphore(self.options.concurrent)
        results: list[PortResult] = []

        async def probe(port: int) -> None:
            async with semaphore:
                state = await self._udp_probe(host, port)
                results.append(PortResult(port=port, state=state, service=_SERVICE_PORT_HINTS.get(port)))

        await asyncio.gather(*(probe(p) for p in self.options.ports))
        results.sort(key=lambda r: r.port)
        return results

    async def _udp_probe(self, host: str, port: int) -> PortState:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as raw:
            packet = self._build_udp(host, port, b"probe")
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, raw.sendto, packet, (host, port)
                )
            except (OSError, PermissionError):
                return PortState.FILTERED

            try:
                loop = asyncio.get_running_loop()
                await asyncio.wait_for(
                    loop.run_in_executor(None, raw.recvfrom, 512),
                    timeout=self.options.timeout,
                )
                return PortState.OPEN
            except (TimeoutError, OSError):
                return PortState.FILTERED

    @staticmethod
    def _build_udp(dst: str, dport: int, payload: bytes) -> bytes:
        src_ip = "0.0.0.0"
        sport = random.randint(49152, 65535)
        length = 8 + len(payload)
        pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst)
        pseudo += struct.pack("!BBH", 0, socket.IPPROTO_UDP, length)
        udp = struct.pack("!HHHH", sport, dport, length, 0) + payload
        csum = checksum(pseudo + udp)
        udp = struct.pack("!HHHH", sport, dport, length, csum) + payload
        return udp
