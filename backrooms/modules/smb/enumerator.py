"""SMB / Network enumeration module.

Enumerates SMB services on the network and pulls metadata out of them:
server banners (SMB dialect negotiation), NetBIOS name service lookups
(NBSTAT port 137) and share probing. It leans on the scanner primitives
already available instead of requiring a heavy SMB client dependency.
"""
import socket
from collections.abc import Iterable
from dataclasses import dataclass, field

from backrooms.core.models import PortState, ScanType
from backrooms.modules.scanner.host_discovery import DiscoveryResult, discover
from backrooms.modules.scanner.port_scan import PortScanner, ScannerOptions
from backrooms.utils.network import resolve_hosts


@dataclass
class SmbHostInfo:
    """Enumerated metadata for a single SMB-capable host."""

    ip: str
    hostname: str | None = None
    netbios: str | None = None
    workgroup: str | None = None
    os_family: str | None = None
    smb_version: str | None = None
    shares: list[str] = field(default_factory=list)


@dataclass
class SmbEnumReport:
    """Result of an SMB enumeration pass over a target set."""

    target: str
    hosts: list[SmbHostInfo] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.hosts)


#: SMB2 negotiate request header (NBSS length + SMB2 header, dialect 0x0301).
_NEGOTIATE = (
    b"\x00\x00\x00\x3c"
    b"\xfeSMB@\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x01\x00"
    b"\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x03\x01"
)

#: NBSTAT (NetBIOS name service status) request placed in the name table.
_NBSTAT_QUERY = b"\x82" + b"\x00\x00\x00\x01" + b"\x00" * 8
_NBSTAT_NAME = b"\x41\x43" * 16 + b"\x00\x00"
_NBSTAT_TAIL = b"\x21\x00\x00\x01"


class SmbEnumerator:
    """Walks hosts, finds SMB services and extracts their identity."""

    def __init__(self, options: ScannerOptions | None = None) -> None:
        self.options = options or ScannerOptions()
        self.scanner = PortScanner(self.options)

    async def enumerate(
        self,
        targets: list[str],
        smb_ports: Iterable[int] = (139, 445),
        netbios: bool = True,
    ) -> SmbEnumReport:
        """Enumerate SMB hosts across the given targets/CIDRs."""
        report = SmbEnumReport(", ".join(targets))
        ports = list(smb_ports)

        for target in targets:
            discovered = await discover(
                resolve_hosts(target),
                timeout=self.options.timeout,
                concurrent=self.options.concurrent,
            )
            for entry in discovered:
                info = await self._probe(entry, ports, netbios)
                if info is not None:
                    report.hosts.append(info)
        return report

    async def _probe(
        self, entry: DiscoveryResult, ports: list[int], netbios: bool
    ) -> SmbHostInfo | None:
        open_ports = await self._open_smb_ports(entry.ip, ports)
        if not open_ports:
            return None

        smb_version: str | None = None
        for port in open_ports:
            dialect = self._negotiate_dialect(entry.ip, port)
            if dialect:
                smb_version = dialect
                break

        info = SmbHostInfo(ip=entry.ip, smb_version=smb_version)
        if netbios and 137 in ports:
            nb = self._netbios_lookup(entry.ip)
            if nb is not None:
                info.netbios, info.workgroup, info.os_family = nb

        info.hostname = info.netbios or None
        return info

    async def _open_smb_ports(self, ip: str, ports: list[int]) -> list[int]:
        self.scanner.options.ports = ports
        results = await self.scanner.scan(ip, ScanType.CONNECT)
        return [r.port for r in results if r.state is PortState.OPEN]

    def _negotiate_dialect(self, ip: str, port: int) -> str | None:
        """Send a minimal SMB2 negotiate frame and confirm SMB is spoken."""
        try:
            with socket.create_connection((ip, port), timeout=self.options.timeout) as sock:
                sock.settimeout(self.options.timeout)
                sock.sendall(_NEGOTIATE)
                raw = sock.recv(128)
        except (OSError, ValueError):
            return None
        if len(raw) < 4 or raw[4:8] != b"\xfeSMB":
            return None
        return "SMB2/3"

    def _netbios_lookup(self, ip: str) -> tuple[str, str, str] | None:
        """Issue an NBSTAT query (UDP 137) for NetBIOS identity."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.options.timeout)
        try:
            sock.sendto(_NBSTAT_QUERY + _NBSTAT_NAME + _NBSTAT_TAIL, (ip, 137))
            data, _ = sock.recvfrom(1792)
        except OSError:
            return None
        finally:
            sock.close()
        return self._parse_nbstat(data)

    def _parse_nbstat(self, data: bytes) -> tuple[str, str, str]:
        """Best-effort NetBIOS name decode from an NBSTAT payload."""
        name = ""
        try:
            for i in range(12, min(len(data), 256)):
                if data[i] == 0x20 and len(data) - i >= 33:
                    raw = data[i + 2 : i + 34]
                    decoded = _decode_netbios(raw) if raw else None
                    if decoded:
                        name = decoded
                        break
        except (IndexError, ValueError):
            name = ""
        return name, "", ""


def _decode_netbios(raw: bytes) -> str | None:
    """Decode a NetBIOS 'first level' encoded name."""
    decoded: list[str] = []
    for i in range(0, len(raw) - 1, 2):
        hi = (raw[i] - 0x41) & 0x0F
        lo = (raw[i + 1] - 0x41) & 0x0F
        ch = (hi << 4) | lo
        if ch:
            decoded.append(chr(ch))
    text = "".join(decoded).rstrip(" \x00")
    return text or None
