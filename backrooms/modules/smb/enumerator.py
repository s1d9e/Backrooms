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


def _build_negotiate() -> bytes:
    """Build a minimal valid SMB2 NEGOTIATE request (SMB 3.1.1)."""
    import struct

    # SMB2 header (64 bytes), MS-SMB2 2.2.1 sequential field layout.
    header = struct.pack(
        "<4sHHHHHHIIQIIQ16s",
        b"\xfeSMB",   # Protocol
        64,           # StructureSize
        0,            # CreditCharge
        0,            # ChannelSequence (reserved in request)
        0,            # Reserved
        0,            # Command = SMB2_NEGOTIATE
        1,            # CreditRequest = 1
        0,            # Flags
        0,            # NextCommand
        0,            # MessageId
        0,            # ProcessId (reserved)
        0,            # TreeId
        0,            # SessionId
        b"\x00" * 16,  # Signature
    )
    # SMB2_NEGOTIATE Request Body (MS-SMB2 2.2.3, dialect list without contexts).
    # StructureSize = 36 for SMB 3.1.1 contexts, but 28 when no contexts follow
    # (dialects 2.0.2..3.0.2). We advertise dialects without negotiate contexts.
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]  # SMB 2.0.2 .. 3.0.2
    body = struct.pack(
        "<HHHHI16s",
        28,              # StructureSize = sizeof(SMB2_NEGOTIATE_Request)
        len(dialects),   # DialectCount
        0x0002,          # SecurityMode = SIGNING_ENABLED
        0,               # Reserved
        0x00400000,      # Capabilities = DFS
        bytes.fromhex("00112233445566778899aabbccddeeff"),
    )
    dial_bytes = b"".join(struct.pack("<H", d) for d in dialects)
    payload = header + body + dial_bytes
    # NetBIOS Session Service header: 0x00 + 3-byte big-endian payload length.
    nbs = b"\x00" + len(payload).to_bytes(3, "big")
    return nbs + payload


#: Prebuilt SMB2 negotiate request delivered through port 445/139.
_NEGOTIATE = _build_negotiate()

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
        if b"\xfeSMB" not in raw[:8]:
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
        """Parse a NetBIOS Node Status (NBSTAT) response.

        Layout (RFC 1002 §4.2.18): a 34-byte encoded response name block, then
        a one-byte name count, then 18-byte name records, then a 6-byte MAC.
        Names in the records use NetBIOS first-level encoding truncated to 15
        bytes; we decode them when they look encoded and fall back to latin-1.
        """
        hostname = ""
        workgroup = ""
        try:
            if len(data) < 35:
                return "", "", ""
            num_names = data[34]
            records: list[bytes] = []
            pos = 35
            for _ in range(min(num_names, 20)):
                if pos + 18 > len(data):
                    break
                records.append(data[pos : pos + 18])
                pos += 18

            for rec in records:
                name_bytes = rec[:15]
                name = _decode_record_name(name_bytes)
                if not name:
                    continue
                if name.lower() in ("..__msbrowse__.", "..__msbrowse__"):
                    workgroup = name
                    continue
                if not hostname:
                    hostname = name
        except (IndexError, TypeError, ValueError):
            return "", "", ""
        return hostname, workgroup, ""


def _decode_record_name(name_bytes: bytes) -> str:
    """Decode a (possibly first-level encoded) NetBIOS name in a status record."""
    # Encoded names are ASCII 'A'..'Z' for both nibble bytes (all >= 0x41).
    if name_bytes and all(0x41 <= b <= 0x7A for b in name_bytes):
        decoded = _decode_netbios(name_bytes)
        if decoded:
            return decoded
    return name_bytes.decode("latin-1", errors="replace").rstrip(" \x00")


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
