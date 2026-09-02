"""Passive OS fingerprinting based on TCP/IP stack behaviour.

Uses TTL and TCP window size heuristics. This is intentionally defensive
and informational; it relies on the host having opened a TCP connection.
"""

import asyncio
import random

from backrooms.core.exceptions import ScanError

_TTL_WINDOW_OS: list[tuple[int, int, str]] = [
    (64, 65535, "Linux / macOS / most modern Unix"),
    (128, 65535, "Windows (modern)"),
    (128, 8192, "Windows XP / 2000"),
    (64, 5840, "Linux (older / embedded)"),
    (255, 4128, "Cisco / network devices (TCP)"),
    (60, 16384, "AIX"),
    (64, 16384, "OpenBSD"),
    (64, 32120, "FreeBSD"),
]


def guess_os(ttl: int, window: int) -> str | None:
    """Best-effort OS guess from TTL and initial TCP window."""
    for ttl_bucket, window_bucket, label in _TTL_WINDOW_OS:
        if ttl == ttl_bucket and window == window_bucket:
            return label
    if ttl <= 64:
        return "Linux / Unix-like (likely)"
    if ttl >= 128:
        return "Windows / network device (likely)"
    return None


async def fingerprint(host: str, port: int = 80, timeout: float = 2.0) -> str | None:
    """Fingerprint a host's OS by opening a TCP connection and reading the SYN.

    Attempts to extract TTL and window size from the received packet.
    """
    try:
        from scapy.all import IP, TCP, sr  # type: ignore[attr-defined]
    except ImportError as exc:  # pragma: no cover
        raise ScanError("Scapy is required for OS fingerprinting") from exc

    sport = random.randint(49152, 65535)
    probe = IP(dst=host) / TCP(sport=sport, dport=port, flags="S")
    try:
        answered, _ = await asyncio.to_thread(
            sr, probe, timeout=timeout, verbose=False
        )
    except (OSError, PermissionError) as exc:
        raise ScanError(
            "OS fingerprinting requires root privileges for raw sockets"
        ) from exc

    for _, response in answered:
        tcp = response.getlayer(TCP)
        if tcp is None or not (tcp.flags & 0x12):  # SYN-ACK expected
            continue
        ttl = response.ttl
        window = tcp.window
        os_name = guess_os(ttl, window)
        if os_name:
            return os_name
        return f"ttl={ttl} window={window}"
    return None
