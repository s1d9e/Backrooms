"""Tests for the scanner module."""


import pytest

from backrooms.core.models import Host, Port, PortState, ScanType, ServiceProtocol
from backrooms.modules.scanner.port_scan import PortScanner, ScannerOptions
from backrooms.modules.scanner.scanner import NetworkScanner, ScanReport
from backrooms.modules.scanner.service_detect import match_banner
from backrooms.utils.network import checksum, resolve_hosts


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("192.168.1.1", ["192.168.1.1"]),
        ("192.168.1.0/30", ["192.168.1.1", "192.168.1.2"]),
        ("127.0.0.1", ["127.0.0.1"]),
    ],
)
def test_resolve_hosts(target: str, expected: list[str]) -> None:
    assert resolve_hosts(target) == expected


def test_resolve_hosts_hostname() -> None:
    hosts = resolve_hosts("localhost")
    assert "127.0.0.1" in hosts


def test_checksum_reference() -> None:
    assert checksum(b"\x45\x00\x00\x54") >= 0


@pytest.mark.parametrize(
    ("banner", "fallback", "expected"),
    [
        ("SSH-2.0-OpenSSH_9.2p1", "unknown", "ssh"),
        ("HTTP/1.1 200 OK", None, "http"),
        ("nginx/1.24.0", None, "http"),
        ("220 Microsoft FTP Service", "ftp", "ftp"),
        ("", "telnet", "telnet"),
        (None, None, None),
        ("garbage banner !!!", None, "garbage banner !!!"),
    ],
)
def test_match_banner(banner: str | None, fallback: str | None, expected: str | None) -> None:
    assert match_banner(banner, fallback) == expected


@pytest.mark.asyncio
async def test_connect_scan_localhost() -> None:
    scanner = PortScanner(ScannerOptions(ports=[22, 80, 443, 65533, 65534], timeout=0.3))
    results = await scanner.scan("127.0.0.1", ScanType.CONNECT)
    assert all(r.port in {22, 80, 443, 65533, 65534} for r in results)
    by_port = {r.port: r for r in results}
    # Closed high ports must be reported closed for connect scans.
    assert by_port[65533].state is PortState.CLOSED


@pytest.mark.asyncio
async def test_network_scanner_localhost() -> None:
    options = ScannerOptions(ports=[22, 65533], timeout=0.3)
    scanner = NetworkScanner(options)
    report = await scanner.scan_hosts(
        ["127.0.0.1"],
        scan_type=ScanType.CONNECT,
        discovery=False,
        fingerprint_os=False,
    )
    assert isinstance(report, ScanReport)
    assert report.total_hosts == 1
    host = report.hosts[0]
    assert host.ip == "127.0.0.1"
    assert all(isinstance(p.port, int) for p in host.ports)


def test_scan_report_properties() -> None:
    host = Host(
        ip="192.168.1.1",
        ports=[
            Port(port=22, state=PortState.OPEN, protocol=ServiceProtocol.TCP, service="ssh"),
            Port(port=81, state=PortState.CLOSED, protocol=ServiceProtocol.TCP),
            Port(port=80, state=PortState.OPEN, protocol=ServiceProtocol.TCP, service="http"),
        ],
    )
    report = ScanReport(target="x", hosts=[host])
    assert report.total_hosts == 1
    assert report.total_open_ports == 2
    assert [p.port for p in host.open_ports] == [22, 80]
