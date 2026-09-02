"""Service detection from banners and port hints."""

from backrooms.core.models import Port, PortState
from backrooms.modules.scanner.port_scan import PortScanner


def match_banner(banner: str | None, fallback: str | None) -> str | None:
    """Map a raw banner to a service name, with a port-hint fallback."""
    known = {
        "ssh": "ssh",
        "http": "http",
        "https": "https",
        "pop3": "pop3",
        "imap": "imap",
        "smtp": "smtp",
        "ftp": "ftp",
        "mysql": "mysql",
        "mariadb": "mariadb",
        "postgres": "postgresql",
        "redis": "redis",
        "mongodb": "mongod",
        "apache": "http",
        "nginx": "http",
        "iis": "http",
        "microsoft-ds": "microsoft-ds",
    }
    if not banner:
        return fallback
    lowered = banner.lower()
    for key, service in known.items():
        if key in lowered:
            return service
    return fallback or banner[:40]


async def detect_services(
    scanner: PortScanner,
    host: str,
    open_ports: list[Port],
) -> list[Port]:
    """Attach service names and banners to each open port."""
    for port in open_ports:
        if port.state is not PortState.OPEN:
            continue
        banner = await scanner.grab_banner(host, port.port)
        port.service = match_banner(banner, port.service)
        port.banner = banner
    return open_ports
