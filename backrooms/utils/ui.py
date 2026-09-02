"""Rich-based console output helpers."""

from rich.console import Console
from rich.table import Table
from rich.text import Text

from backrooms.core.models import Host, Port, PortState

console = Console()

BACKROOMS_BANNER = r"""
██████╗  █████╗  ██████╗██╗  ██╗██████╗  ██████╗  ██████╗ ███╗   ███╗███████╗
██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██╔═══██╗██╔═══██╗████╗ ████║██╔════╝
██████╔╝███████║██║     █████╔╝ ██████╔╝██║   ██║██║   ██║██╔████╔██║███████╗
██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══██╗██║   ██║██║   ██║██║╚██╔╝██║╚════██║
██████╔╝██║  ██║╚██████╗██║  ██╗██║  ██║╚██████╔╝╚██████╔╝██║ ╚═╝ ██║███████║
╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚══════╝
"""


def print_banner() -> None:
    console.print(BACKROOMS_BANNER, style="bold yellow")
    console.print("Red Team Network Toolkit  |  Honeypot Labyrinth", style="dim")
    console.print()


def state_style(state: PortState) -> str:
    return {"open": "green", "closed": "red", "filtered": "yellow"}.get(state.value, "white")


def print_hosts(hosts: list[Host]) -> None:
    """Render scan results as an aligned table."""
    table = Table(title="Scan Results", show_lines=False)
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("MAC", style="magenta")
    table.add_column("Hostname", style="blue")
    table.add_column("OS", style="white")
    table.add_column("Open Ports", style="green")

    if not hosts:
        console.print("[yellow]No hosts discovered.[/yellow]")
        return

    for host in hosts:
        ports = ", ".join(str(p.port) for p in host.open_ports) or "-"
        table.add_row(
            host.ip,
            host.mac or "-",
            host.hostname or "-",
            host.os or "-",
            ports,
        )
    console.print(table)


def print_ports(host_ip: str, ports: list[Port]) -> None:
    table = Table(title=f"Ports for {host_ip}")
    table.add_column("Port", style="cyan")
    table.add_column("Protocol", style="magenta")
    table.add_column("State", style="white")
    table.add_column("Service", style="green")
    table.add_column("Version", style="blue")
    table.add_column("Banner", style="dim")

    for port in ports:
        table.add_row(
            str(port.port),
            port.protocol.value,
            Text(port.state.value, style=state_style(port.state)),
            port.service or "-",
            port.version or "-",
            (port.banner or "-")[:60],
        )
    console.print(table)
