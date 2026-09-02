"""Backrooms CLI entry point."""

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.text import Text

from backrooms.core.config import ConfigManager
from backrooms.core.models import ScanType
from backrooms.honeypot.labyrinth import LabyrinthTracker
from backrooms.honeypot.manager import DecoyStatus
from backrooms.honeypot.models import HoneypotConfig
from backrooms.modules.scanner.port_scan import PortResult
from backrooms.modules.scanner.scanner import NetworkScanner, ScanReport
from backrooms.utils.ui import console, print_banner, print_hosts

# Default location for the honeypot configuration file.
DEFAULT_HONEYPOT_CONFIG = Path.home() / ".config" / "backrooms" / "honeypot.yaml"

app = typer.Typer(
    name="backrooms",
    help="Red Team Network Toolkit with Honeypot Labyrinth",
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)

scan_app = typer.Typer(
    help="Network scanning: host discovery, port scan, OS fingerprint",
    no_args_is_help=True,
)
app.add_typer(scan_app, name="scan")

mitm_app = typer.Typer(help="Man-in-the-Middle attacks", no_args_is_help=True)
app.add_typer(mitm_app, name="mitm")

wireless_app = typer.Typer(help="Wireless attacks", no_args_is_help=True)
app.add_typer(wireless_app, name="wireless")

smb_app = typer.Typer(help="SMB enumeration", no_args_is_help=True)
app.add_typer(smb_app, name="smb")

honeypot_app = typer.Typer(help="Honeypot labyrinth deployment", no_args_is_help=True)
app.add_typer(honeypot_app, name="honeypot")


def _print_version(value: bool) -> None:
    if value:
        from backrooms import __version__

        console.print(f"[bold yellow]backrooms[/bold yellow] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: Annotated[bool, typer.Option("--version", "-V", help="Show version")] = False,
    config: Annotated[Path | None, typer.Option(help="Path to config file")] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Suppress banner")] = False,
) -> None:
    """Backrooms CLI."""
    _print_version(version)
    if not quiet:
        print_banner()
    ctx.obj = ConfigManager(config).load()


@app.command("tui")
def tui_command() -> None:
    """Launch the interactive TUI dashboard."""
    from backrooms.tui.app import run_tui

    run_tui()


@honeypot_app.command("deploy")
def honeypot_deploy(
    config: Annotated[Path, typer.Argument(help="Path to honeypot YAML config")],
    build_only: Annotated[bool, typer.Option("--build-only", help="Build without starting")] = False,
) -> None:
    """Deploy the honeypot labyrinth of fake machines."""
    from backrooms.honeypot.config import load_honeypot_config
    from backrooms.honeypot.manager import HoneypotManager

    cfg = load_honeypot_config(config)
    manager = HoneypotManager(cfg)

    with console.status("[bold cyan]Deploying labyrinth...") as status:
        status.update("[cyan]Pulling base image and starting decoys...")
        statuses = manager.deploy()

    _print_decoys(statuses)
    _print_labyrinth_hint(cfg)


@honeypot_app.command("status")
def honeypot_status(
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Path to honeypot YAML config")
    ] = DEFAULT_HONEYPOT_CONFIG,
) -> None:
    """Show live status of deployed decoys."""
    from backrooms.honeypot.config import load_honeypot_config
    from backrooms.honeypot.manager import HoneypotManager

    cfg = load_honeypot_config(config)
    manager = HoneypotManager(cfg)
    _print_decoys(manager.status())


@honeypot_app.command("logs")
def honeypot_logs(
    name: Annotated[str, typer.Argument(help="Decoy name")],
    tail: Annotated[int, typer.Option("--tail", help="Lines to show")] = 200,
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Path to honeypot YAML config")
    ] = DEFAULT_HONEYPOT_CONFIG,
) -> None:
    """Show recent container logs for a decoy."""
    from backrooms.honeypot.config import load_honeypot_config
    from backrooms.honeypot.manager import HoneypotManager

    cfg = load_honeypot_config(config)
    manager = HoneypotManager(cfg)
    console.print(manager.logs(name, tail=tail))


@honeypot_app.command("destroy")
def honeypot_destroy(
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Path to honeypot YAML config")
    ] = DEFAULT_HONEYPOT_CONFIG,
    force: Annotated[bool, typer.Option("--force", "-f", help="Skip confirmation")] = False,
) -> None:
    """Stop and remove all decoys and the labyrinth network."""
    from backrooms.honeypot.config import load_honeypot_config
    from backrooms.honeypot.manager import HoneypotManager

    if not force:
        typer.confirm("Destroy all decoys and the labyrinth network?", abort=True)
    cfg = load_honeypot_config(config)
    manager = HoneypotManager(cfg)
    removed = manager.destroy()
    if removed:
        console.print(f"[green]Removed: {', '.join(removed)}[/green]")
    else:
        console.print("[yellow]No decoys were running.[/yellow]")


@scan_app.command("hosts")
def scan_hosts(
    target: Annotated[str, typer.Argument(help="IP, hostname or CIDR to scan")],
    timeout: Annotated[float, typer.Option("--timeout", help="Probe timeout (s)")] = 1.0,
    concurrent: Annotated[int, typer.Option("--concurrent", help="Concurrent probes")] = 100,
) -> None:
    """Discover active hosts on a network."""
    from backrooms.modules.scanner.host_discovery import discover
    from backrooms.utils.network import resolve_hosts

    hosts = resolve_hosts(target)
    results = asyncio.run(discover(hosts, timeout=timeout, concurrent=concurrent))
    from rich.table import Table

    tbl = Table(title=f"Hosts on {target}")
    tbl.add_column("IP", style="cyan")
    tbl.add_column("MAC", style="magenta")
    for r in results:
        tbl.add_row(r.ip, r.mac or "-")
    console.print(tbl)


@scan_app.command("ports")
def scan_ports(
    target: Annotated[str, typer.Argument(help="IP or hostname to scan")],
    port_range: Annotated[str, typer.Option("--ports", "-p", help="e.g. 80,443 or 1-1000")] = "1-1024",
    scan_type: Annotated[ScanType, typer.Option("--type", help="Scan technique")] = ScanType.SYN,
    timeout: Annotated[float, typer.Option("--timeout", help="Probe timeout (s)")] = 1.0,
    concurrent: Annotated[int, typer.Option("--concurrent", help="Concurrent probes")] = 100,
) -> None:
    """Scan ports on a host and detect services."""
    from backrooms.modules.scanner.port_scan import PortScanner, ScannerOptions
    from backrooms.utils.network import resolve_hosts

    hosts = resolve_hosts(target)
    if len(hosts) > 1:
        console.print("[yellow]Ports scan is limited to a single host; using first.[/yellow]")

    ports = _parse_port_range(port_range)
    options = ScannerOptions(timeout=timeout, concurrent=concurrent, ports=ports)
    scanner = PortScanner(options)
    for host in hosts:
        results = asyncio.run(scanner.scan(host, scan_type))
        print_ports_data(host, results)


@scan_app.command("full")
def scan_full(
    target: Annotated[str, typer.Argument(help="IP, hostname or CIDR")],
    port_range: Annotated[str, typer.Option("--ports", "-p", help="e.g. 80,443 or 1-1000")] = "1-1024",
    scan_type: Annotated[ScanType, typer.Option("--type", help="Scan technique")] = ScanType.SYN,
    timeout: Annotated[float, typer.Option("--timeout", help="Probe timeout (s)")] = 1.0,
    concurrent: Annotated[int, typer.Option("--concurrent", help="Concurrent probes")] = 100,
    no_discovery: Annotated[bool, typer.Option("--no-discovery", help="Skip host discovery")] = False,
    no_os: Annotated[bool, typer.Option("--no-os", help="Skip OS fingerprinting")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON")] = False,
) -> None:
    """Full scan: discover hosts, scan ports, detect services and OS."""
    from backrooms.modules.scanner.port_scan import ScannerOptions

    options = ScannerOptions(timeout=timeout, concurrent=concurrent, ports=_parse_port_range(port_range))
    scanner = NetworkScanner(options)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        console=console,
        transient=True,
    ) as progress:
        description = f"[bold cyan]Scanning {target}..."
        task = progress.add_task(description, total=None)
        report = asyncio.run(
            scanner.scan_hosts(
                [target],
                scan_type=scan_type,
                discovery=not no_discovery,
                fingerprint_os=not no_os,
            )
        )
        progress.update(task, completed=True)

    if json_output:
        _emit_json(report)
    else:
        print_hosts(report.hosts)


@smb_app.command("enum")
def smb_enum(
    target: Annotated[str, typer.Argument(help="IP, hostname or CIDR")],
    ports: Annotated[str, typer.Option("--ports", "-p", help="SMB ports to probe (139,445)")] = "139,445",
    timeout: Annotated[float, typer.Option("--timeout", help="Probe timeout (s)")] = 1.0,
    no_netbios: Annotated[bool, typer.Option("--no-netbios", help="Skip NetBIOS name lookup")] = False,
) -> None:
    """Enumerate SMB hosts and their identities across a network."""
    from rich.table import Table

    from backrooms.modules.scanner.port_scan import ScannerOptions
    from backrooms.modules.smb.enumerator import SmbEnumerator

    options = ScannerOptions(timeout=timeout)
    enumerator = SmbEnumerator(options)
    report = asyncio.run(
        enumerator.enumerate([target], smb_ports=_parse_port_range(ports), netbios=not no_netbios)
    )

    if not report.hosts:
        console.print("[yellow]No SMB hosts found.[/yellow]")
        return

    tbl = Table(title=f"SMB hosts on {target}")
    tbl.add_column("IP", style="cyan")
    tbl.add_column("Hostname", style="magenta")
    tbl.add_column("SMB", style="green")
    tbl.add_column("NetBIOS", style="yellow")
    for host in report.hosts:
        tbl.add_row(
            host.ip,
            host.hostname or "-",
            host.smb_version or "-",
            host.netbios or "-",
        )
    console.print(tbl)


@mitm_app.command("arp")
def mitm_arp(
    target: Annotated[str, typer.Argument(help="Victim IP whose ARP cache to poison")],
    gateway: Annotated[str, typer.Option("--gateway", "-g", help="Gateway/router IP to impersonate")],
    interface: Annotated[str | None, typer.Option("--interface", "-i", help="Network interface")] = None,
) -> None:
    """Poison ARP to forward the victim's traffic through this host."""
    from backrooms.modules.mitm.core import ArpSpoof
    from backrooms.utils.network import get_default_interface

    iface = interface or get_default_interface()
    if gateway is None:
        console.print("[red]--gateway is required[/red]")
        raise typer.Exit(2)
    console.print(
        f"[cyan]Poisoning[/cyan] {target} <-> {gateway} on [yellow]{iface}[/yellow] "
        "(Ctrl+C to stop and restore)"
    )
    spoof = ArpSpoof(target, gateway, iface)
    try:
        spoof.poison_loop()
    except KeyboardInterrupt:
        console.print("\n[green]ARP cache restored.[/green]")


@mitm_app.command("forward")
def mitm_forward(
    local_port: Annotated[int, typer.Argument(help="Local listen port")],
    target: Annotated[str, typer.Argument(help="Target host:port, e.g. 192.168.1.10:80")],
    local_host: Annotated[str, typer.Option("--listen", help="Local bind address")] = "0.0.0.0",  # noqa: S104
    quiet: Annotated[bool, typer.Option("--quiet", help="Suppress captured-payload echo")] = False,
) -> None:
    """Transparently forward TCP connections and capture credentials."""
    from rich.table import Table

    from backrooms.modules.mitm.core import TcpForwarder

    if ":" not in target:
        console.print("[red]target must be host:port[/red]")
        raise typer.Exit(2)
    t_host, t_port_str = target.rsplit(":", 1)
    t_port = int(t_port_str)

    forwarder = TcpForwarder()
    console.print(
        f"[cyan]Forwarding[/cyan] {local_host}:{local_port} -> [yellow]{t_host}:{t_port}[/yellow] "
        "(Ctrl+C to stop)"
    )
    try:
        asyncio.run(forwarder.run(local_host, local_port, t_host, t_port))
    except KeyboardInterrupt:
        console.print("\n[green]Forwarder stopped.[/green]")

    if not quiet and forwarder.hits:
        tbl = Table(title="Captured credential-like payloads")
        tbl.add_column("Source", style="cyan")
        tbl.add_column("Direction", style="magenta")
        tbl.add_column("Marker", style="yellow")
        tbl.add_column("Payload", style="white")
        for hit in forwarder.hits:
            tbl.add_row(hit.source, hit.direction, hit.marker, hit.payload)
        console.print(tbl)
    else:
        console.print("[dim]No credential-like payloads captured.[/dim]")
    if forwarder.active_connections:
        console.print(f"[dim]{forwarder.active_connections} connections were active.[/dim]")


@wireless_app.command("interfaces")
def wireless_interfaces() -> None:
    """List wireless interfaces available for monitoring."""
    from backrooms.modules.wireless.core import list_wireless_interfaces

    ifaces = list_wireless_interfaces()
    if not ifaces:
        console.print("[yellow]No wireless interfaces found (iw may be missing).[/yellow]")
        return
    for iface in ifaces:
        console.print(f"[cyan]{iface}[/cyan]")


@wireless_app.command("monitor")
def wireless_monitor(
    interface: Annotated[str, typer.Argument(help="Wireless interface name")],
    mode: Annotated[str, typer.Option("--mode", "-m", help="monitor or managed")] = "monitor",
) -> None:
    """Switch a wireless interface into/out of monitor mode."""
    from backrooms.modules.wireless.core import set_monitor_mode

    enable = mode.lower() == "monitor"
    try:
        set_monitor_mode(interface, enable)
    except Exception as exc:  # noqa: BLE001 - surface the error cleanly
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    mode_label = "monitor" if enable else "managed"
    console.print(f"[green]{interface}[/green] set to [yellow]{mode_label}[/yellow] mode")


@wireless_app.command("scan")
def wireless_scan(
    interface: Annotated[str, typer.Argument(help="Monitor-mode interface")],
    timeout: Annotated[float, typer.Option("--timeout", help="Beacon capture duration (s)")] = 3.0,
) -> None:
    """Scan for access points on a monitor interface."""
    from rich.table import Table

    from backrooms.modules.wireless.core import scan_access_points

    result = scan_access_points(interface, timeout=timeout)
    if not result.access_points:
        console.print("[yellow]No access points captured.[/yellow]")
        return
    tbl = Table(title=f"Access Points on {interface}")
    tbl.add_column("BSSID", style="cyan")
    tbl.add_column("SSID", style="magenta")
    tbl.add_column("CH", style="yellow")
    tbl.add_column("Privacy", style="green")
    for ap in result.access_points:
        tbl.add_row(ap.bssid, ap.ssid or "<hidden>", str(ap.channel) or "-", ap.encryption)
    console.print(tbl)


@wireless_app.command("deauth")
def wireless_deauth(
    bssid: Annotated[str, typer.Argument(help="Target AP BSSID")],
    interface: Annotated[str, typer.Option("--interface", "-i", help="Monitor interface")] = "",
    victim: Annotated[str, typer.Option("--victim", help="Client MAC (defaults to broadcast)")] = (
        "ff:ff:ff:ff:ff:ff"
    ),
    count: Annotated[int, typer.Option("--count", help="Frames to send")] = 10,
) -> None:
    """Send 802.11 deauthentication frames (requires monitor mode / root)."""
    from backrooms.modules.wireless.core import deauth_burst

    sent = deauth_burst(bssid, victim_mac=victim, interface=interface, count=count)
    console.print(f"[green]Sent {sent} deauth frame(s) to {bssid}.[/green]")


def _emit_json(report: ScanReport) -> None:
    import json

    payload = [
        {
            "ip": h.ip,
            "mac": h.mac,
            "os": h.os,
            "ports": [
                {"port": p.port, "protocol": p.protocol.value, "state": p.state.value,
                 "service": p.service, "version": p.version, "banner": p.banner}
                for p in h.ports
            ],
        }
        for h in report.hosts
    ]
    console.print(json.dumps(payload, indent=2))


def _parse_port_range(spec: str) -> list[int]:
    """Parse '80,443,1-1000' style port specifications."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                lo_i, hi_i = int(lo), int(hi)
            except ValueError as exc:
                raise typer.BadParameter(f"Invalid port range: {part!r}") from exc
            if not (0 < lo_i <= 65535 and 0 < hi_i <= 65535 and lo_i <= hi_i):
                raise typer.BadParameter(f"Invalid port range: {part!r}")
            ports.update(range(lo_i, hi_i + 1))
        else:
            try:
                port = int(part)
            except ValueError as exc:
                raise typer.BadParameter(f"Invalid port: {part!r}") from exc
            if not (0 < port <= 65535):
                raise typer.BadParameter(f"Port out of range: {port}")
            ports.add(port)
    if not ports:
        raise typer.BadParameter("Empty port specification")
    return sorted(ports)


def print_ports_data(host: str, results: list[PortResult]) -> None:
    """Render port scan results for a single host."""
    from backrooms.core.models import Port, ServiceProtocol
    from backrooms.utils.ui import print_ports

    ports = [
        Port(
            port=r.port,
            protocol=ServiceProtocol.TCP,
            state=r.state,
            service=r.service,
            banner=r.banner,
        )
        for r in results
    ]
    print_ports(host, ports)


@honeypot_app.command("track")
def honeypot_track(
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Path to honeypot YAML config")
    ] = DEFAULT_HONEYPOT_CONFIG,
    interval: Annotated[float, typer.Option("--interval", help="Poll interval (s)")] = 2.0,
) -> None:
    """Stream decoy events and show attacker positions in the maze (Ctrl+C to stop)."""
    from backrooms.honeypot.config import load_honeypot_config
    from backrooms.honeypot.ids.logger import IdsLogger
    from backrooms.honeypot.ingest import wait_and_ingest
    from backrooms.honeypot.labyrinth import LabyrinthTracker
    from backrooms.honeypot.manager import HoneypotManager

    cfg = load_honeypot_config(config)
    manager = HoneypotManager(cfg)
    tracker = LabyrinthTracker(
        cfg.labyrinth, IdsLogger(cfg.ids), decoy_names=[d.name for d in cfg.decoys]
    )
    console.print("[dim]Tailing labyrinth... press Ctrl+C to stop.[/dim]")
    try:
        wait_and_ingest(manager, tracker, interval=interval)
    except KeyboardInterrupt:
        console.print()
        _print_attacker_sessions(tracker)


@honeypot_app.command("paths")
def honeypot_paths(
    config: Annotated[
        Path, typer.Option("--config", "-c", help="Path to honeypot YAML config")
    ] = DEFAULT_HONEYPOT_CONFIG,
) -> None:
    """Show attacker paths through the maze, deduced from the IDS database."""
    from backrooms.honeypot.config import load_honeypot_config
    from backrooms.honeypot.ids.logger import IdsLogger
    from backrooms.honeypot.labyrinth import LabyrinthTracker

    cfg = load_honeypot_config(config)
    logger = IdsLogger(cfg.ids)
    tracker = LabyrinthTracker(
        cfg.labyrinth, logger, decoy_names=[d.name for d in cfg.decoys]
    )

    # Rebuild sessions from persisted connection events.
    interesting = {
        "connection", "ssh_handshake", "http", "telnet", "ftp",
        "smb", "mysql", "postgres",
    }
    for event in logger.history(limit=5000):
        source = event.get("source_ip")
        decoy = event.get("decoy")
        if source and decoy and decoy != "labyrinth" and event.get("kind") in interesting:
            tracker.record_hit(decoy, source)
    _print_attacker_sessions(tracker)


def _print_attacker_sessions(tracker: LabyrinthTracker) -> None:
    from rich.table import Table

    sessions = tracker.sessions()
    if not sessions:
        console.print("[yellow]No attacker sessions recorded yet.[/yellow]")
        return
    table = Table(title="Attacker Sessions in the Labyrinth")
    table.add_column("Source IP", style="cyan")
    table.add_column("Hops", style="white")
    table.add_column("Path", style="yellow")
    table.add_column("State", style="green")
    for session in sessions:
        state = "LOST" if session.lost else "wandering"
        table.add_row(
            session.source_ip,
            str(session.hop_count),
            " -> ".join(session.path) or "-",
            Text(state.upper(), style="bold red" if session.lost else "bold green"),
        )
    console.print(table)


def _print_decoys(statuses: list[DecoyStatus]) -> None:
    from rich.table import Table

    table = Table(title="Labyrinth Decoys")
    table.add_column("Name", style="cyan")
    table.add_column("Container", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("IP", style="blue")
    table.add_column("Services", style="yellow")
    for status in statuses:
        services = ", ".join(s.value for s in status.spec.services)
        table.add_row(
            status.spec.name,
            status.container_id[:12],
            Text(status.status.upper(), style="bold green" if status.status == "running" else "bold red"),
            status.ip or "-",
            services,
        )
    console.print(table)


def _print_labyrinth_hint(cfg: HoneypotConfig) -> None:
    max_hops = cfg.labyrinth.max_hops
    console.print(
        f"[dim]Labyrinth active with up to {max_hops} redirect hops. "
        f"Attackers will circle between the fake machines above.[/dim]"
    )


DEFAULT_HONEYPOT_CONFIG = Path.home() / ".config" / "backrooms" / "honeypot.yaml"


DEFAULT_HONEYPOT_CONFIG = Path.home() / ".config" / "backrooms" / "honeypot.yaml"


if __name__ == "__main__":
    app()
