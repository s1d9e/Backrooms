"""Docker-based honeypot decoy lifecycle management.

Creates isolated containers that listen on various fake services and
belong to a dedicated user-defined Docker network. The host forwards
external traffic on selected ports to the decoys.
"""

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backrooms.core.exceptions import DockerError
from backrooms.honeypot.ids.logger import IdsLogger, classify_command
from backrooms.honeypot.models import DecoySpec, HoneypotConfig

_BASE_IMAGE = "python:3.12-slim"

_DECOY_SCRIPT = r"""
import socket
import subprocess
import sys
import threading
import time
import os
import json

HOST = "0.0.0.0"
FAKE_HOSTNAME = os.environ.get("BR_HOSTNAME", "decoy")

def log(kind, detail="", src=""):
    payload = json.dumps(
        {"ts": time.time(), "host": FAKE_HOSTNAME, "kind": kind, "detail": detail, "src": src}
    )
    print(payload, flush=True)


def peer_ip(conn):
    try:
        return str(conn.getpeername()[0])
    except (OSError, IndexError):
        return ""


def http_srv():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, 80))
    srv.listen(16)
    log("service", "http listening on :80")
    while True:
        conn, _ = srv.accept()
        log("connection", "tcp/80", peer_ip(conn))
        threading.Thread(target=http_handle, args=(conn,), daemon=True).start()


def http_handle(conn):
    try:
        data = conn.recv(4096)
        request = data.decode(errors="replace")
        for line in request.splitlines():
            if line.startswith("Host:"):
                log("http", line, peer_ip(conn))
        body = (b"<html><body><h1>Welcome</h1>"
                b"<p>Internal server of %s</p></body></html>"
                % FAKE_HOSTNAME.encode())
        header = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                  b"Content-Length: %d\r\n\r\n" % len(body))
        conn.sendall(header + body)
    except OSError:
        pass
    finally:
        conn.close()


def ssh_srv():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, 22))
    srv.listen(16)
    log("service", "ssh (fake banner) listening on :22")
    while True:
        conn, _ = srv.accept()
        log("connection", "tcp/22", peer_ip(conn))
        threading.Thread(target=ssh_handle, args=(conn,), daemon=True).start()


def ssh_handle(conn):
    log("ssh_handshake", "banner offered", peer_ip(conn))
    ident = ("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2").encode()
    conn.sendall(ident + b"\r\n")
    try:
        time.sleep(30)
    except (OSError, KeyboardInterrupt):
        pass
    finally:
        conn.close()


def grep_services():
    services = os.environ.get("BR_SERVICES", "http")
    for name in services.split(","):
        name = name.strip()
        if name == "http":
            threading.Thread(target=http_srv, daemon=True).start()
        elif name == "ssh":
            threading.Thread(target=ssh_srv, daemon=True).start()
        elif name == "telnet":
            threading.Thread(target=telnet_srv, daemon=True).start()
        elif name == "ftp":
            threading.Thread(target=ftp_srv, daemon=True).start()


def telnet_srv():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, 23))
    srv.listen(16)
    log("service", "telnet listening on :23")
    while True:
        conn, _ = srv.accept()
        log("connection", "tcp/23", peer_ip(conn))
        threading.Thread(target=telnet_handle, args=(conn,), daemon=True).start()


def telnet_handle(conn):
    conn.sendall(b"login: ")
    try:
        data = conn.recv(4096)
        if data:
            log("telnet", data.decode(errors="replace").strip()[:120], peer_ip(conn))
    except OSError:
        pass
    conn.close()


def ftp_srv():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, 21))
    srv.listen(16)
    log("service", "ftp (fake banner) listening on :21")
    while True:
        conn, _ = srv.accept()
        log("connection", "tcp/21", peer_ip(conn))
        threading.Thread(target=ftp_handle, args=(conn,), daemon=True).start()


def ftp_handle(conn):
    conn.sendall(b"220 (vsFTPd 3.0.5)\r\n")
    try:
        data = conn.recv(4096)
        if data:
            log("ftp", data.decode(errors="replace").strip()[:120], peer_ip(conn))
            conn.sendall(b"530 Please login with USER and PASS.\r\n")
    except OSError:
        pass
    conn.close()


def smb_srv():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, 445))
    srv.listen(8)
    log("service", "smb (fake) listening on :445")
    while True:
        conn, _ = srv.accept()
        log("connection", "tcp/445", peer_ip(conn))
        threading.Thread(target=smb_handle, args=(conn,), daemon=True).start()


def smb_handle(conn):
    try:
        data = conn.recv(4096)
        if data:
            log("smb", "negotiate attempt %d bytes" % len(data), peer_ip(conn))
    except OSError:
        pass
    conn.close()


def rdp_srv():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, 3389))
    srv.listen(8)
    log("service", "rdp (fake) listening on :3389")
    while True:
        conn, _ = srv.accept()
        log("connection", "tcp/3389", peer_ip(conn))
        threading.Thread(target=rdp_handle, args=(conn,), daemon=True).start()


def rdp_handle(conn):
    try:
        conn.sendall(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00")
        conn.recv(4096)
    except OSError:
        pass
    conn.close()


def mysql_srv():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, 3306))
    srv.listen(8)
    log("service", "mysql (fake) listening on :3306")
    while True:
        conn, _ = srv.accept()
        log("connection", "tcp/3306", peer_ip(conn))
        threading.Thread(target=mysql_handle, args=(conn,), daemon=True).start()


def mysql_handle(conn):
    # MySQL handshake
    payload = b"\x0a" + b"\x00" * 27
    try:
        conn.sendall(payload)
        data = conn.recv(4096)
        if data:
            log("mysql", "client handshake %d bytes" % len(data), peer_ip(conn))
    except OSError:
        pass
    conn.close()


def postgres_srv():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, 5432))
    srv.listen(8)
    log("service", "postgres (fake) listening on :5432")
    while True:
        conn, _ = srv.accept()
        log("connection", "tcp/5432", peer_ip(conn))
        threading.Thread(target=postgres_handle, args=(conn,), daemon=True).start()


def postgres_handle(conn):
    try:
        data = conn.recv(4096)
        if data:
            log("postgres", "startup %d bytes" % len(data), peer_ip(conn))
    except OSError:
        pass
    conn.close()


if __name__ == "__main__":
    log("boot", "decoy %s starting" % FAKE_HOSTNAME)
    grep_services()
    while True:
        time.sleep(5)
"""


@dataclass
class DecoyStatus:
    """Runtime status of a deployed decoy."""

    spec: DecoySpec
    container_id: str
    status: str
    ip: str | None = None
    ports: dict[int, int] = field(default_factory=dict)


class HoneypotManager:
    """Creates and manages the decoy container fleet on Docker."""

    NETWORK_NAME = "backrooms-labyrinth"
    LABEL_PREFIX = "backrooms"

    def __init__(self, config: HoneypotConfig, logger: IdsLogger | None = None) -> None:
        self.config = config
        self.logger = logger or IdsLogger(config.ids)
        self._docker = None

    @property
    def docker(self) -> Any:
        if self._docker is None:
            try:
                import docker  # type: ignore[import-untyped]

                self._docker = docker.from_env()
            except Exception as exc:  # noqa: BLE001 - surface a friendly error
                raise DockerError(f"Docker unavailable: {exc}") from exc
        return self._docker

    def deploy(self) -> list[DecoyStatus]:
        """Build and start all configured decoys."""
        client = self.docker
        network = self._ensure_network(client)

        statuses: list[DecoyStatus] = []
        for spec in self.config.decoys:
            container_id = self._run_decoy(client, network, spec)
            container = client.containers.get(container_id)
            container.reload()
            ip = container.attrs.get("NetworkSettings", {}).get("Networks", {}).get(
                self.NETWORK_NAME, {}
            ).get("IPAddress")
            statuses.append(
                DecoyStatus(
                    spec=spec,
                    container_id=container_id,
                    status=container.status,
                    ip=ip,
                    ports=spec.ports,
                )
            )
        return statuses

    def _ensure_network(self, client: Any) -> Any:
        try:
            network = client.networks.get(self.NETWORK_NAME)
            return network
        except Exception:  # noqa: BLE001
            from ipaddress import ip_network

            net = ip_network(self.config.subnet, strict=False)
            return client.networks.create(
                name=self.NETWORK_NAME,
                driver="bridge",
                ipam=self._ipam(net.prefixlen, str(net.network_address)),
                labels={self.LABEL_PREFIX: "network"},
                check_duplicate=True,
            )

    @staticmethod
    def _ipam(prefixlen: int, subnet: str) -> dict[str, Any]:
        return {"driver": "default", "config": [{"subnet": f"{subnet}/{prefixlen}"}]}

    def _run_decoy(self, client: Any, network: Any, spec: DecoySpec) -> str:
        image = self._ensure_image(client)
        name = f"br-{spec.name}"
        env = {
            "BR_HOSTNAME": spec.hostname,
            "BR_SERVICES": ",".join(s.value for s in spec.services),
        }

        script_path = self._write_script(spec.name)
        volumes = {str(script_path): {"bind": "/decoy.py", "mode": "ro"}}
        container = client.containers.run(
            image,
            command=["python", "/decoy.py"],
            name=name,
            detach=True,
            environment=env,
            network=self.NETWORK_NAME,
            hostname=spec.hostname,
            labels={self.LABEL_PREFIX: "decoy", "br-name": spec.name},
            restart_policy={"Name": "always"},
            volumes=volumes,
            remove=False,
        )
        return str(container.id)

    def _ensure_image(self, client: Any) -> str:
        if self._has_local_image(client):
            return _BASE_IMAGE
        try:
            client.images.pull(_BASE_IMAGE)
            return _BASE_IMAGE
        except Exception as exc:  # noqa: BLE001
            raise DockerError(f"Could not pull image {_BASE_IMAGE}: {exc}") from exc

    @staticmethod
    def _has_local_image(client: Any) -> bool:
        try:
            client.images.get(_BASE_IMAGE)
        except Exception:  # noqa: BLE001 - image missing locally
            return False
        return True

    def _write_script(self, name: str) -> Path:
        script_path = Path(tempfile.gettempdir()) / f"backrooms-{name}-decoy.py"
        script_path.write_text(_DECOY_SCRIPT.lstrip("\n"), encoding="utf-8")
        return script_path

    def status(self) -> list[DecoyStatus]:
        """Return live status of all decoys managed by this instance."""
        client = self.docker
        statuses: list[DecoyStatus] = []
        containers = client.containers.list(
            all=True, filters={"label": f"{self.LABEL_PREFIX}=decoy"}
        )
        by_name = {c.labels.get("br-name"): c for c in containers}
        for spec in self.config.decoys:
            container = by_name.get(spec.name)
            if container is None:
                continue
            container.reload()
            ip = container.attrs.get("NetworkSettings", {}).get("Networks", {}).get(
                self.NETWORK_NAME, {}
            ).get("IPAddress")
            statuses.append(
                DecoyStatus(
                    spec=spec,
                    container_id=container.id,
                    status=container.status,
                    ip=ip,
                    ports=spec.ports,
                )
            )
        return statuses

    def logs(self, name: str, tail: int = 200) -> str:
        """Return recent container logs for a decoy by name."""
        client = self.docker
        try:
            container = client.containers.get(f"br-{name}")
        except Exception as exc:  # noqa: BLE001
            raise DockerError(f"No decoy named {name!r}") from exc
        raw = container.logs(tail=tail)
        if isinstance(raw, bytes):
            return raw.decode(errors="replace")
        return str(raw)

    def destroy(self) -> list[str]:
        """Stop and remove every decoy container and the labyrinth network."""
        client = self.docker
        removed: list[str] = []
        containers = client.containers.list(
            all=True, filters={"label": f"{self.LABEL_PREFIX}=decoy"}
        )
        for container in containers:
            name = container.name
            container.remove(force=True)
            removed.append(name)
        for network in client.networks.list(greedy=True, filters={"label": f"{self.LABEL_PREFIX}=network"}):
            network.remove()
        return removed

    def record(self, decoy: str, kind: str, detail: str = "", source: str | None = None) -> int:
        """Record an IDS event (used when services are containerized)."""
        alert = classify_command(detail)
        self.logger.log(decoy, alert or kind, detail=detail, source_ip=source)
        return 0
