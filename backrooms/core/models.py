"""Pydantic data models for Backrooms."""

from enum import StrEnum

from pydantic import BaseModel, Field


class ServiceProtocol(StrEnum):
    """Network protocol for a scanned service."""

    TCP = "tcp"
    UDP = "udp"


class PortState(StrEnum):
    """State of a discovered port."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class ScanType(StrEnum):
    """Supported port scan techniques."""

    SYN = "syn"
    CONNECT = "connect"
    ACK = "ack"
    UDP = "udp"


class Host(BaseModel):
    """A discovered network host."""

    ip: str
    mac: str | None = None
    hostname: str | None = None
    os: str | None = None
    ports: list["Port"] = Field(default_factory=list)

    @property
    def open_ports(self) -> list["Port"]:
        return [p for p in self.ports if p.state == PortState.OPEN]


class Port(BaseModel):
    """A single scanned port with service info."""

    port: int
    protocol: ServiceProtocol = ServiceProtocol.TCP
    state: PortState = PortState.CLOSED
    service: str | None = None
    version: str | None = None
    banner: str | None = None


class ScanTarget(BaseModel):
    """A resolved scan target (host or CIDR)."""

    hosts: list[str]


class ServiceBanner(BaseModel):
    """Banner grabbed from a service."""

    port: int
    protocol: ServiceProtocol
    banner: str | None = None
