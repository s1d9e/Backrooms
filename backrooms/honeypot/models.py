"""Honeypot data models."""

from enum import StrEnum

from pydantic import BaseModel, Field, model_validator


class ServiceType(StrEnum):
    """Fake services a decoy can expose."""

    SSH = "ssh"
    HTTP = "http"
    SMB = "smb"
    RDP = "rdp"
    FTP = "ftp"
    MYSQL = "mysql"
    POSTGRES = "postgres"
    TELNET = "telnet"


class FakeUser(BaseModel):
    """A fake (attractant) user account on a decoy."""

    username: str
    password: str


class DecoySpec(BaseModel):
    """What a single decoy container should look like."""

    name: str
    kind: str = Field(default="linux")
    hostname: str
    services: list[ServiceType] = Field(default_factory=lambda: [ServiceType.HTTP])
    ssh_port: int = Field(default=2222, ge=1, le=65535)
    fake_users: list[FakeUser] = Field(default_factory=list)
    ports: dict[int, int] = Field(
        default_factory=dict, description="Host port -> container port mapping"
    )


class LabyrinthSettings(BaseModel):
    """Behaviour of the honeypot maze."""

    max_hops: int = Field(default=5, ge=1, le=25)
    redirect_delay: float = Field(default=2.0, ge=0)
    session_timeout: float = Field(default=900.0, ge=10)

    @model_validator(mode="after")
    def _valid_hops(self) -> "LabyrinthSettings":
        if self.max_hops < 1:
            raise ValueError("max_hops must be at least 1")
        return self


class IdsSettings(BaseModel):
    """Intrusion detection settings."""

    enabled: bool = True
    alert_on: list[str] = Field(
        default_factory=lambda: ["privilege_escalation", "lateral_movement", "credential_dumping"]
    )


class HoneypotConfig(BaseModel):
    """Top-level honeypot deployment configuration."""

    network: str = Field(default="172.28.0.0/16")
    subnet: str = Field(default="172.28.0.0/24")
    gateway: str = Field(default="172.28.0.1")
    host_ip: str = Field(default="0.0.0.0")  # noqa: S104 - bind default for decoys
    decoys: list[DecoySpec] = Field(default_factory=list)
    labyrinth: LabyrinthSettings = Field(default_factory=LabyrinthSettings)
    ids: IdsSettings = Field(default_factory=IdsSettings)

    @model_validator(mode="after")
    def _require_decoys(self) -> "HoneypotConfig":
        if not self.decoys:
            raise ValueError("At least one decoy must be defined")
        return self
