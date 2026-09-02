"""Backrooms custom exceptions."""


class BackroomsError(Exception):
    """Base exception for all Backrooms errors."""


class ConfigurationError(BackroomsError):
    """Raised when configuration is invalid."""


class NetworkError(BackroomsError):
    """Raised for network-related failures."""


class ScanError(NetworkError):
    """Raised when a scan operation fails."""


class HostUnreachableError(NetworkError):
    """Raised when a target host cannot be reached."""


class PrivilegeError(BackroomsError):
    """Raised when elevated privileges are required but missing."""


class HoneypotError(BackroomsError):
    """Raised for honeypot lifecycle failures."""


class DockerError(HoneypotError):
    """Raised when Docker operations fail."""


class NotRootError(PrivilegeError):
    """Raised when running as root is required (e.g. raw sockets)."""


class WirelessError(NetworkError):
    """Raised for wireless interface / scanning failures."""
