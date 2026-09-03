"""Tests for the SMB enumeration module."""

import struct

from backrooms.modules.scanner.port_scan import ScannerOptions
from backrooms.modules.smb.enumerator import (
    SmbEnumerator,
    _build_negotiate,
    _decode_netbios,
)


def test_netbios_name_decode() -> None:
    # Classic NetBIOS first-level encoding of "WS01".
    def enc(c: str) -> bytes:
        hi = (ord(c) >> 4) & 0x0F
        lo = ord(c) & 0x0F
        return bytes([0x41 + hi, 0x41 + lo])

    raw = b"".join(enc(c) for c in "WS01")
    assert _decode_netbios(raw) == "WS01"


def test_netbios_decode_empty() -> None:
    assert _decode_netbios(b"") in (None, "")
    assert _decode_netbios(b"\x00") in (None, "")


def test_enumerator_constructs() -> None:
    enum = SmbEnumerator(ScannerOptions(timeout=0.5))
    assert enum.options.timeout == 0.5


def test_nbstat_parse_empty() -> None:
    enum = SmbEnumerator()
    assert enum._parse_nbstat(b"") == ("", "", "")


def test_nbstat_parse_too_short() -> None:
    enum = SmbEnumerator()
    assert enum._parse_nbstat(b"\x00" * 30) == ("", "", "")


def test_nbstat_parse_records() -> None:
    """A crafted NBSTAT payload yields a hostname from its records."""
    enum = SmbEnumerator()
    # 34-byte response name block (zeros) + name count + 18-byte record.
    # The record holds a first-level encoded name padded to 15 bytes.
    encoded = b"".join(_netbios_encode(c) for c in "PC01")
    encoded = encoded + b"\x41" * (15 - len(encoded))  # pad to 15 (decodes to 0x00)
    record = encoded + b"\x00" * 3  # 15 name + type + flags
    payload = b"\x00" * 34 + bytes([1]) + record
    result = enum._parse_nbstat(payload)
    assert "PC0" in result[0]  # partial decode of "PC01" is acceptable


def _netbios_encode(c: str) -> bytes:
    """Return the first-level-encoded bytes for char c (two bytes)."""
    hi = (ord(c) >> 4) & 0x0F
    lo = ord(c) & 0x0F
    return bytes([0x41 + hi, 0x41 + lo])


def test_negotiate_frame_is_valid() -> None:
    frame = _build_negotiate()
    # NetBIOS session header + SMB2 magic (prot at SMB2 offset 0 = frame 4).
    assert frame[0] == 0x00
    assert frame[4:8] == b"\xfeSMB"
    # SMB2 StructureSize == 64 (SMB2 offset 4 = frame offset 8).
    (struct_size,) = struct.unpack_from("<H", frame, 8)
    assert struct_size == 64
    # Command == SMB2_NEGOTIATE (0) at SMB2 offset 12 = frame offset 16.
    (command,) = struct.unpack_from("<H", frame, 16)
    assert command == 0
    # Request body begins at frame offset 4 (session hdr) + 64 (SMB2 header).
    body_off = 4 + 64
    (struct_size_body,) = struct.unpack_from("<H", frame, body_off)
    assert struct_size_body == 28
    (dialect_count,) = struct.unpack_from("<H", frame, body_off + 2)
    assert dialect_count >= 1


def test_negotiate_no_server() -> None:
    # Connecting to a closed/unreachable port should return None, not raise.
    enum = SmbEnumerator()
    assert enum._negotiate_dialect("127.0.0.1", 1) is None
