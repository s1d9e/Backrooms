"""Tests for the SMB enumeration module."""


from backrooms.modules.scanner.port_scan import ScannerOptions
from backrooms.modules.smb.enumerator import SmbEnumerator, _decode_netbios


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


def test_nbstat_parse_unknown() -> None:
    enum = SmbEnumerator()
    result = enum._parse_nbstat(b"\x00" * 40)
    assert result[0] == ""


def test_negotiate_no_server() -> None:
    # Connecting to a closed/unreachable port should return None, not raise.
    enum = SmbEnumerator()
    assert enum._negotiate_dialect("127.0.0.1", 1) is None
