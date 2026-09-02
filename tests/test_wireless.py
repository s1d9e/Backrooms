"""Tests for the wireless module (pure logic only)."""

from backrooms.modules.wireless.core import AccessPoint, ScanResult, _iw_block, _mac


def test_mac_from_tuple() -> None:
    assert _mac((0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03)) == "aa:bb:cc:01:02:03"


def test_mac_from_string_passthrough() -> None:
    assert _mac("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"


def test_mac_empty() -> None:
    assert _mac(None) == ""


def test_ap_label_hidden() -> None:
    ap = AccessPoint(bssid="00:11:22:33:44:55", ssid="")
    assert "hidden" in ap.label


def test_access_point_field_defaults() -> None:
    ap = AccessPoint(bssid="00:11:22:33:44:55", ssid="BackroomsNet")
    assert ap.channel == 0
    assert ap.privacy is False
    assert ap.encryption == "OPEN"


def test_scan_result_total() -> None:
    result = ScanResult(
        interface="wlan0",
        access_points=[AccessPoint(bssid="a", ssid="s")],
    )
    assert result.total == 1


def test_iw_block_extracts_interface() -> None:
    sample = (
        "phy#0\n"
        "\tInterface wlan0\n"
        "\t\ttype monitor\n"
        "phy#1\n"
        "\tInterface wlan1\n"
        "\t\ttype managed\n"
    )
    block = _iw_block(sample, "wlan0")
    assert block is not None
    assert "type monitor" in block
    assert "wlan1" not in block


def test_iw_block_missing_returns_none() -> None:
    sample = "\tInterface wlan0\n"
    assert _iw_block(sample, "doesnotexist") is None
