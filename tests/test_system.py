from unittest.mock import MagicMock, patch

import pytest

from src.oslayer.system import (
    available_memory_info,
    memory_pressure_hint,
    uptime_seconds,
)


def _make_svmem(total, available):
    return MagicMock(total=total, available=available)


@patch("src.oslayer.system.psutil.virtual_memory")
def test_available_memory_info_returns_expected_fields(mock_vm):
    mock_vm.return_value = _make_svmem(total=8 * 1024**3, available=2 * 1024**3)
    result = available_memory_info()
    assert result is not None
    assert result["total_gb"] == 8.0
    assert result["free_gb"] == 2.0
    assert result["free_pct"] == 25.0


@patch("src.oslayer.system.psutil.virtual_memory")
def test_available_memory_info_returns_none_on_error(mock_vm):
    mock_vm.side_effect = Exception("psutil failed")
    assert available_memory_info() is None


@patch("src.oslayer.system.psutil.virtual_memory")
def test_available_memory_info_zero_total(mock_vm):
    mock_vm.return_value = _make_svmem(total=0, available=0)
    result = available_memory_info()
    assert result is not None
    assert result["free_pct"] == 0.0


@patch("src.oslayer.system.time.time", return_value=1000000.0)
@patch("src.oslayer.system.psutil.boot_time", return_value=999000.0)
def test_uptime_seconds_returns_positive_value(mock_boot, mock_time):
    result = uptime_seconds()
    assert result == pytest.approx(1000.0)


@patch("src.oslayer.system.psutil.boot_time")
def test_uptime_seconds_returns_none_on_error(mock_boot):
    mock_boot.side_effect = Exception("psutil failed")
    assert uptime_seconds() is None


@patch("src.oslayer.system.psutil.virtual_memory")
def test_memory_pressure_hint_empty_when_ok(mock_vm):
    mock_vm.return_value = _make_svmem(total=8 * 1024**3, available=4 * 1024**3)
    assert memory_pressure_hint() == ""


@patch("src.oslayer.system.psutil.virtual_memory")
def test_memory_pressure_hint_triggers_when_low(mock_vm):
    mock_vm.return_value = _make_svmem(total=8 * 1024**3, available=1 * 1024**3)
    hint = memory_pressure_hint()
    assert "system memory is low" in hint
    assert "12%" in hint


def test_smoke_real_psutil_returns_reasonable_values():
    """Integration smoke test: calls real psutil (no mock) and validates
    the returned values are sane. Catches field-name mismatches (e.g. if
    psutil changed .available to .free) that mocked tests can't detect.
    """
    info = available_memory_info()
    assert info is not None
    assert info["total_gb"] > 0
    assert info["free_gb"] > 0
    assert info["free_gb"] <= info["total_gb"]
    assert 0 <= info["free_pct"] <= 100

    uptime = uptime_seconds()
    assert uptime is not None
    assert uptime > 0
