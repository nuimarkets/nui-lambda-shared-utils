"""
Tests for timezone module.
"""

import pytest
from datetime import datetime, timezone
import pytz
from unittest.mock import patch
from nui_lambda_shared_utils.timezone import nz_time, format_nz_time, NZ_TZ


class TestNzTime:
    """Tests for nz_time function."""

    def test_nz_time_with_utc_datetime(self):
        """Test converting UTC datetime to NZ time."""
        # Create a UTC datetime (2024-01-30 10:00:00 UTC)
        utc_dt = datetime(2024, 1, 30, 10, 0, 0, tzinfo=timezone.utc)

        result = nz_time(utc_dt)

        # In January, NZ is UTC+13 (NZDT)
        # So 10:00 UTC should be 23:00 NZDT
        assert result.hour == 23
        assert result.day == 30
        assert result.tzinfo.zone == "Pacific/Auckland"

    def test_nz_time_with_naive_datetime(self):
        """Test converting naive datetime to NZ time (assumes UTC)."""
        # Create a naive datetime
        naive_dt = datetime(2024, 1, 30, 10, 0, 0)

        result = nz_time(naive_dt)

        # Should treat as UTC and convert to NZ
        assert result.hour == 23
        assert result.day == 30
        assert result.tzinfo.zone == "Pacific/Auckland"

    def test_nz_time_no_argument(self):
        """Test getting current NZ time."""
        # Mock current UTC time
        mock_now = datetime(2024, 1, 30, 10, 0, 0, tzinfo=timezone.utc)

        with patch("nui_lambda_shared_utils.timezone.datetime") as mock_dt:
            mock_dt.now.return_value = mock_now
            result = nz_time()

        assert result.hour == 23
        assert result.day == 30
        assert result.tzinfo.zone == "Pacific/Auckland"

    def test_nz_time_winter_time(self):
        """Test NZ time during winter (NZST - UTC+12)."""
        # July is winter in NZ (UTC+12)
        utc_dt = datetime(2024, 7, 15, 10, 0, 0, tzinfo=timezone.utc)

        result = nz_time(utc_dt)

        # 10:00 UTC should be 22:00 NZST
        assert result.hour == 22
        assert result.day == 15
        assert result.tzinfo.zone == "Pacific/Auckland"

    def test_nz_time_with_already_nz_datetime(self):
        """Test passing datetime already in NZ timezone."""
        nz_dt = NZ_TZ.localize(datetime(2024, 1, 30, 15, 0, 0))

        result = nz_time(nz_dt)

        # Should preserve the time
        assert result.hour == 15
        assert result.day == 30
        assert result.tzinfo.zone == "Pacific/Auckland"


class TestFormatNzTime:
    """Tests for format_nz_time function."""

    def test_format_nz_time_with_datetime(self):
        """Test formatting specific datetime."""
        utc_dt = datetime(2024, 1, 30, 10, 30, 45, tzinfo=timezone.utc)

        result = format_nz_time(utc_dt)

        # Default format includes timezone
        assert result == "2024-01-30 23:30:45 NZDT"

    def test_format_nz_time_custom_format(self):
        """Test custom format string."""
        utc_dt = datetime(2024, 1, 30, 10, 30, 45, tzinfo=timezone.utc)

        result = format_nz_time(utc_dt, fmt="%Y-%m-%d %H:%M")

        assert result == "2024-01-30 23:30"

    def test_format_nz_time_no_argument(self):
        """Test formatting current time."""
        mock_now = datetime(2024, 1, 30, 10, 30, 45, tzinfo=timezone.utc)

        with patch("nui_lambda_shared_utils.timezone.datetime") as mock_dt:
            mock_dt.now.return_value = mock_now
            result = format_nz_time()

        assert result == "2024-01-30 23:30:45 NZDT"

    def test_format_nz_time_date_only(self):
        """Test formatting date only."""
        utc_dt = datetime(2024, 1, 30, 10, 0, 0, tzinfo=timezone.utc)

        result = format_nz_time(utc_dt, fmt="%Y-%m-%d")

        assert result == "2024-01-30"

    def test_format_nz_time_12_hour(self):
        """Test 12-hour format."""
        utc_dt = datetime(2024, 1, 30, 10, 0, 0, tzinfo=timezone.utc)

        result = format_nz_time(utc_dt, fmt="%I:%M %p")

        assert result == "11:00 PM"

    def test_format_nz_time_winter(self):
        """Test formatting during winter (NZST)."""
        utc_dt = datetime(2024, 7, 15, 10, 0, 0, tzinfo=timezone.utc)

        result = format_nz_time(utc_dt)

        assert result == "2024-07-15 22:00:00 NZST"


class TestTimezoneConstants:
    """Tests for timezone constants."""

    def test_nz_tz_constant(self):
        """Test that NZ_TZ is properly configured."""
        assert NZ_TZ.zone == "Pacific/Auckland"

        # Test DST transitions
        # Summer time (NZDT - UTC+13)
        summer = datetime(2024, 1, 15, 12, 0, 0)
        summer_nz = NZ_TZ.localize(summer)
        assert summer_nz.strftime("%Z") == "NZDT"
        assert summer_nz.utcoffset().total_seconds() == 13 * 3600

        # Winter time (NZST - UTC+12)
        winter = datetime(2024, 7, 15, 12, 0, 0)
        winter_nz = NZ_TZ.localize(winter)
        assert winter_nz.strftime("%Z") == "NZST"
        assert winter_nz.utcoffset().total_seconds() == 12 * 3600
