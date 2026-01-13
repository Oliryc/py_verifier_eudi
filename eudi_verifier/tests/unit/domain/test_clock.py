"""Tests for Clock abstraction"""

from datetime import datetime, timedelta, timezone

import pytest

from eudi_verifier.domain import SystemClock, FixedClock


class TestSystemClock:
    """Tests for SystemClock"""

    def test_now_returns_utc_datetime(self):
        """SystemClock.now() returns timezone-aware UTC datetime"""
        clock = SystemClock()
        now = clock.now()

        assert now.tzinfo == timezone.utc
        assert isinstance(now, datetime)

    def test_now_returns_current_time(self):
        """SystemClock.now() returns time close to actual current time"""
        clock = SystemClock()
        before = datetime.now(timezone.utc)
        now = clock.now()
        after = datetime.now(timezone.utc)

        # Should be within 1 second
        assert before <= now <= after
        assert (after - before).total_seconds() < 1.0


class TestFixedClock:
    """Tests for FixedClock"""

    def test_now_returns_fixed_time(self, fixed_clock: FixedClock):
        """FixedClock.now() returns the fixed time"""
        expected = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        assert fixed_clock.now() == expected

    def test_now_returns_same_time_on_multiple_calls(self, fixed_clock: FixedClock):
        """Multiple calls to now() return same time"""
        time1 = fixed_clock.now()
        time2 = fixed_clock.now()
        time3 = fixed_clock.now()

        assert time1 == time2 == time3

    def test_advance_moves_time_forward(self, fixed_clock: FixedClock):
        """advance() moves clock forward by specified delta"""
        initial = fixed_clock.now()
        fixed_clock.advance(timedelta(hours=2, minutes=30))
        after = fixed_clock.now()

        assert after == initial + timedelta(hours=2, minutes=30)
        assert after > initial

    def test_advance_can_be_called_multiple_times(self, fixed_clock: FixedClock):
        """Multiple advance() calls accumulate"""
        initial = fixed_clock.now()
        fixed_clock.advance(timedelta(hours=1))
        fixed_clock.advance(timedelta(minutes=30))
        fixed_clock.advance(timedelta(seconds=45))
        final = fixed_clock.now()

        expected = initial + timedelta(hours=1, minutes=30, seconds=45)
        assert final == expected

    def test_set_changes_time_to_specific_value(self, fixed_clock: FixedClock):
        """set() changes clock to specific time"""
        new_time = datetime(2025, 6, 30, 18, 45, 0, tzinfo=timezone.utc)
        fixed_clock.set(new_time)

        assert fixed_clock.now() == new_time

    def test_init_with_naive_datetime_converts_to_utc(self):
        """FixedClock converts naive datetime to UTC"""
        naive = datetime(2024, 1, 1, 12, 0, 0)
        clock = FixedClock(naive)
        result = clock.now()

        assert result.tzinfo == timezone.utc
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 1

    def test_init_with_aware_datetime_converts_to_utc(self):
        """FixedClock converts aware datetime to UTC"""
        # Create time in different timezone (EST = UTC-5)
        import datetime as dt

        est = dt.timezone(timedelta(hours=-5))
        aware = datetime(2024, 1, 1, 12, 0, 0, tzinfo=est)
        clock = FixedClock(aware)
        result = clock.now()

        assert result.tzinfo == timezone.utc
        # 12:00 EST = 17:00 UTC
        assert result.hour == 17

    def test_set_with_naive_datetime_converts_to_utc(self, fixed_clock: FixedClock):
        """set() with naive datetime converts to UTC"""
        naive = datetime(2025, 12, 25, 9, 0, 0)
        fixed_clock.set(naive)
        result = fixed_clock.now()

        assert result.tzinfo == timezone.utc
        assert result.year == 2025
        assert result.month == 12
        assert result.day == 25
