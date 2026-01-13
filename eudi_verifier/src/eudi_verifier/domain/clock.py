"""Clock abstraction for testable time operations"""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Final


class Clock(ABC):
    """Abstract clock for time operations"""

    @abstractmethod
    def now(self) -> datetime:
        """Get current time as timezone-aware UTC datetime"""
        pass


class SystemClock(Clock):
    """Production clock using system time"""

    def now(self) -> datetime:
        """Get current system time in UTC"""
        return datetime.now(timezone.utc)


class FixedClock(Clock):
    """Test clock with fixed or controllable time"""

    def __init__(self, fixed_time: datetime):
        """
        Initialize with fixed time

        Args:
            fixed_time: The fixed datetime to return. Will be converted to UTC if naive.
        """
        # Ensure time is timezone-aware UTC
        if fixed_time.tzinfo is None:
            self._current_time = fixed_time.replace(tzinfo=timezone.utc)
        else:
            self._current_time = fixed_time.astimezone(timezone.utc)

    def now(self) -> datetime:
        """Get the fixed time"""
        return self._current_time

    def advance(self, delta: timedelta) -> None:
        """
        Advance the clock by given timedelta

        Args:
            delta: Amount of time to advance
        """
        self._current_time += delta

    def set(self, new_time: datetime) -> None:
        """
        Set clock to specific time

        Args:
            new_time: New datetime to set. Will be converted to UTC if naive.
        """
        if new_time.tzinfo is None:
            self._current_time = new_time.replace(tzinfo=timezone.utc)
        else:
            self._current_time = new_time.astimezone(timezone.utc)
