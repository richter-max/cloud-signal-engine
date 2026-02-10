"""Detection rule interface."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy.orm import Session


class DetectionRule(ABC):
    """Base class for all detection rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable rule name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Rule description."""
        pass

    @property
    @abstractmethod
    def severity(self) -> str:
        """Default severity: low, medium, high, critical."""
        pass

    @property
    @abstractmethod
    def window_minutes(self) -> int:
        """Time window to analyze (in minutes)."""
        pass

    @abstractmethod
    def detect(
        self, db: Session, window_start: datetime, window_end: datetime
    ) -> List[Dict[str, Any]]:
        """
        Execute detection logic.

        Args:
            db: Database session
            window_start: Start of time window to analyze
            window_end: End of time window to analyze

        Returns:
            List of alert dictionaries with evidence
        """
        pass
