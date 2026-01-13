"""Presentation repository port - Interface for presentation persistence"""

from abc import ABC, abstractmethod
from typing import Optional

from returns.result import Result

from eudi_verifier.domain import (
    Presentation,
    RequestId,
    TransactionId,
)


class PresentationNotFound(Exception):
    """Raised when presentation is not found"""

    def __init__(self, identifier: str):
        self.identifier = identifier
        super().__init__(f"Presentation not found: {identifier}")


class PresentationRepository(ABC):
    """
    Repository for storing and retrieving presentation transactions.

    This port defines the interface for persistence operations. Implementations
    can use in-memory storage, Redis, databases, etc.
    """

    @abstractmethod
    async def save(self, presentation: Presentation) -> Result[None, Exception]:
        """
        Save or update a presentation.

        Args:
            presentation: Presentation to save

        Returns:
            Success(None) or Failure(exception)
        """
        pass

    @abstractmethod
    async def get_by_transaction_id(self, transaction_id: TransactionId) -> Result[Presentation, PresentationNotFound]:
        """
        Retrieve presentation by transaction ID.

        Args:
            transaction_id: Transaction identifier

        Returns:
            Success(Presentation) or Failure(PresentationNotFound)
        """
        pass

    @abstractmethod
    async def get_by_request_id(self, request_id: RequestId) -> Result[Presentation, PresentationNotFound]:
        """
        Retrieve presentation by request ID (state parameter).

        Args:
            request_id: Request identifier

        Returns:
            Success(Presentation) or Failure(PresentationNotFound)
        """
        pass

    @abstractmethod
    async def delete(self, transaction_id: TransactionId) -> Result[None, Exception]:
        """
        Delete a presentation.

        Args:
            transaction_id: Transaction identifier

        Returns:
            Success(None) or Failure(exception)
        """
        pass

    @abstractmethod
    async def get_all_expired(self) -> Result[list[Presentation], Exception]:
        """
        Get all expired presentations (for cleanup).

        Returns:
            Success(list of expired presentations) or Failure(exception)
        """
        pass

    @abstractmethod
    async def count(self) -> Result[int, Exception]:
        """
        Get total number of presentations in storage.

        Returns:
            Success(count) or Failure(exception)
        """
        pass
