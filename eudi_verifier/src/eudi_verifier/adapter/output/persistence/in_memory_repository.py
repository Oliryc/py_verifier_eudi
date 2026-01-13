"""In-memory implementation of PresentationRepository"""

import asyncio
from typing import Dict

from returns.result import Failure, Result, Success

from eudi_verifier.domain import (
    Clock,
    Presentation,
    PresentationRequested,
    PresentationRequestObjectRetrieved,
    RequestId,
    TransactionId,
    get_request_id,
    get_transaction_id,
    is_expired,
)
from eudi_verifier.port.output import PresentationNotFound, PresentationRepository


class InMemoryPresentationRepository(PresentationRepository):
    """
    In-memory implementation of PresentationRepository.

    Uses Python dictionaries to store presentations. Provides two indexes:
    - By transaction_id: For verifier-side lookups
    - By request_id: For wallet-side lookups (state parameter)

    Thread-safe for async operations using asyncio.Lock.
    """

    def __init__(self, clock: Clock):
        """
        Initialize repository with empty storage.

        Args:
            clock: Clock for checking expiration
        """
        self.clock = clock
        self._by_transaction_id: Dict[str, Presentation] = {}
        self._by_request_id: Dict[str, Presentation] = {}
        self._lock = asyncio.Lock()

    async def save(self, presentation: Presentation) -> Result[None, Exception]:
        """
        Save or update a presentation.

        Maintains dual indexes by transaction_id and request_id.

        Args:
            presentation: Presentation to save

        Returns:
            Success(None) or Failure(exception)
        """
        try:
            async with self._lock:
                transaction_id = get_transaction_id(presentation)
                request_id = get_request_id(presentation)

                self._by_transaction_id[transaction_id.value] = presentation
                self._by_request_id[request_id.value] = presentation

            return Success(None)
        except Exception as e:
            return Failure(e)

    async def get_by_transaction_id(
        self, transaction_id: TransactionId
    ) -> Result[Presentation, PresentationNotFound]:
        """
        Retrieve presentation by transaction ID.

        Args:
            transaction_id: Transaction identifier

        Returns:
            Success(Presentation) or Failure(PresentationNotFound)
        """
        try:
            async with self._lock:
                presentation = self._by_transaction_id.get(transaction_id.value)

            if presentation is None:
                return Failure(PresentationNotFound(identifier=transaction_id.value))

            return Success(presentation)
        except Exception as e:
            return Failure(PresentationNotFound(identifier=transaction_id.value))

    async def get_by_request_id(self, request_id: RequestId) -> Result[Presentation, PresentationNotFound]:
        """
        Retrieve presentation by request ID (state parameter).

        Args:
            request_id: Request identifier

        Returns:
            Success(Presentation) or Failure(PresentationNotFound)
        """
        try:
            async with self._lock:
                presentation = self._by_request_id.get(request_id.value)

            if presentation is None:
                return Failure(PresentationNotFound(identifier=request_id.value))

            return Success(presentation)
        except Exception as e:
            return Failure(PresentationNotFound(identifier=request_id.value))

    async def delete(self, transaction_id: TransactionId) -> Result[None, Exception]:
        """
        Delete a presentation.

        Removes from both indexes.

        Args:
            transaction_id: Transaction identifier

        Returns:
            Success(None) or Failure(exception)
        """
        try:
            async with self._lock:
                presentation = self._by_transaction_id.get(transaction_id.value)
                if presentation is None:
                    return Failure(PresentationNotFound(identifier=transaction_id.value))

                request_id = get_request_id(presentation)

                del self._by_transaction_id[transaction_id.value]
                del self._by_request_id[request_id.value]

            return Success(None)
        except Exception as e:
            return Failure(e)

    async def get_all_expired(self) -> Result[list[Presentation], Exception]:
        """
        Get all expired presentations (for cleanup).

        Checks expiration using the clock provided at construction.

        Returns:
            Success(list of expired presentations) or Failure(exception)
        """
        try:
            async with self._lock:
                all_presentations = list(self._by_transaction_id.values())

            expired = [p for p in all_presentations if is_expired(p, self.clock)]

            return Success(expired)
        except Exception as e:
            return Failure(e)

    async def count(self) -> Result[int, Exception]:
        """
        Get total number of presentations in storage.

        Returns:
            Success(count) or Failure(exception)
        """
        try:
            async with self._lock:
                count = len(self._by_transaction_id)

            return Success(count)
        except Exception as e:
            return Failure(e)

    async def clear(self) -> Result[None, Exception]:
        """
        Clear all presentations (useful for testing).

        Returns:
            Success(None) or Failure(exception)
        """
        try:
            async with self._lock:
                self._by_transaction_id.clear()
                self._by_request_id.clear()

            return Success(None)
        except Exception as e:
            return Failure(e)
