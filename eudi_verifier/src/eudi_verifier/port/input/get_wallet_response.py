"""Get wallet response use case - Retrieve wallet response for a transaction"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional

from returns.result import Result

from eudi_verifier.domain import (
    Presentation,
    ResponseCode,
    TransactionId,
)


@dataclass(frozen=True)
class GetWalletResponseRequest:
    """
    Request to retrieve wallet response.

    Attributes:
        transaction_id: Transaction identifier
        response_code: Optional response code for polling-based retrieval
    """

    transaction_id: TransactionId
    response_code: Optional[ResponseCode] = None


@dataclass(frozen=True)
class GetWalletResponseResponse:
    """
    Response from get wallet response use case.

    Attributes:
        transaction_id: Transaction identifier
        presentation: Current presentation state
        wallet_response: Wallet response data (if submitted)
        is_completed: Whether presentation is in terminal state
        is_successful: Whether credentials were successfully submitted
    """

    transaction_id: TransactionId
    presentation: Presentation
    wallet_response: Optional[Dict[str, Any]] = None
    is_completed: bool = False
    is_successful: bool = False


class GetWalletResponseError(Exception):
    """Error during wallet response retrieval"""

    pass


class PresentationNotReady(GetWalletResponseError):
    """Presentation is not yet completed"""

    def __init__(self, transaction_id: TransactionId, current_state: str):
        self.transaction_id = transaction_id
        self.current_state = current_state
        super().__init__(f"Presentation {transaction_id} not ready, current state: {current_state}")


class InvalidResponseCode(GetWalletResponseError):
    """Response code is invalid"""

    def __init__(self, response_code: ResponseCode):
        self.response_code = response_code
        super().__init__(f"Invalid response code: {response_code}")


class GetWalletResponse(ABC):
    """
    Use case: Retrieve wallet response for a transaction.

    This allows verifiers to check the status and retrieve validated credentials.

    Flow:
    1. Retrieve presentation by transaction_id
    2. Verify response_code if provided (for polling)
    3. Check presentation state
    4. Return presentation and wallet response if available
    """

    @abstractmethod
    async def execute(
        self, request: GetWalletResponseRequest
    ) -> Result[GetWalletResponseResponse, GetWalletResponseError]:
        """
        Execute the get wallet response use case.

        Args:
            request: Get wallet response request

        Returns:
            Success(GetWalletResponseResponse) with presentation state or
            Failure(GetWalletResponseError)
        """
        pass
