"""Init transaction use case - Initialize a new presentation transaction"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional

from returns.result import Result

from eudi_verifier.domain import (
    DCQL,
    Nonce,
    RequestId,
    ResponseModeOption,
    TransactionData,
    TransactionId,
)


@dataclass(frozen=True)
class InitTransactionRequest:
    """
    Request to initialize a new presentation transaction.

    Attributes:
        dcql_query: DCQL query specifying required credentials
        nonce: Cryptographic nonce for replay protection
        response_mode: How wallet should respond (direct_post or direct_post.jwt)
        transaction_data: Optional transaction data for RQES flows
        presentation_definition: Optional DIF Presentation Exchange definition
    """

    dcql_query: DCQL
    nonce: Nonce
    response_mode: Optional[ResponseModeOption] = None
    transaction_data: Optional[TransactionData] = None
    presentation_definition: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class InitTransactionResponse:
    """
    Response from init transaction use case.

    Attributes:
        transaction_id: Unique transaction identifier
        request_id: State parameter for wallet
        client_id: Verifier client identifier
        request_uri: URI where wallet can retrieve JAR (by reference)
        request: Optional JAR content (by value)
        authorization_request: Complete authorization request URI (eudi-openid4vp://...)
    """

    transaction_id: TransactionId
    request_id: RequestId
    client_id: str
    request_uri: Optional[str] = None
    request: Optional[str] = None
    authorization_request: Optional[str] = None


class InitTransactionError(Exception):
    """Error during transaction initialization"""

    pass


class InitTransaction(ABC):
    """
    Use case: Initialize a new presentation transaction.

    This is the primary entry point for verifiers to request credentials from wallets.

    Flow:
    1. Validate input (DCQL, nonce, etc.)
    2. Generate transaction and request IDs
    3. Create JWT-Secured Authorization Request (JAR)
    4. Store presentation in repository
    5. Return authorization request details
    """

    @abstractmethod
    async def execute(self, request: InitTransactionRequest) -> Result[InitTransactionResponse, InitTransactionError]:
        """
        Execute the init transaction use case.

        Args:
            request: Init transaction request

        Returns:
            Success(InitTransactionResponse) with authorization details or
            Failure(InitTransactionError)
        """
        pass
