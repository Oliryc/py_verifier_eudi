"""Get request object use case - Retrieve JAR for wallet"""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from returns.result import Result

from eudi_verifier.domain import (
    RequestId,
)


@dataclass(frozen=True)
class GetRequestObjectRequest:
    """
    Request to retrieve request object (JAR).

    Attributes:
        request_id: Request identifier (state parameter)
    """

    request_id: RequestId


@dataclass(frozen=True)
class GetRequestObjectResponse:
    """
    Response from get request object use case.

    Attributes:
        request_id: Request identifier
        jar: JWT-Secured Authorization Request
        content_type: MIME type (application/oauth-authz-req+jwt)
    """

    request_id: RequestId
    jar: str
    content_type: str = "application/oauth-authz-req+jwt"


class GetRequestObjectError(Exception):
    """Error during request object retrieval"""

    pass


class RequestObjectExpired(GetRequestObjectError):
    """Request object has expired"""

    def __init__(self, request_id: RequestId):
        self.request_id = request_id
        super().__init__(f"Request object expired: {request_id}")


class GetRequestObject(ABC):
    """
    Use case: Retrieve request object (JAR) for wallet.

    Wallets use this endpoint to fetch the JWT-Secured Authorization Request
    when using request_uri (by reference) instead of request (by value).

    Flow:
    1. Retrieve presentation by request_id
    2. Check presentation is not expired
    3. Transition to RequestObjectRetrieved state
    4. Return JAR
    """

    @abstractmethod
    async def execute(self, request: GetRequestObjectRequest) -> Result[GetRequestObjectResponse, GetRequestObjectError]:
        """
        Execute the get request object use case.

        Args:
            request: Get request object request

        Returns:
            Success(GetRequestObjectResponse) with JAR or
            Failure(GetRequestObjectError)
        """
        pass
