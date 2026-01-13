"""Post wallet response use case - Handle wallet's credential submission"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from returns.result import Result

from eudi_verifier.domain import (
    RequestId,
    WalletResponse,
)


@dataclass(frozen=True)
class PostWalletResponseRequest:
    """
    Request to submit wallet response.

    Attributes:
        request_id: State parameter from authorization request
        vp_token: VP token(s) from wallet (string or list)
        presentation_submission: Optional presentation submission descriptor
        state: State parameter (should match request_id)
        error: Optional error code if wallet returned error
        error_description: Optional error description
    """

    request_id: RequestId
    vp_token: Optional[str | List[str]] = None
    presentation_submission: Optional[Dict[str, Any]] = None
    state: Optional[str] = None
    error: Optional[str] = None
    error_description: Optional[str] = None


@dataclass(frozen=True)
class ValidatedCredential:
    """
    A validated credential with extracted claims.

    Attributes:
        format: Credential format
        issuer: Credential issuer
        verified_claims: Extracted and verified claims
        is_valid: Whether validation succeeded
        validation_errors: List of validation errors (if any)
    """

    format: str
    issuer: str
    verified_claims: Dict[str, Any]
    is_valid: bool
    validation_errors: List[str]


@dataclass(frozen=True)
class PostWalletResponseResponse:
    """
    Response from post wallet response use case.

    Attributes:
        request_id: Request identifier
        wallet_response: Parsed wallet response
        validated_credentials: List of validated credentials (if successful)
        is_satisfied: Whether DCQL requirements are satisfied
        redirect_uri: Optional redirect URI with response_code
    """

    request_id: RequestId
    wallet_response: WalletResponse
    validated_credentials: Optional[List[ValidatedCredential]] = None
    is_satisfied: bool = False
    redirect_uri: Optional[str] = None


class PostWalletResponseError(Exception):
    """Error during wallet response processing"""

    pass


class PostWalletResponse(ABC):
    """
    Use case: Process wallet's credential submission.

    This handles the wallet's response to an authorization request.

    Flow:
    1. Retrieve presentation by request_id
    2. Validate presentation is in correct state
    3. Decrypt response if encrypted (direct_post.jwt)
    4. Validate VP tokens (signatures, trust, expiration, revocation)
    5. Check DCQL satisfaction
    6. Transition presentation to Submitted state
    7. Return validation results
    """

    @abstractmethod
    async def execute(
        self, request: PostWalletResponseRequest
    ) -> Result[PostWalletResponseResponse, PostWalletResponseError]:
        """
        Execute the post wallet response use case.

        Args:
            request: Wallet response request

        Returns:
            Success(PostWalletResponseResponse) with validation results or
            Failure(PostWalletResponseError)
        """
        pass
