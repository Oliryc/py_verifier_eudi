"""Wallet response models and error types

This module defines the response types from wallet to verifier, including:
- Wallet response formats (direct_post, direct_post.jwt)
- Verifiable presentations (vp_token)
- Error responses
- Validation error hierarchy

All response types are immutable and validated.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Final, Literal

from pydantic import BaseModel, Field, field_validator


# ======================
# Verifiable Presentation Formats
# ======================


@dataclass(frozen=True)
class VpTokenStr:
    """
    VP token as string.

    Single verifiable presentation as string (JWT, SD-JWT VC, etc.)

    Attributes:
        value: String representation of VP
    """

    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("VP token cannot be blank")


@dataclass(frozen=True)
class VpTokenArray:
    """
    VP token as array.

    Multiple verifiable presentations (can be different formats).
    Used when DCQL requests multiple credentials.

    Attributes:
        values: List of VP strings
    """

    values: list[str]

    def __post_init__(self) -> None:
        if not self.values:
            raise ValueError("VP token array cannot be empty")
        for i, vp in enumerate(self.values):
            if not vp or not vp.strip():
                raise ValueError(f"VP token at index {i} cannot be blank")


# Union type for VP token
VpToken = VpTokenStr | VpTokenArray


# ======================
# Presentation Submission
# ======================


class PresentationSubmission(BaseModel):
    """
    Presentation submission descriptor.

    Maps vp_token contents to presentation definition requirements.
    Follows DIF Presentation Exchange spec.

    Attributes:
        id: Unique submission identifier
        definition_id: ID of the presentation definition being satisfied
        descriptor_map: Mapping of inputs to credentials
    """

    id: str = Field(..., min_length=1, description="Submission identifier")
    definition_id: str = Field(..., min_length=1, description="Presentation definition ID")
    descriptor_map: list[dict[str, Any]] = Field(..., min_length=1, description="Input descriptor mapping")

    @field_validator("id", "definition_id")
    @classmethod
    def validate_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Field cannot be blank")
        return v


# ======================
# Wallet Response Types
# ======================


@dataclass(frozen=True)
class WalletResponseVpToken:
    """
    Successful wallet response with credentials.

    Contains verifiable presentations (vp_token) and optional presentation submission.

    Attributes:
        vp_token: Verifiable presentation(s)
        presentation_submission: Optional presentation submission descriptor
        state: State parameter echoed from request
    """

    vp_token: VpToken
    presentation_submission: PresentationSubmission | None
    state: str

    def __post_init__(self) -> None:
        if not self.state or not self.state.strip():
            raise ValueError("state cannot be blank")

    def get_vp_tokens_as_list(self) -> list[str]:
        """
        Get VP tokens as list.

        Normalizes both VpTokenStr and VpTokenArray to list format.

        Returns:
            List of VP token strings
        """
        if isinstance(self.vp_token, VpTokenStr):
            return [self.vp_token.value]
        return self.vp_token.values


@dataclass(frozen=True)
class WalletResponseError:
    """
    Error response from wallet.

    Wallet encountered an error and could not provide credentials.

    Attributes:
        error: Error code (invalid_request, access_denied, etc.)
        error_description: Human-readable error description
        state: State parameter echoed from request
    """

    error: str
    error_description: str | None
    state: str

    def __post_init__(self) -> None:
        if not self.error or not self.error.strip():
            raise ValueError("error cannot be blank")
        if not self.state or not self.state.strip():
            raise ValueError("state cannot be blank")

    def is_user_cancelled(self) -> bool:
        """Check if error indicates user cancelled/denied"""
        return self.error in ("access_denied", "consent_required")


# Union type for wallet response
WalletResponse = WalletResponseVpToken | WalletResponseError


# ======================
# Response Retrieval Methods
# ======================


class GetWalletResponseMethod(str, Enum):
    """
    Method for retrieving wallet response.

    REDIRECT: Query parameter in redirect URI (deprecated, not recommended)
    POLL: Polling endpoint with response_code
    """

    REDIRECT: Final[str] = "redirect"
    POLL: Final[str] = "poll"


# ======================
# Validation Error Types
# ======================


@dataclass(frozen=True)
class ValidationError:
    """
    Base validation error.

    Attributes:
        message: Error message
        details: Optional additional details
    """

    message: str = ""
    details: dict[str, Any | None] = None


@dataclass(frozen=True)
class InvalidFormat(ValidationError):
    """VP token format is invalid (not parseable)"""

    format: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "message", f"Invalid VP format: {self.format}")


@dataclass(frozen=True)
class UnsupportedFormat(ValidationError):
    """VP token format is not supported by verifier"""

    format: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "message", f"Unsupported VP format: {self.format}")


@dataclass(frozen=True)
class InvalidSignature(ValidationError):
    """VP signature verification failed"""

    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "message", f"Invalid signature: {self.reason}")


@dataclass(frozen=True)
class UntrustedIssuer(ValidationError):
    """VP issuer is not trusted"""

    issuer: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "message", f"Untrusted issuer: {self.issuer}")


@dataclass(frozen=True)
class CredentialExpired(ValidationError):
    """Credential has expired"""

    expiry_date: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "message", f"Credential expired on: {self.expiry_date}")


@dataclass(frozen=True)
class CredentialRevoked(ValidationError):
    """Credential has been revoked"""

    revocation_date: str | None = None

    def __post_init__(self) -> None:
        msg = "Credential has been revoked"
        if self.revocation_date:
            msg += f" on {self.revocation_date}"
        object.__setattr__(self, "message", msg)


@dataclass(frozen=True)
class InvalidNonce(ValidationError):
    """Nonce does not match expected value"""

    expected: str = ""
    actual: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "message", f"Nonce mismatch. Expected: {self.expected}, Actual: {self.actual}")


@dataclass(frozen=True)
class MissingRequiredClaim(ValidationError):
    """Required claim is missing from credential"""

    claim_path: list[str] | None = None

    def __post_init__(self) -> None:
        if self.claim_path is None:
            object.__setattr__(self, "claim_path", [])
        path_str = " -> ".join(self.claim_path) if self.claim_path else "unknown"
        object.__setattr__(self, "message", f"Missing required claim: {path_str}")


@dataclass(frozen=True)
class DcqlNotSatisfied(ValidationError):
    """DCQL query not satisfied by provided credentials"""

    query_id: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "message", f"DCQL query '{self.query_id}' not satisfied: {self.reason}")


@dataclass(frozen=True)
class InvalidKeyBinding(ValidationError):
    """Key binding proof is invalid"""

    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "message", f"Invalid key binding: {self.reason}")


# ======================
# Factory Functions
# ======================


def create_vp_token_response(
    vp_token: str | list[str],
    state: str,
    presentation_submission: PresentationSubmission | None = None,
) -> WalletResponseVpToken:
    """
    Create wallet response with VP token.

    Args:
        vp_token: Single VP string or list of VPs
        state: State parameter from request
        presentation_submission: Optional presentation submission

    Returns:
        WalletResponseVpToken instance
    """
    if isinstance(vp_token, str):
        vp = VpTokenStr(value=vp_token)
    else:
        vp = VpTokenArray(values=vp_token)

    return WalletResponseVpToken(vp_token=vp, presentation_submission=presentation_submission, state=state)


def create_error_response(error: str, state: str, error_description: str | None = None) -> WalletResponseError:
    """
    Create wallet error response.

    Args:
        error: Error code
        state: State parameter from request
        error_description: Optional error description

    Returns:
        WalletResponseError instance
    """
    return WalletResponseError(error=error, error_description=error_description, state=state)


def is_successful_response(response: WalletResponse) -> bool:
    """
    Check if wallet response is successful (contains VP token).

    Args:
        response: Wallet response

    Returns:
        True if response contains VP token
    """
    return isinstance(response, WalletResponseVpToken)


def is_error_response(response: WalletResponse) -> bool:
    """
    Check if wallet response is an error.

    Args:
        response: Wallet response

    Returns:
        True if response is an error
    """
    return isinstance(response, WalletResponseError)
