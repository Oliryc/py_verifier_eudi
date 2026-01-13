"""Value objects for the domain layer"""

from dataclasses import dataclass
from enum import Enum
from typing import Final


@dataclass(frozen=True)
class TransactionId:
    """Unique identifier for a presentation transaction"""

    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("TransactionId cannot be blank")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class RequestId:
    """
    Identifier of the Presentation which is communicated to the wallet as 'state'.
    Used to correlate an authorization response from wallet with a Presentation.
    """

    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("RequestId cannot be blank")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Nonce:
    """Cryptographic nonce for replay protection"""

    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("Nonce cannot be blank")

    def __str__(self) -> str:
        return self.value

    @staticmethod
    def generate() -> "Nonce":
        """Generate a cryptographically secure random nonce"""
        import secrets
        return Nonce(value=secrets.token_urlsafe(32))


@dataclass(frozen=True)
class ResponseCode:
    """Response code for redirect-based wallet response retrieval"""

    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("ResponseCode cannot be blank")

    def __str__(self) -> str:
        return self.value


class Format(str, Enum):
    """
    Credential format types supported by the verifier

    MSO_MDOC: ISO/IEC 18013-5 Mobile Driving License format
    SD_JWT_VC: IETF SD-JWT VC (Selective Disclosure JWT Verifiable Credential)
    W3C_JWT_VC: W3C JWT VC (not yet fully implemented)
    """

    MSO_MDOC: Final[str] = "mso_mdoc"
    SD_JWT_VC: Final[str] = "dc+sd-jwt"
    W3C_JWT_VC: Final[str] = "jwt_vc_json"

    def __str__(self) -> str:
        return self.value


class RequestUriMethod(str, Enum):
    """Method for wallet to retrieve request object"""

    GET: Final[str] = "get"
    POST: Final[str] = "post"


class ResponseModeOption(str, Enum):
    """Response mode options for wallet responses"""

    DIRECT_POST: Final[str] = "direct_post"
    DIRECT_POST_JWT: Final[str] = "direct_post.jwt"
