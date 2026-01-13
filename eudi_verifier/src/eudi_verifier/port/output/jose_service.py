"""JOSE service port - Interface for JWT/JWE operations"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from returns.result import Result

from eudi_verifier.domain import VerifierConfig


class JoseError(Exception):
    """Base exception for JOSE operations"""

    pass


class SigningError(JoseError):
    """Error during JWT signing"""

    pass


class EncryptionError(JoseError):
    """Error during JWE encryption"""

    pass


class DecryptionError(JoseError):
    """Error during JWE decryption"""

    pass


class JoseService(ABC):
    """
    Service for JOSE operations (JWT signing, JWE encryption/decryption).

    Handles creation of JWT-Secured Authorization Requests (JAR) and
    processing of encrypted wallet responses.
    """

    @abstractmethod
    async def create_signed_jwt(
        self, payload: Dict[str, Any], config: VerifierConfig, include_x5c: bool = True
    ) -> Result[str, SigningError]:
        """
        Create a signed JWT (JAR).

        Args:
            payload: JWT claims
            config: Verifier configuration with signing key
            include_x5c: Whether to include x5c header (certificate chain)

        Returns:
            Success(signed JWT string) or Failure(SigningError)
        """
        pass

    @abstractmethod
    async def create_signed_and_encrypted_jwt(
        self, payload: Dict[str, Any], config: VerifierConfig, encryption_jwk: Dict[str, Any]
    ) -> Result[str, JoseError]:
        """
        Create a signed and encrypted JWT (nested JWT).

        The JWT is first signed, then encrypted with the provided encryption key.

        Args:
            payload: JWT claims
            config: Verifier configuration with signing key
            encryption_jwk: Public key for encryption (ephemeral key)

        Returns:
            Success(encrypted JWT string) or Failure(JoseError)
        """
        pass

    @abstractmethod
    async def decrypt_jwt(self, jwe: str, decryption_jwk: Dict[str, Any]) -> Result[Dict[str, Any], DecryptionError]:
        """
        Decrypt a JWE and return the claims.

        Args:
            jwe: Encrypted JWT (JWE)
            decryption_jwk: Private key for decryption

        Returns:
            Success(decrypted claims dict) or Failure(DecryptionError)
        """
        pass

    @abstractmethod
    async def verify_jwt(self, jwt: str, verification_jwk: Dict[str, Any]) -> Result[Dict[str, Any], JoseError]:
        """
        Verify a JWT signature and return claims.

        Args:
            jwt: JWT to verify
            verification_jwk: Public key for verification

        Returns:
            Success(verified claims dict) or Failure(JoseError)
        """
        pass

    @abstractmethod
    async def generate_ephemeral_key(
        self, key_type: str = "EC", curve: str = "P-256"
    ) -> Result[tuple[Dict[str, Any], Dict[str, Any]], JoseError]:
        """
        Generate an ephemeral key pair for response encryption.

        Args:
            key_type: Key type (EC, RSA, etc.)
            curve: Curve name for EC keys (P-256, P-384, P-521)

        Returns:
            Success((public_jwk, private_jwk)) or Failure(JoseError)
        """
        pass

    @abstractmethod
    async def extract_x5c_from_jwt(self, jwt: str) -> Result[Optional[list[str]], JoseError]:
        """
        Extract x5c (certificate chain) from JWT header.

        Args:
            jwt: JWT to extract from

        Returns:
            Success(list of certs or None) or Failure(JoseError)
        """
        pass
