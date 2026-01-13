"""Validation service port - Interface for credential validation"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List

from returns.result import Result

from eudi_verifier.domain import (
    DCQL,
    Format,
    Nonce,
    ValidationError,
    VerifierConfig,
)


class ValidationResult:
    """Result of credential validation"""

    def __init__(self, is_valid: bool, errors: List[ValidationError], verified_claims: Dict[str, Any]):
        self.is_valid = is_valid
        self.errors = errors
        self.verified_claims = verified_claims


class ValidationService(ABC):
    """
    Service for validating verifiable credentials.

    Supports multiple formats: SD-JWT VC, MSO MDoc, etc.
    Validates signatures, trust chains, expiration, revocation status.
    """

    @abstractmethod
    async def validate_vp_token(
        self, vp_token: str, format: Format, nonce: Nonce, config: VerifierConfig
    ) -> Result[ValidationResult, Exception]:
        """
        Validate a VP token (verifiable presentation).

        Performs comprehensive validation:
        - Parse and decode the VP
        - Verify signatures
        - Check issuer trust
        - Validate expiration
        - Check revocation status
        - Verify nonce/challenge

        Args:
            vp_token: VP token string (JWT, CBOR, etc.)
            format: Credential format
            nonce: Expected nonce for replay protection
            config: Verifier configuration

        Returns:
            Success(ValidationResult) or Failure(exception)
        """
        pass

    @abstractmethod
    async def validate_sd_jwt_vc(
        self, sd_jwt: str, nonce: Nonce, config: VerifierConfig
    ) -> Result[ValidationResult, Exception]:
        """
        Validate SD-JWT VC (Selective Disclosure JWT Verifiable Credential).

        Args:
            sd_jwt: SD-JWT string with disclosures and key binding
            nonce: Expected nonce
            config: Verifier configuration

        Returns:
            Success(ValidationResult) or Failure(exception)
        """
        pass

    @abstractmethod
    async def validate_mso_mdoc(
        self, mdoc_cbor: bytes, nonce: Nonce, config: VerifierConfig
    ) -> Result[ValidationResult, Exception]:
        """
        Validate MSO MDoc (ISO 18013-5 Mobile Document).

        Args:
            mdoc_cbor: CBOR-encoded mdoc
            nonce: Expected nonce
            config: Verifier configuration

        Returns:
            Success(ValidationResult) or Failure(exception)
        """
        pass

    @abstractmethod
    async def check_dcql_satisfaction(
        self, verified_claims: List[Dict[str, Any]], dcql: DCQL
    ) -> Result[bool, Exception]:
        """
        Check if provided credentials satisfy DCQL requirements.

        Args:
            verified_claims: List of verified credential claims
            dcql: DCQL query to satisfy

        Returns:
            Success(True if satisfied) or Failure(exception)
        """
        pass

    @abstractmethod
    async def extract_claims(
        self, vp_token: str, format: Format, claim_paths: List[List[str]]
    ) -> Result[Dict[str, Any], Exception]:
        """
        Extract specific claims from a VP token.

        Args:
            vp_token: VP token string
            format: Credential format
            claim_paths: List of JSON paths to extract

        Returns:
            Success(dict of extracted claims) or Failure(exception)
        """
        pass
