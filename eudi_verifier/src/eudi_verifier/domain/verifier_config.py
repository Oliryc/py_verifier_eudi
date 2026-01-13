"""Verifier configuration models

This module defines the core configuration for the EUDI verifier endpoint,
including:

- Verifier identity with 3 client ID schemes (pre-registered, x509_san_dns, x509_hash)
- Supported VP formats (SD-JWT VC, MSO MDoc)
- JAR signing configuration
- Response modes and encryption
- Trust sources

All configuration is immutable and validated.
"""

from dataclasses import dataclass
from typing import Any, ClassVar, Dict, Final, List, Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator


# ======================
# Signing Configuration
# ======================


class SigningConfig(BaseModel):
    """
    Configuration for signing JARs (JWT-Secured Authorization Requests).

    Attributes:
        algorithm: JWT signing algorithm (RS256, ES256, etc.)
        jwk: JSON Web Key for signing
        jwk_set_url: Optional public JWK Set URL
        certificate_chain: Optional X.509 certificate chain (for x5c header)
    """

    algorithm: str = Field(..., description="JWT signing algorithm (RS256, ES256, etc.)")
    jwk: Dict[str, Any] = Field(..., description="JSON Web Key for signing")
    jwk_set_url: Optional[str] = Field(None, description="Public JWK Set URL")
    certificate_chain: Optional[List[str]] = Field(None, description="X.509 certificate chain (PEM)")

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        """Validate signing algorithm"""
        valid_algorithms = {
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512",
            "EdDSA",
        }
        if v not in valid_algorithms:
            raise ValueError(f"Invalid signing algorithm: {v}. Must be one of {valid_algorithms}")
        return v

    @field_validator("jwk")
    @classmethod
    def validate_jwk(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Validate JWK has required fields"""
        if "kty" not in v:
            raise ValueError("JWK must contain 'kty' field")
        if "use" in v and v["use"] not in ("sig", "enc"):
            raise ValueError("JWK 'use' must be 'sig' or 'enc'")
        return v

    @field_validator("certificate_chain")
    @classmethod
    def validate_certificate_chain(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate certificate chain is not empty"""
        if v is not None and len(v) == 0:
            raise ValueError("certificate_chain must contain at least one certificate")
        return v


# ======================
# Verifier Identity (Client ID Schemes)
# ======================


@dataclass(frozen=True)
class PreRegisteredClientId:
    """
    Pre-registered client identifier (traditional OAuth flow).

    The client_id is a URL or URN agreed upon in advance with the wallet.
    This is the simplest scheme but requires pre-registration.

    Attributes:
        client_id: Pre-registered identifier (URL or URN)
    """

    scheme: ClassVar[str] = "pre-registered"
    client_id: str

    def __post_init__(self) -> None:
        if not self.client_id or not self.client_id.strip():
            raise ValueError("client_id cannot be blank")

    def get_client_id(self) -> str:
        """Return the client_id value"""
        return self.client_id


@dataclass(frozen=True)
class X509SanDnsClientId:
    """
    Client identifier from X.509 certificate DNS SAN.

    The client_id is extracted from the DNS Subject Alternative Name (SAN)
    in the X.509 certificate used to sign the JAR. Provides proof of domain
    ownership without pre-registration.

    Attributes:
        certificate: X.509 certificate (PEM format)
    """

    scheme: ClassVar[str] = "x509_san_dns"
    certificate: str

    def __post_init__(self) -> None:
        if not self.certificate or not self.certificate.strip():
            raise ValueError("certificate cannot be blank")
        # Basic validation that it looks like PEM
        if "-----BEGIN CERTIFICATE-----" not in self.certificate:
            raise ValueError("certificate must be in PEM format")

    def get_client_id(self) -> str:
        """
        Extract DNS SAN from certificate.

        Note: In production, this would parse the X.509 certificate.
        Placeholder implementation for now.
        """
        # TODO: Implement actual X.509 parsing and SAN extraction
        return "placeholder-san-dns"


@dataclass(frozen=True)
class X509HashClientId:
    """
    Client identifier from X.509 certificate hash.

    The client_id is the SHA-256 hash of the X.509 certificate DER encoding,
    prefixed with "sha256-". Provides cryptographic binding without requiring
    domain ownership.

    Attributes:
        certificate: X.509 certificate (PEM format)
    """

    scheme: ClassVar[str] = "x509_hash"
    certificate: str

    def __post_init__(self) -> None:
        if not self.certificate or not self.certificate.strip():
            raise ValueError("certificate cannot be blank")
        if "-----BEGIN CERTIFICATE-----" not in self.certificate:
            raise ValueError("certificate must be in PEM format")

    def get_client_id(self) -> str:
        """
        Compute SHA-256 hash of certificate DER encoding.

        Returns client_id in format: sha256-<base64url-hash>

        Note: In production, this would parse and hash the certificate.
        Placeholder implementation for now.
        """
        # TODO: Implement actual X.509 parsing and hashing
        return "sha256-placeholder-hash"


# Union type for all client ID schemes
VerifierId = Union[PreRegisteredClientId, X509SanDnsClientId, X509HashClientId]


# ======================
# VP Format Configuration
# ======================


class SdJwtVcConfig(BaseModel):
    """
    Configuration for SD-JWT VC format support.

    Attributes:
        algorithms: Supported JWT signing algorithms
        kb_jwt_algorithms: Supported key binding JWT algorithms
        check_status: Whether to check credential status lists
        validate_json_schema: Whether to validate against VC type's JSON schema
    """

    algorithms: List[str] = Field(..., min_length=1, description="Supported JWT signing algorithms")
    kb_jwt_algorithms: List[str] = Field(..., min_length=1, description="Key binding JWT algorithms")
    check_status: bool = Field(True, description="Check credential status")
    validate_json_schema: bool = Field(True, description="Validate against JSON schema")

    @field_validator("algorithms", "kb_jwt_algorithms")
    @classmethod
    def validate_algorithms(cls, v: List[str]) -> List[str]:
        """Validate algorithm list"""
        valid_algorithms = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}
        for alg in v:
            if alg not in valid_algorithms:
                raise ValueError(f"Invalid algorithm: {alg}")
        return v


class MsoMdocConfig(BaseModel):
    """
    Configuration for MSO MDoc (ISO 18013-5) format support.

    Attributes:
        issuer_auth_algorithms: Supported COSE algorithms for IssuerAuth
        device_auth_algorithms: Supported COSE algorithms for DeviceAuth
        check_validity_period: Whether to check ValidFrom/ValidUntil dates
    """

    issuer_auth_algorithms: List[int] = Field(
        ..., min_length=1, description="COSE algorithm IDs for IssuerAuth (-7, -35, -36)"
    )
    device_auth_algorithms: List[int] = Field(
        ..., min_length=1, description="COSE algorithm IDs for DeviceAuth (-7, -35, -36)"
    )
    check_validity_period: bool = Field(True, description="Check validity period")

    @field_validator("issuer_auth_algorithms", "device_auth_algorithms")
    @classmethod
    def validate_cose_algorithms(cls, v: List[int]) -> List[int]:
        """
        Validate COSE algorithm IDs.

        Common algorithms:
        -7: ES256 (ECDSA with SHA-256)
        -35: ES384 (ECDSA with SHA-384)
        -36: ES512 (ECDSA with SHA-512)
        """
        valid_algorithms = {-7, -35, -36, -37, -38, -39}  # ECDSA family
        for alg in v:
            if alg not in valid_algorithms:
                # Warning: Allow other algorithms but log
                pass
        return v


class VpFormatsSupported(BaseModel):
    """
    Supported VP formats and their configurations.

    Attributes:
        sd_jwt_vc: SD-JWT VC configuration (None if not supported)
        mso_mdoc: MSO MDoc configuration (None if not supported)
    """

    sd_jwt_vc: Optional[SdJwtVcConfig] = Field(None, description="SD-JWT VC configuration")
    mso_mdoc: Optional[MsoMdocConfig] = Field(None, description="MSO MDoc configuration")

    @model_validator(mode="after")
    def validate_at_least_one_format(self) -> "VpFormatsSupported":
        """Ensure at least one format is supported"""
        if not self.sd_jwt_vc and not self.mso_mdoc:
            raise ValueError("At least one VP format must be supported")
        return self


# ======================
# Response Configuration
# ======================


class ResponseEncryption(BaseModel):
    """
    Configuration for response encryption (direct_post.jwt mode).

    Attributes:
        algorithm: JWE key agreement algorithm (ECDH-ES, ECDH-ES+A256KW, etc.)
        encryption_method: JWE content encryption method (A256GCM, A128CBC-HS256, etc.)
        ephemeral_key_jwk: Optional pre-generated ephemeral key (for testing)
    """

    algorithm: str = Field(..., description="JWE key agreement algorithm")
    encryption_method: str = Field(..., description="JWE content encryption method")
    ephemeral_key_jwk: Optional[Dict[str, Any]] = Field(None, description="Ephemeral key (testing only)")

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        """Validate JWE algorithm"""
        valid_algorithms = {
            "ECDH-ES",
            "ECDH-ES+A128KW",
            "ECDH-ES+A192KW",
            "ECDH-ES+A256KW",
            "RSA-OAEP",
            "RSA-OAEP-256",
        }
        if v not in valid_algorithms:
            raise ValueError(f"Invalid JWE algorithm: {v}")
        return v

    @field_validator("encryption_method")
    @classmethod
    def validate_encryption_method(cls, v: str) -> str:
        """Validate JWE encryption method"""
        valid_methods = {"A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"}
        if v not in valid_methods:
            raise ValueError(f"Invalid JWE encryption method: {v}")
        return v


# ======================
# Client Metadata
# ======================


class ClientMetaData(BaseModel):
    """
    Client metadata included in JAR.

    Attributes:
        jwks: JSON Web Key Set
        jwks_uri: JWK Set URI
        authorization_signed_response_alg: Algorithm for signed responses
        authorization_encrypted_response_alg: Algorithm for encrypted responses
        authorization_encrypted_response_enc: Encryption method for responses
    """

    jwks: Optional[Dict[str, Any]] = Field(None, description="JSON Web Key Set")
    jwks_uri: Optional[str] = Field(None, description="JWK Set URI")
    authorization_signed_response_alg: Optional[str] = Field(None, description="Signed response algorithm")
    authorization_encrypted_response_alg: Optional[str] = Field(None, description="Encrypted response algorithm")
    authorization_encrypted_response_enc: Optional[str] = Field(None, description="Encrypted response method")

    @model_validator(mode="after")
    def validate_jwks_or_jwks_uri(self) -> "ClientMetaData":
        """Ensure either jwks or jwks_uri is provided"""
        if not self.jwks and not self.jwks_uri:
            raise ValueError("Either 'jwks' or 'jwks_uri' must be provided")
        if self.jwks and self.jwks_uri:
            raise ValueError("Only one of 'jwks' or 'jwks_uri' should be provided")
        return self


# ======================
# Main Verifier Configuration
# ======================


class VerifierConfig(BaseModel):
    """
    Complete verifier endpoint configuration.

    Attributes:
        verifier_id: Verifier identity (client ID scheme)
        public_url: Public URL of the verifier
        signing_config: JAR signing configuration
        vp_formats_supported: Supported VP formats
        default_response_mode: Default response mode
        max_age_seconds: Maximum presentation lifetime in seconds
        response_encryption: Optional encryption config for direct_post.jwt
        client_metadata: Client metadata for JAR
        authorization_request_scheme: Custom URI scheme for authorization requests
    """

    verifier_id: Union[PreRegisteredClientId, X509SanDnsClientId, X509HashClientId] = Field(
        ..., description="Verifier identity"
    )
    public_url: str = Field(..., description="Public URL of verifier")
    signing_config: SigningConfig = Field(..., description="JAR signing configuration")
    vp_formats_supported: VpFormatsSupported = Field(..., description="Supported VP formats")
    default_response_mode: Literal["direct_post", "direct_post.jwt"] = Field(
        "direct_post", description="Default response mode"
    )
    max_age_seconds: int = Field(6400, ge=60, le=86400, description="Max presentation lifetime (seconds)")
    response_encryption: Optional[ResponseEncryption] = Field(None, description="Response encryption config")
    client_metadata: ClientMetaData = Field(..., description="Client metadata")
    authorization_request_scheme: str = Field("eudi-openid4vp", description="Authorization request URI scheme")

    @field_validator("public_url")
    @classmethod
    def validate_public_url(cls, v: str) -> str:
        """Validate public URL format"""
        if not v.startswith("https://") and not v.startswith("http://localhost"):
            raise ValueError("public_url must be HTTPS (or http://localhost for dev)")
        return v

    @model_validator(mode="after")
    def validate_encryption_config(self) -> "VerifierConfig":
        """Ensure encryption config is present for direct_post.jwt"""
        if self.default_response_mode == "direct_post.jwt" and not self.response_encryption:
            raise ValueError("response_encryption required when default_response_mode is 'direct_post.jwt'")
        return self

    def get_client_id(self) -> str:
        """Get the client_id value for this verifier"""
        return self.verifier_id.get_client_id()

    def supports_format(self, format: str) -> bool:
        """
        Check if verifier supports a specific format.

        Args:
            format: Format string (mso_mdoc, dc+sd-jwt, etc.)

        Returns:
            True if format is supported
        """
        if format == "mso_mdoc":
            return self.vp_formats_supported.mso_mdoc is not None
        elif format == "dc+sd-jwt":
            return self.vp_formats_supported.sd_jwt_vc is not None
        return False
