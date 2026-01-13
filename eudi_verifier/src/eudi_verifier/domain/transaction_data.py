"""Transaction Data models for RQES support

This module implements transaction data support for Remote Qualified Electronic Signature
(RQES) flows, as specified in the EUDI Wallet specification.

Transaction data allows the verifier to request the wallet to display data to the user
and obtain cryptographic proof (hash) that the user saw and consented to specific content.

Key concepts:
- Transaction data is hashed and included in the authorization request
- Wallet displays the data and binds user consent cryptographically
- Supports multiple data types: QES authorization, certificate creation acceptance

Reference: ETSI EN 419 241 (Trustworthy Systems Supporting Server Signing)
"""

import base64
import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Final, List, Optional

from pydantic import BaseModel, Field, field_validator


# ======================
# Hash Algorithms
# ======================


class HashAlgorithm(str, Enum):
    """
    Supported hash algorithms for transaction data.

    Values correspond to JWA (JSON Web Algorithms) hash algorithm names.
    """

    SHA256: Final[str] = "sha-256"
    SHA384: Final[str] = "sha-384"
    SHA512: Final[str] = "sha-512"

    def compute_hash(self, data: bytes) -> bytes:
        """
        Compute hash of data using this algorithm.

        Args:
            data: Bytes to hash

        Returns:
            Hash digest bytes
        """
        if self == HashAlgorithm.SHA256:
            return hashlib.sha256(data).digest()
        elif self == HashAlgorithm.SHA384:
            return hashlib.sha384(data).digest()
        elif self == HashAlgorithm.SHA512:
            return hashlib.sha512(data).digest()
        raise ValueError(f"Unsupported hash algorithm: {self}")


# ======================
# Base Transaction Data
# ======================


class TransactionData(ABC):
    """
    Abstract base class for transaction data.

    Transaction data is content that:
    1. The wallet must display to the user
    2. The user must explicitly consent to
    3. Is cryptographically bound to the authorization response

    The data is serialized to JSON, hashed, and the hash is included
    in the authorization request.
    """

    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for JSON serialization.

        Returns:
            Dictionary representation
        """
        pass

    def to_json(self) -> str:
        """
        Serialize to JSON string.

        Returns:
            JSON string (compact, no whitespace)
        """
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)

    def to_base64url(self) -> str:
        """
        Serialize and encode as Base64URL.

        This is the format transmitted in the authorization request.

        Returns:
            Base64URL-encoded JSON string (no padding)
        """
        json_bytes = self.to_json().encode("utf-8")
        return base64.urlsafe_b64encode(json_bytes).decode("ascii").rstrip("=")

    def compute_hash(self, algorithm: HashAlgorithm) -> str:
        """
        Compute hash of transaction data.

        The hash is computed over the UTF-8 bytes of the compact JSON representation.

        Args:
            algorithm: Hash algorithm to use

        Returns:
            Base64URL-encoded hash (no padding)
        """
        json_bytes = self.to_json().encode("utf-8")
        hash_bytes = algorithm.compute_hash(json_bytes)
        return base64.urlsafe_b64encode(hash_bytes).decode("ascii").rstrip("=")


# ======================
# QES Authorization (RQES)
# ======================


class CredentialInfo(BaseModel):
    """
    Information about a credential subject.

    Used in QES authorization to describe the signer.

    Attributes:
        credential_id: Unique identifier of the credential
        description: Human-readable description
        certificates: Optional certificate chain (X.509 PEM)
    """

    credential_id: str = Field(..., min_length=1, description="Credential identifier")
    description: Optional[str] = Field(None, description="Human-readable description")
    certificates: Optional[List[str]] = Field(None, description="Certificate chain (PEM)")

    @field_validator("credential_id")
    @classmethod
    def validate_credential_id(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("credential_id cannot be blank")
        return v


class DocumentToSign(BaseModel):
    """
    Document to be signed in QES flow.

    Attributes:
        label: Human-readable label for the document
        description: Optional description
        hash: Base64URL-encoded hash of the document
        hash_algorithm: Algorithm used to compute hash
    """

    label: str = Field(..., min_length=1, description="Document label")
    description: Optional[str] = Field(None, description="Document description")
    hash: str = Field(..., min_length=1, description="Base64URL-encoded document hash")
    hash_algorithm: HashAlgorithm = Field(HashAlgorithm.SHA256, description="Hash algorithm")

    @field_validator("label", "hash")
    @classmethod
    def validate_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Field cannot be blank")
        return v


@dataclass(frozen=True)
class QesAuthorization(TransactionData):
    """
    QES (Qualified Electronic Signature) authorization transaction data.

    Used in RQES (Remote Qualified Electronic Signature) flows where the verifier
    requests the wallet to authorize a signature operation.

    The wallet displays:
    - Document to be signed (hash)
    - Credential information (who is signing)
    - Signature policy requirements

    User must explicitly consent to the signature operation.

    Attributes:
        credential_info: Information about the signing credential
        documents_to_sign: List of documents to sign
        signature_qualifier: Optional signature policy identifier
        num_signatures: Number of signatures to create
    """

    credential_info: CredentialInfo
    documents_to_sign: List[DocumentToSign]
    signature_qualifier: Optional[str] = None
    num_signatures: int = 1

    def __post_init__(self) -> None:
        """Validate QES authorization"""
        if not self.documents_to_sign:
            raise ValueError("documents_to_sign cannot be empty")
        if self.num_signatures < 1:
            raise ValueError("num_signatures must be >= 1")
        if self.num_signatures > len(self.documents_to_sign):
            raise ValueError("num_signatures cannot exceed number of documents")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result: Dict[str, Any] = {
            "type": "qes_authorization",
            "credential_info": self.credential_info.model_dump(exclude_none=True),
            "documents_to_sign": [doc.model_dump(exclude_none=True) for doc in self.documents_to_sign],
            "num_signatures": self.num_signatures,
        }
        if self.signature_qualifier:
            result["signature_qualifier"] = self.signature_qualifier
        return result


# ======================
# Certificate Creation Acceptance
# ======================


class CertificatePolicy(BaseModel):
    """
    Certificate policy for certificate creation.

    Attributes:
        policy_oid: OID of the certificate policy
        policy_name: Human-readable policy name
        policy_url: Optional URL with policy details
    """

    policy_oid: str = Field(..., pattern=r"^\d+(\.\d+)+$", description="Policy OID (e.g., 1.2.3.4)")
    policy_name: str = Field(..., min_length=1, description="Policy name")
    policy_url: Optional[str] = Field(None, description="Policy details URL")

    @field_validator("policy_name")
    @classmethod
    def validate_policy_name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("policy_name cannot be blank")
        return v


class SubjectAttributes(BaseModel):
    """
    Subject attributes for certificate creation.

    Attributes:
        common_name: Common Name (CN)
        organization: Organization (O)
        organizational_unit: Organizational Unit (OU)
        country: Country (C) - ISO 3166-1 alpha-2
        email: Email address
    """

    common_name: str = Field(..., min_length=1, description="Common Name (CN)")
    organization: Optional[str] = Field(None, description="Organization (O)")
    organizational_unit: Optional[str] = Field(None, description="Organizational Unit (OU)")
    country: Optional[str] = Field(None, min_length=2, max_length=2, description="Country (C)")
    email: Optional[str] = Field(None, description="Email address")

    @field_validator("common_name")
    @classmethod
    def validate_common_name(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("common_name cannot be blank")
        return v

    @field_validator("country")
    @classmethod
    def validate_country_code(cls, v: Optional[str]) -> Optional[str]:
        if v and (len(v) != 2 or not v.isalpha()):
            raise ValueError("country must be 2-letter ISO 3166-1 alpha-2 code")
        return v.upper() if v else None


@dataclass(frozen=True)
class QCertCreationAcceptance(TransactionData):
    """
    Qualified Certificate creation acceptance transaction data.

    Used when requesting user consent to create a qualified certificate for them.
    The wallet displays:
    - Certificate policy
    - Subject attributes (who the certificate is for)
    - Validity period
    - Key usage

    User must explicitly consent to certificate creation.

    Attributes:
        certificate_policy: Certificate policy information
        subject_attributes: Subject DN attributes
        validity_days: Certificate validity period in days
        key_usages: List of key usage purposes
    """

    certificate_policy: CertificatePolicy
    subject_attributes: SubjectAttributes
    validity_days: int
    key_usages: List[str]

    def __post_init__(self) -> None:
        """Validate certificate creation acceptance"""
        if self.validity_days < 1:
            raise ValueError("validity_days must be >= 1")
        if self.validity_days > 3650:  # 10 years max
            raise ValueError("validity_days cannot exceed 3650 (10 years)")
        if not self.key_usages:
            raise ValueError("key_usages cannot be empty")

        # Validate key usages
        valid_key_usages = {
            "digitalSignature",
            "nonRepudiation",
            "keyEncipherment",
            "dataEncipherment",
            "keyAgreement",
            "keyCertSign",
            "cRLSign",
        }
        for usage in self.key_usages:
            if usage not in valid_key_usages:
                raise ValueError(f"Invalid key usage: {usage}. Must be one of {valid_key_usages}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "type": "qcert_creation_acceptance",
            "certificate_policy": self.certificate_policy.model_dump(exclude_none=True),
            "subject_attributes": self.subject_attributes.model_dump(exclude_none=True),
            "validity_days": self.validity_days,
            "key_usages": self.key_usages,
        }


# ======================
# Factory Functions
# ======================


def create_qes_authorization(
    credential_id: str,
    credential_description: str,
    document_label: str,
    document_hash: str,
    hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256,
) -> QesAuthorization:
    """
    Create simple QES authorization for single document.

    Args:
        credential_id: Signing credential identifier
        credential_description: Human-readable credential description
        document_label: Document label
        document_hash: Base64URL-encoded document hash
        hash_algorithm: Hash algorithm used

    Returns:
        QesAuthorization instance
    """
    credential_info = CredentialInfo(credential_id=credential_id, description=credential_description)
    document = DocumentToSign(label=document_label, hash=document_hash, hash_algorithm=hash_algorithm)
    return QesAuthorization(credential_info=credential_info, documents_to_sign=[document])


def create_qcert_creation_acceptance(
    policy_oid: str,
    policy_name: str,
    common_name: str,
    organization: str,
    country: str,
    validity_days: int = 365,
    key_usages: Optional[List[str]] = None,
) -> QCertCreationAcceptance:
    """
    Create qualified certificate creation acceptance.

    Args:
        policy_oid: Certificate policy OID
        policy_name: Policy name
        common_name: Subject common name
        organization: Subject organization
        country: Subject country (ISO 3166-1 alpha-2)
        validity_days: Certificate validity in days
        key_usages: Key usage purposes

    Returns:
        QCertCreationAcceptance instance
    """
    if key_usages is None:
        key_usages = ["digitalSignature", "nonRepudiation"]

    policy = CertificatePolicy(policy_oid=policy_oid, policy_name=policy_name)
    subject = SubjectAttributes(common_name=common_name, organization=organization, country=country)
    return QCertCreationAcceptance(
        certificate_policy=policy, subject_attributes=subject, validity_days=validity_days, key_usages=key_usages
    )
