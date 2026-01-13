"""Trust service port - Interface for trust and certificate validation"""

from abc import ABC, abstractmethod
from typing import List, Optional

from returns.result import Result


class TrustValidationError(Exception):
    """Error during trust validation"""

    pass


class CertificateChain:
    """Represents an X.509 certificate chain"""

    def __init__(self, certificates: List[str]):
        """
        Initialize certificate chain.

        Args:
            certificates: List of PEM-encoded certificates (leaf first)
        """
        self.certificates = certificates

    @property
    def leaf_certificate(self) -> str:
        """Get the leaf (end-entity) certificate"""
        return self.certificates[0] if self.certificates else ""

    @property
    def issuer_certificates(self) -> List[str]:
        """Get intermediate and root certificates"""
        return self.certificates[1:] if len(self.certificates) > 1 else []


class TrustResult:
    """Result of trust validation"""

    def __init__(self, is_trusted: bool, issuer: str, reason: Optional[str] = None):
        self.is_trusted = is_trusted
        self.issuer = issuer
        self.reason = reason


class TrustService(ABC):
    """
    Service for validating trust chains and issuer trust.

    Supports multiple trust sources:
    - Keystore (JKS, PKCS12)
    - LOTL (List of Trusted Lists)
    - Trust patterns (regex-based)
    """

    @abstractmethod
    async def validate_certificate_chain(
        self, chain: CertificateChain, trust_anchors: Optional[List[str]] = None
    ) -> Result[TrustResult, TrustValidationError]:
        """
        Validate an X.509 certificate chain.

        Args:
            chain: Certificate chain to validate
            trust_anchors: Optional list of trusted root certificates (PEM)

        Returns:
            Success(TrustResult) or Failure(TrustValidationError)
        """
        pass

    @abstractmethod
    async def is_issuer_trusted(self, issuer: str) -> Result[bool, Exception]:
        """
        Check if an issuer identifier is trusted.

        Args:
            issuer: Issuer identifier (DID, URL, DN, etc.)

        Returns:
            Success(True if trusted) or Failure(exception)
        """
        pass

    @abstractmethod
    async def extract_issuer_from_certificate(self, certificate_pem: str) -> Result[str, Exception]:
        """
        Extract issuer DN from X.509 certificate.

        Args:
            certificate_pem: PEM-encoded certificate

        Returns:
            Success(issuer DN string) or Failure(exception)
        """
        pass

    @abstractmethod
    async def extract_san_dns_from_certificate(self, certificate_pem: str) -> Result[Optional[str], Exception]:
        """
        Extract DNS Subject Alternative Name from certificate.

        Args:
            certificate_pem: PEM-encoded certificate

        Returns:
            Success(DNS SAN or None) or Failure(exception)
        """
        pass

    @abstractmethod
    async def compute_certificate_hash(self, certificate_pem: str) -> Result[str, Exception]:
        """
        Compute SHA-256 hash of certificate DER encoding.

        Returns hash in format: sha256-<base64url>

        Args:
            certificate_pem: PEM-encoded certificate

        Returns:
            Success(hash string) or Failure(exception)
        """
        pass

    @abstractmethod
    async def load_trust_anchors_from_keystore(self, keystore_path: str, password: str) -> Result[List[str], Exception]:
        """
        Load trusted certificates from keystore (JKS, PKCS12).

        Args:
            keystore_path: Path to keystore file
            password: Keystore password

        Returns:
            Success(list of PEM certificates) or Failure(exception)
        """
        pass

    @abstractmethod
    async def refresh_lotl(self, lotl_url: str) -> Result[int, Exception]:
        """
        Refresh LOTL (List of Trusted Lists) from remote source.

        Args:
            lotl_url: URL of LOTL XML file

        Returns:
            Success(number of trust lists loaded) or Failure(exception)
        """
        pass
