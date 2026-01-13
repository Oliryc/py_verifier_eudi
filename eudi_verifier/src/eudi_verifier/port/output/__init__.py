"""Output ports - Interfaces for external dependencies"""

from eudi_verifier.port.output.presentation_repository import (
    PresentationRepository,
    PresentationNotFound,
)
from eudi_verifier.port.output.jose_service import (
    JoseService,
    JoseError,
    SigningError,
    EncryptionError,
    DecryptionError,
)
from eudi_verifier.port.output.validation_service import (
    ValidationService,
    ValidationResult,
)
from eudi_verifier.port.output.trust_service import (
    TrustService,
    TrustResult,
    TrustValidationError,
    CertificateChain,
)
from eudi_verifier.port.output.qrcode_service import (
    QrCodeService,
    QrCodeFormat,
    QrCodeError,
)

__all__ = [
    # Presentation Repository
    "PresentationRepository",
    "PresentationNotFound",
    # JOSE Service
    "JoseService",
    "JoseError",
    "SigningError",
    "EncryptionError",
    "DecryptionError",
    # Validation Service
    "ValidationService",
    "ValidationResult",
    # Trust Service
    "TrustService",
    "TrustResult",
    "TrustValidationError",
    "CertificateChain",
    # QR Code Service
    "QrCodeService",
    "QrCodeFormat",
    "QrCodeError",
]
