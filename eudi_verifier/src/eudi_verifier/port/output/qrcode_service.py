"""QR code service port - Interface for QR code generation"""

from abc import ABC, abstractmethod
from enum import Enum

from returns.result import Result


class QrCodeFormat(str, Enum):
    """QR code image format"""

    PNG = "png"
    SVG = "svg"
    JPEG = "jpeg"


class QrCodeError(Exception):
    """Error during QR code generation"""

    pass


class QrCodeService(ABC):
    """
    Service for generating QR codes for OpenID4VP authorization requests.

    Generates QR codes that wallets can scan to initiate credential presentation.
    """

    @abstractmethod
    async def generate_qr_code(
        self, data: str, format: QrCodeFormat = QrCodeFormat.PNG, size: int = 300, error_correction: str = "M"
    ) -> Result[bytes, QrCodeError]:
        """
        Generate QR code image from data.

        Args:
            data: Data to encode (authorization request URI)
            format: Image format (PNG, SVG, JPEG)
            size: QR code size in pixels
            error_correction: Error correction level (L, M, Q, H)

        Returns:
            Success(image bytes) or Failure(QrCodeError)
        """
        pass

    @abstractmethod
    async def generate_authorization_request_qr(
        self, authorization_request: str, format: QrCodeFormat = QrCodeFormat.PNG
    ) -> Result[bytes, QrCodeError]:
        """
        Generate QR code for OpenID4VP authorization request.

        Optimizes QR code generation for authorization request URIs.

        Args:
            authorization_request: Full authorization request (eudi-openid4vp://...)
            format: Image format

        Returns:
            Success(QR code image bytes) or Failure(QrCodeError)
        """
        pass
