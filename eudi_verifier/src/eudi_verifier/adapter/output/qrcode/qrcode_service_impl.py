"""QR code service implementation using qrcode library"""

import io
from typing import Any

import qrcode
import qrcode.image.svg
from PIL import Image
from returns.result import Failure, Result, Success

from eudi_verifier.port.output import QrCodeError, QrCodeFormat, QrCodeService


class QrCodeServiceImpl(QrCodeService):
    """
    Implementation of QrCodeService using the qrcode library.

    Generates QR codes in various formats (PNG, SVG, JPEG) for
    OpenID4VP authorization requests.
    """

    async def generate_qr_code(
        self,
        data: str,
        format: QrCodeFormat = QrCodeFormat.PNG,
        size: int = 300,
        error_correction: str = "M",
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
        try:
            # Map error correction level
            error_correction_map = {
                "L": qrcode.constants.ERROR_CORRECT_L,
                "M": qrcode.constants.ERROR_CORRECT_M,
                "Q": qrcode.constants.ERROR_CORRECT_Q,
                "H": qrcode.constants.ERROR_CORRECT_H,
            }

            ec_level = error_correction_map.get(error_correction, qrcode.constants.ERROR_CORRECT_M)

            # Create QR code instance
            qr = qrcode.QRCode(
                version=None,  # Auto-detect version based on data
                error_correction=ec_level,
                box_size=10,
                border=4,
            )

            # Add data
            qr.add_data(data)
            qr.make(fit=True)

            # Generate image based on format
            if format == QrCodeFormat.SVG:
                # Generate SVG
                factory = qrcode.image.svg.SvgPathImage
                img = qr.make_image(image_factory=factory)

                # Convert to bytes
                buffer = io.BytesIO()
                img.save(buffer)
                return Success(buffer.getvalue())

            else:
                # Generate PIL image (for PNG/JPEG)
                img = qr.make_image(fill_color="black", back_color="white")

                # Resize to requested size
                img = img.resize((size, size), Image.Resampling.LANCZOS)

                # Convert to bytes
                buffer = io.BytesIO()

                if format == QrCodeFormat.PNG:
                    img.save(buffer, format="PNG")
                elif format == QrCodeFormat.JPEG:
                    # Convert RGBA to RGB for JPEG (no alpha channel support)
                    if img.mode in ("RGBA", "LA"):
                        background = Image.new("RGB", img.size, (255, 255, 255))
                        background.paste(img, mask=img.split()[-1])
                        img = background
                    img.save(buffer, format="JPEG", quality=95)
                else:
                    return Failure(QrCodeError(f"Unsupported format: {format}"))

                return Success(buffer.getvalue())

        except Exception as e:
            return Failure(QrCodeError(f"Failed to generate QR code: {e}"))

    async def generate_authorization_request_qr(
        self, authorization_request: str, format: QrCodeFormat = QrCodeFormat.PNG
    ) -> Result[bytes, QrCodeError]:
        """
        Generate QR code for OpenID4VP authorization request.

        Optimizes QR code generation for authorization request URIs.
        Uses higher error correction for reliability.

        Args:
            authorization_request: Full authorization request (eudi-openid4vp://...)
            format: Image format

        Returns:
            Success(QR code image bytes) or Failure(QrCodeError)
        """
        try:
            # Use higher error correction for authorization requests
            # This ensures the QR code remains scannable even if partially obscured
            result = await self.generate_qr_code(
                data=authorization_request, format=format, size=400, error_correction="H"
            )

            return result

        except Exception as e:
            return Failure(QrCodeError(f"Failed to generate authorization request QR: {e}"))
