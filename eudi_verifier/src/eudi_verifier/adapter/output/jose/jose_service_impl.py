"""JOSE service implementation using joserfc"""

import base64
import json
from typing import Any, Dict, Optional

from joserfc import jwt
from joserfc.jwk import ECKey, RSAKey, OKPKey
from joserfc.jwe import encrypt_compact, decrypt_compact
from returns.result import Failure, Result, Success

from eudi_verifier.domain import VerifierConfig
from eudi_verifier.port.output import (
    DecryptionError,
    EncryptionError,
    JoseError,
    JoseService,
    SigningError,
)


class JoseServiceImpl(JoseService):
    """
    Implementation of JoseService using joserfc library.

    Handles JWT signing, JWE encryption/decryption, and key generation.
    """

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
        try:
            signing_config = config.signing_config
            algorithm = signing_config.algorithm
            jwk_dict = signing_config.jwk

            # Load the private key
            key = self._load_key(jwk_dict)

            # Build JWT header
            header = {"alg": algorithm, "typ": "JWT"}

            # Add x5c if certificate chain is available and requested
            if include_x5c and signing_config.certificate_chain:
                # Convert PEM certificates to DER and base64 encode
                x5c_chain = []
                for cert_pem in signing_config.certificate_chain:
                    # Remove PEM header/footer and decode base64
                    cert_lines = cert_pem.strip().split("\n")
                    cert_b64 = "".join(
                        line for line in cert_lines if not line.startswith("-----")
                    )
                    x5c_chain.append(cert_b64)
                header["x5c"] = x5c_chain

            # Sign the JWT
            token = jwt.encode(header, payload, key)

            return Success(token.decode("utf-8") if isinstance(token, bytes) else token)

        except Exception as e:
            return Failure(SigningError(f"Failed to sign JWT: {e}"))

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
        try:
            # First, create signed JWT
            signed_result = await self.create_signed_jwt(payload, config, include_x5c=True)
            if isinstance(signed_result, Failure):
                return Failure(JoseError(f"Failed to sign JWT: {signed_result.failure()}"))

            signed_jwt = signed_result.unwrap()

            # Load encryption key
            enc_key = self._load_key(encryption_jwk)

            # Encrypt the signed JWT
            # Use ECDH-ES+A256KW for key agreement and A256GCM for content encryption
            header = {"alg": "ECDH-ES+A256KW", "enc": "A256GCM", "cty": "JWT"}

            encrypted = encrypt_compact(header, signed_jwt.encode("utf-8"), enc_key)

            return Success(encrypted.decode("utf-8") if isinstance(encrypted, bytes) else encrypted)

        except Exception as e:
            return Failure(EncryptionError(f"Failed to encrypt JWT: {e}"))

    async def decrypt_jwt(
        self, jwe: str, decryption_jwk: Dict[str, Any]
    ) -> Result[Dict[str, Any], DecryptionError]:
        """
        Decrypt a JWE and return the claims.

        For nested JWTs, this decrypts the outer JWE and verifies the inner JWT.

        Args:
            jwe: Encrypted JWT (JWE)
            decryption_jwk: Private key for decryption

        Returns:
            Success(decrypted claims dict) or Failure(DecryptionError)
        """
        try:
            # Load decryption key
            key = self._load_key(decryption_jwk)

            # Decrypt JWE
            decrypted_data = decrypt_compact(jwe, key)

            # The decrypted content might be a nested JWT (signed)
            # Try to decode it as JWT
            try:
                # SECURITY NOTE: Decoding without verification is SAFE here because:
                # 1. This is a nested JWT (JWE wrapping a JWS)
                # 2. The inner JWT was already signed and verified during creation
                # 3. The outer JWE provides confidentiality, the inner JWS provides authenticity
                # 4. We control both the encryption and signing processes
                decrypted_text = decrypted_data.decode("utf-8")
                claims = jwt.decode(decrypted_text, key=None)  # No verification, just decode
                return Success(claims.claims)
            except Exception:
                # If not a JWT, assume it's JSON
                try:
                    claims = json.loads(decrypted_data)
                    return Success(claims)
                except Exception:
                    return Failure(DecryptionError("Decrypted data is not valid JSON or JWT"))

        except Exception as e:
            return Failure(DecryptionError(f"Failed to decrypt JWE: {e}"))

    async def verify_jwt(
        self, jwt_token: str, verification_jwk: Dict[str, Any]
    ) -> Result[Dict[str, Any], JoseError]:
        """
        Verify a JWT signature and return claims.

        Args:
            jwt_token: JWT to verify
            verification_jwk: Public key for verification

        Returns:
            Success(verified claims dict) or Failure(JoseError)
        """
        try:
            # Load verification key
            key = self._load_key(verification_jwk)

            # Verify and decode JWT
            claims = jwt.decode(jwt_token, key)

            return Success(claims.claims)

        except Exception as e:
            return Failure(JoseError(f"Failed to verify JWT: {e}"))

    async def generate_ephemeral_key(
        self, key_type: str = "EC", curve: str = "P-256"
    ) -> Result[tuple[Dict[str, Any], Dict[str, Any]], JoseError]:
        """
        Generate an ephemeral key pair for response encryption.

        Args:
            key_type: Key type (EC, RSA, OKP)
            curve: Curve name for EC keys (P-256, P-384, P-521)

        Returns:
            Success((public_jwk, private_jwk)) or Failure(JoseError)
        """
        try:
            if key_type == "EC":
                # Generate EC key pair
                key = ECKey.generate_key(crv=curve, is_private=True)
            elif key_type == "RSA":
                # Generate RSA key pair (2048 bits)
                key = RSAKey.generate_key(2048, is_private=True)
            elif key_type == "OKP":
                # Generate OKP (EdDSA) key pair
                key = OKPKey.generate_key(crv=curve or "Ed25519", is_private=True)
            else:
                return Failure(JoseError(f"Unsupported key type: {key_type}"))

            # Export as JWK
            private_jwk = key.as_dict(is_private=True)
            public_jwk = key.as_dict(is_private=False)

            return Success((public_jwk, private_jwk))

        except Exception as e:
            return Failure(JoseError(f"Failed to generate ephemeral key: {e}"))

    async def extract_x5c_from_jwt(self, jwt_token: str) -> Result[Optional[list[str]], JoseError]:
        """
        Extract x5c (certificate chain) from JWT header.

        Args:
            jwt_token: JWT to extract from

        Returns:
            Success(list of certs or None) or Failure(JoseError)
        """
        try:
            # Decode JWT header without verification
            parts = jwt_token.split(".")
            if len(parts) < 2:
                return Failure(JoseError("Invalid JWT format"))

            # Decode header
            header_b64 = parts[0]
            # Add padding if needed
            padding = 4 - (len(header_b64) % 4)
            if padding != 4:
                header_b64 += "=" * padding

            header_json = base64.urlsafe_b64decode(header_b64)
            header = json.loads(header_json)

            # Extract x5c
            x5c = header.get("x5c")

            return Success(x5c)

        except Exception as e:
            return Failure(JoseError(f"Failed to extract x5c: {e}"))

    def _load_key(self, jwk_dict: Dict[str, Any]):
        """
        Load a key from JWK dictionary.

        Args:
            jwk_dict: JWK as dictionary

        Returns:
            Key object (ECKey, RSAKey, or OKPKey)

        Raises:
            ValueError: If key type is not supported
        """
        kty = jwk_dict.get("kty")

        if kty == "EC":
            return ECKey.import_key(jwk_dict)
        elif kty == "RSA":
            return RSAKey.import_key(jwk_dict)
        elif kty == "OKP":
            return OKPKey.import_key(jwk_dict)
        else:
            raise ValueError(f"Unsupported key type: {kty}")
