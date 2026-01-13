# JAR Creation and Encryption - Detailed Design

**Document Version**: 1.0
**Last Updated**: 2025-01-03
**Status**: Design Phase

---

## 1. OVERVIEW

JAR (JWT-Secured Authorization Request) is the request object sent to wallets according to RFC 9101. It contains the DCQL query, nonce, response_uri, and client metadata. This subsystem creates, signs, and optionally encrypts these JARs.

---

## 2. JAR STRUCTURE

### 2.1 JWT Header

```json
{
  "typ": "oauth-authz-req+jwt",
  "alg": "RS256",
  "kid": "verifier-key-1"  // For pre-registered
  // OR
  "x5c": ["base64cert", ...]  // For X.509 schemes
}
```

### 2.2 JWT Claims

```json
{
  "client_id": "https://verifier.example.com",
  "response_type": "vp_token",
  "response_mode": "direct_post",
  "response_uri": "https://verifier.example.com/wallet/direct_post/abc123",
  "nonce": "n-0S6_WzA2Mj",
  "state": "af0ifjsldkj",
  "aud": "https://wallet.example.com",
  "iat": 1711532834,
  "dcql_query": { /* DCQL object */ },
  "transaction_data": [ /* array */ ],
  "wallet_nonce": "wallet-nonce",  // Optional
  "client_metadata": {  // Client metadata
    "jwks": { /* keys */ },
    "vp_formats": { /* formats */ }
  }
}
```

---

## 3. PYTHON IMPLEMENTATION

### 3.1 Core Classes

```python
from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime
from returns.result import Result, Success, Failure

@dataclass(frozen=True)
class RequestObject:
    """Domain representation of JAR content"""
    verifier_id: VerifierId
    response_type: List[str]  # ["vp_token"]
    response_mode: str  # "direct_post" or "direct_post.jwt"
    response_uri: str
    nonce: str
    state: str
    aud: str
    issued_at: datetime
    dcql_query: Optional[DCQL]
    transaction_data: Optional[List[TransactionData]]
    wallet_nonce: Optional[str]
    scope: List[str]  # Usually empty for OpenID4VP

class CreateJar:
    """Port interface for JAR creation"""

    async def __call__(
        self,
        verifier_config: VerifierConfig,
        clock: Clock,
        presentation: PresentationRequested,
        wallet_nonce: Optional[str],
        encryption_requirement: EncryptionRequirement
    ) -> Result[str, Exception]:
        """Create (and optionally encrypt) JAR"""
        pass

@dataclass(frozen=True)
class EncryptionRequirement:
    """Encryption requirement for JAR or response"""
    @dataclass(frozen=True)
    class NotRequired:
        pass

    @dataclass(frozen=True)
    class Required:
        wallet_jar_encryption_key: dict  # JWK
        encryption_algorithm: str  # e.g., "ECDH-ES"
        encryption_method: str  # e.g., "A256GCM"

class CreateJarImpl:
    """Implementation using python-jose or joserfc"""

    def __init__(self):
        pass

    async def __call__(
        self,
        verifier_config: VerifierConfig,
        clock: Clock,
        presentation: PresentationRequested,
        wallet_nonce: Optional[str],
        encryption_requirement: EncryptionRequirement
    ) -> Result[str, Exception]:
        """
        Create JAR

        Steps:
        1. Build RequestObject from domain objects
        2. Sign JWT
        3. Optionally encrypt JWT
        """

        # Step 1: Build request object
        request_object = self._build_request_object(
            verifier_config,
            clock,
            presentation,
            wallet_nonce
        )

        # Step 2: Sign
        signed_result = self._sign(
            request_object,
            verifier_config.client_metadata,
            presentation.response_mode
        )
        if isinstance(signed_result, Failure):
            return signed_result

        signed_jwt = signed_result.unwrap()

        # Step 3: Optionally encrypt
        if isinstance(encryption_requirement, EncryptionRequirement.NotRequired):
            return Success(signed_jwt)
        else:
            return self._encrypt(encryption_requirement, signed_jwt)
```

### 3.2 Signing Implementation

```python
from jose import jwt
from jwcrypto import jwk
import json

class JarSigner:
    """Signs JARs using configured signing key"""

    def sign(
        self,
        request_object: RequestObject,
        client_metadata: ClientMetaData,
        response_mode: ResponseMode
    ) -> Result[str, Exception]:
        """
        Sign request object as JWT

        Steps:
        1. Build JWT header
        2. Build JWT claims
        3. Sign with private key
        """

        signing_config = request_object.verifier_id.jar_signing

        # Step 1: Build header
        header = {
            'alg': signing_config.algorithm,
            'typ': 'oauth-authz-req+jwt'
        }

        # Add kid or x5c based on verifier ID type
        match request_object.verifier_id:
            case VerifierIdPreRegistered():
                header['kid'] = signing_config.key.get('kid')
            case VerifierIdX509SanDns() | VerifierIdX509Hash():
                # Add x5c header
                header['x5c'] = self._get_x5c_chain(signing_config.certificate)

        # Step 2: Build claims
        claims = {
            'client_id': request_object.verifier_id.client_id,
            'response_type': 'vp_token',
            'response_mode': request_object.response_mode,
            'response_uri': request_object.response_uri,
            'nonce': request_object.nonce,
            'state': request_object.state,
            'aud': request_object.aud,
            'iat': int(request_object.issued_at.timestamp())
        }

        # Optional claims
        if request_object.scope:
            claims['scope'] = ' '.join(request_object.scope)

        if request_object.dcql_query:
            claims['dcql_query'] = request_object.dcql_query.dict()

        if request_object.transaction_data:
            claims['transaction_data'] = [td.dict() for td in request_object.transaction_data]

        if request_object.wallet_nonce:
            claims['wallet_nonce'] = request_object.wallet_nonce

        # Add client_metadata
        client_metadata_json = self._build_client_metadata_json(
            client_metadata,
            response_mode
        )
        if client_metadata_json:
            claims['client_metadata'] = client_metadata_json

        # Step 3: Sign
        try:
            token = jwt.encode(
                claims,
                signing_config.key,
                algorithm=signing_config.algorithm,
                headers=header
            )
            return Success(token)
        except Exception as e:
            return Failure(e)

    def _get_x5c_chain(self, certificate) -> List[str]:
        """Convert certificate to x5c format (base64 DER)"""
        from cryptography.hazmat.primitives import serialization
        import base64

        der_bytes = certificate.public_bytes(serialization.Encoding.DER)
        return [base64.b64encode(der_bytes).decode('utf-8')]

    def _build_client_metadata_json(
        self,
        client_metadata: ClientMetaData,
        response_mode: ResponseMode
    ) -> Dict[str, Any]:
        """Build client_metadata claim"""
        metadata = {}

        # If response mode is direct_post.jwt, include ephemeral key
        if isinstance(response_mode, ResponseModeDirectPostJwt):
            # Add ephemeral public key as JWK
            metadata['jwks'] = {
                'keys': [response_mode.ephemeral_response_encryption_key]
            }

            # Add encryption algorithms
            metadata['authorization_encrypted_response_enc'] = [
                client_metadata.response_encryption_option.encryption_method
            ]

        # Add vp_formats
        metadata['vp_formats'] = client_metadata.vp_formats_supported.dict()

        return metadata
```

### 3.3 Encryption Implementation

```python
from jwcrypto import jwe, jwk as jwcrypto_jwk

class JarEncrypter:
    """Encrypts signed JARs for wallet JAR encryption"""

    def encrypt(
        self,
        signed_jwt: str,
        encryption_key: dict,  # Wallet's encryption JWK
        algorithm: str,
        encryption_method: str
    ) -> Result[str, Exception]:
        """
        Encrypt signed JWT as JWE

        Format: JWE(signed JWT)
        """

        try:
            # Create JWK from dict
            wallet_key = jwcrypto_jwk.JWK(**encryption_key)

            # Create JWE
            protected_header = {
                'alg': algorithm,
                'enc': encryption_method,
                'cty': 'JWT'  # Content type is JWT
            }

            jwe_token = jwe.JWE(
                plaintext=signed_jwt.encode('utf-8'),
                protected=protected_header,
                recipient=wallet_key
            )

            return Success(jwe_token.serialize(compact=True))

        except Exception as e:
            return Failure(e)
```

---

## 4. CLIENT ID SCHEMES

### 4.1 Pre-Registered

```python
@dataclass(frozen=True)
class VerifierIdPreRegistered(VerifierId):
    """Traditional OAuth client_id"""
    original_client_id: str
    jar_signing: SigningConfig

    @property
    def client_id(self) -> str:
        return self.original_client_id  # No prefix
```

### 4.2 X.509 SAN DNS

```python
@dataclass(frozen=True)
class VerifierIdX509SanDns(VerifierId):
    """Client ID from DNS SAN in certificate"""
    original_client_id: str  # DNS name
    jar_signing: SigningConfig

    def __post_init__(self):
        # Validate DNS name is in certificate SAN
        sans = self._get_san_dns_names(self.jar_signing.certificate)
        if self.original_client_id not in sans:
            raise ValueError(f"DNS name {self.original_client_id} not in certificate SAN")

    @property
    def client_id(self) -> str:
        return f"x509_san_dns:{self.original_client_id}"

    def _get_san_dns_names(self, cert) -> List[str]:
        """Extract DNS names from Subject Alternative Name extension"""
        from cryptography import x509
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            return [
                name.value
                for name in san_ext.value
                if isinstance(name, x509.DNSName)
            ]
        except x509.ExtensionNotFound:
            return []
```

### 4.3 X.509 Hash

```python
import hashlib
import base64

@dataclass(frozen=True)
class VerifierIdX509Hash(VerifierId):
    """Client ID from certificate hash"""
    original_client_id: str  # base64url(sha256(cert DER))
    jar_signing: SigningConfig

    def __post_init__(self):
        # Validate hash matches certificate
        computed = self._compute_cert_hash(self.jar_signing.certificate)
        if computed != self.original_client_id:
            raise ValueError(f"Certificate hash mismatch")

    @property
    def client_id(self) -> str:
        return f"x509_hash:{self.original_client_id}"

    def _compute_cert_hash(self, cert) -> str:
        """Compute SHA-256 hash of DER-encoded certificate"""
        from cryptography.hazmat.primitives import serialization
        der_bytes = cert.public_bytes(serialization.Encoding.DER)
        hash_bytes = hashlib.sha256(der_bytes).digest()
        return base64.urlsafe_b64encode(hash_bytes).rstrip(b'=').decode('utf-8')
```

---

## 5. RESPONSE ENCRYPTION (DirectPostJwt)

### 5.1 Ephemeral Key Generation

```python
class GenerateEphemeralEncryptionKeyPair:
    """Generates ephemeral EC key pair for response encryption"""

    def __call__(self) -> Result[dict, Exception]:
        """Generate P-256 EC key pair"""
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.backends import default_backend

            # Generate P-256 key
            private_key = ec.generate_private_key(
                ec.SECP256R1(),
                default_backend()
            )

            # Convert to JWK format (with private key)
            jwk_dict = self._private_key_to_jwk(private_key)

            return Success(jwk_dict)
        except Exception as e:
            return Failure(e)

    def _private_key_to_jwk(self, private_key) -> dict:
        """Convert EC private key to JWK format"""
        from cryptography.hazmat.primitives import serialization
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        private_numbers = private_key.private_numbers()

        return {
            'kty': 'EC',
            'crv': 'P-256',
            'x': self._int_to_base64url(public_numbers.x, 32),
            'y': self._int_to_base64url(public_numbers.y, 32),
            'd': self._int_to_base64url(private_numbers.private_value, 32)
        }

    def _int_to_base64url(self, value: int, length: int) -> str:
        """Convert integer to base64url string"""
        import base64
        bytes_value = value.to_bytes(length, 'big')
        return base64.urlsafe_b64encode(bytes_value).rstrip(b'=').decode('utf-8')
```

### 5.2 Response Decryption

```python
class VerifyEncryptedResponse:
    """Verifies and decrypts JWE responses"""

    def __call__(
        self,
        ephemeral_response_encryption_key: dict,  # Private key from generation
        encrypted_response: str,  # JWE from wallet
        apv: Nonce  # Agreement PartyVInfo (nonce)
    ) -> Result[AuthorisationResponseTO, Exception]:
        """
        Decrypt JWE response

        The wallet sends response as JWE encrypted with ephemeral public key
        """

        try:
            # Load private key
            from jwcrypto import jwe, jwk
            private_key = jwk.JWK(**ephemeral_response_encryption_key)

            # Decrypt JWE
            jwe_token = jwe.JWE()
            jwe_token.deserialize(encrypted_response)
            jwe_token.decrypt(private_key)

            # Get plaintext (should be JWT with response)
            plaintext = jwe_token.payload.decode('utf-8')

            # Verify inner JWT
            from jose import jwt
            response_claims = jwt.decode(
                plaintext,
                options={'verify_signature': False}  # Signature verification TBD
            )

            # Parse to AuthorisationResponseTO
            return Success(AuthorisationResponseTO(
                state=response_claims.get('state'),
                vp_token=response_claims.get('vp_token'),
                error=response_claims.get('error'),
                error_description=response_claims.get('error_description')
            ))

        except Exception as e:
            return Failure(e)
```

---

## 6. TESTING

```python
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

class TestJarCreation:

    @pytest.fixture
    def signing_key(self):
        """Generate test RSA key"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        # Convert to JWK
        from jwcrypto import jwk
        key = jwk.JWK.generate(kty='RSA', size=2048)
        return json.loads(key.export())

    @pytest.mark.asyncio
    async def test_create_signed_jar(self, signing_key):
        """Test creating and signing JAR"""
        signer = JarSigner()

        request_object = RequestObject(
            verifier_id=VerifierIdPreRegistered(
                original_client_id="https://verifier.example.com",
                jar_signing=SigningConfig(
                    key=signing_key,
                    algorithm='RS256'
                )
            ),
            response_type=['vp_token'],
            response_mode='direct_post',
            response_uri='https://verifier.example.com/callback',
            nonce='test-nonce',
            state='test-state',
            aud='https://wallet.example.com',
            issued_at=datetime.now(),
            dcql_query=None,
            transaction_data=None,
            wallet_nonce=None,
            scope=[]
        )

        result = signer.sign(request_object, Mock(), Mock())
        assert isinstance(result, Success)

        # Verify JWT structure
        token = result.unwrap()
        from jose import jwt
        header = jwt.get_unverified_header(token)
        assert header['typ'] == 'oauth-authz-req+jwt'
        assert header['alg'] == 'RS256'

    def test_x509_san_dns_validation(self):
        """Test X.509 SAN DNS client ID validation"""
        # Create certificate with DNS SAN
        cert = create_test_cert_with_san_dns("verifier.example.com")

        # Should succeed
        verifier_id = VerifierIdX509SanDns(
            original_client_id="verifier.example.com",
            jar_signing=SigningConfig(
                key=...,
                algorithm='RS256',
                certificate=cert
            )
        )
        assert verifier_id.client_id == "x509_san_dns:verifier.example.com"

    def test_jar_encryption(self):
        """Test JAR encryption for wallet"""
        signed_jwt = "eyJ..."  # Signed JWT

        # Generate wallet encryption key
        wallet_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        wallet_jwk = private_key_to_jwk(wallet_key)

        # Encrypt
        encrypter = JarEncrypter()
        result = encrypter.encrypt(
            signed_jwt,
            wallet_jwk,
            'ECDH-ES',
            'A256GCM'
        )

        assert isinstance(result, Success)
        jwe = result.unwrap()
        assert jwe.count('.') == 4  # JWE compact format has 5 parts
```

---

## 7. DEPENDENCIES

```
python-jose[cryptography]==3.3.0
# OR
joserfc==0.9.0

jwcrypto==1.5.1
cryptography==42.0.0
returns==0.22.0
```

---

## 8. KEY IMPLEMENTATION NOTES

1. **Library Choice**: `joserfc` is more modern than `python-jose`
2. **X.509 Handling**: Use `cryptography` library for certificates
3. **Key Formats**: Support JWK (JSON Web Key) format throughout
4. **Error Handling**: Return `Result` types for all operations
5. **Testing**: Generate test certificates and keys for unit tests

---

**End of JAR Creation Design Document**
