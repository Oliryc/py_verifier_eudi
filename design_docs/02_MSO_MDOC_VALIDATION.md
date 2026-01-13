# MSO MDoc Validation Subsystem - Detailed Design

**Document Version**: 1.0
**Last Updated**: 2025-01-03
**Status**: Design Phase

---

## 1. OVERVIEW

### 1.1 Purpose
The MSO MDoc (Mobile Security Object - Mobile Document) Validation subsystem validates ISO/IEC 18013-5 compliant mobile driving license credentials and other mobile documents. This is the second of two credential formats supported by the EUDI Verifier Endpoint.

### 1.2 Scope
This subsystem handles:
- CBOR (Concise Binary Object Representation) decoding
- COSE (CBOR Object Signing and Encryption) signature verification
- Device authentication (MAC or signature)
- Issuer authentication via Mobile Security Object (MSO)
- Validity info verification (expiration, issuance dates)
- Digest verification for disclosed attributes
- Trust chain validation for issuer certificates
- Session transcript verification

### 1.3 Key Specifications
- **ISO/IEC 18013-5**: Personal identification - ISO-compliant driving license (mDL)
- **ISO/IEC 18013-7**: mDL test guidelines
- **RFC 9052**: COSE Structures
- **RFC 8949**: CBOR
- **OpenID4VP**: Integration with OpenID for Verifiable Presentations

---

## 2. ARCHITECTURE

### 2.1 Component Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                 MSO MDoc Validation Subsystem                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌────────────────────┐      ┌──────────────────────┐           │
│  │DeviceResponseValidator────▶│  DocumentValidator   │           │
│  │   (Main Entry)     │      │                      │           │
│  └─────────┬──────────┘      └──────────┬───────────┘           │
│            │                              │                       │
│            │                              ├──▶┌─────────────┐   │
│            │                              │   │ MsoValidator│   │
│            │                              │   │             │   │
│            │                              │   └─────────────┘   │
│            │                              │                       │
│            │                              ├──▶┌──────────────┐  │
│            │                              │   │IssuerAuthValidator│
│            │                              │   └──────────────┘  │
│            │                              │                       │
│            │                              └──▶┌──────────────┐  │
│            │                                  │DeviceAuthValidator│
│            │                                  └──────────────┘  │
│            │                                                      │
│            └─────────────────────▶┌──────────────────────┐     │
│                                    │ SessionTranscriptVerifier│     │
│                                    └──────────────────────┘     │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow

```
Input: VerifiablePresentation.Str (base64-encoded CBOR DeviceResponse)
   │
   ▼
1. Decode CBOR DeviceResponse
   ├─ documents: List of Document structures
   ├─ documentErrors: Optional errors
   └─ status: Response status code
   │
   ▼
2. Extract and validate each Document
   ├─ docType: Document type (e.g., "org.iso.18013.5.1.mDL")
   ├─ issuerSigned: Issuer-signed data
   │   ├─ nameSpaces: Map of namespace → IssuerSignedItem[]
   │   └─ issuerAuth: COSE_Sign1 structure
   └─ deviceSigned: Device-signed data
       ├─ nameSpaces: Map of namespace → DeviceSignedItem[]
       └─ deviceAuth: DeviceAuthentication structure
   │
   ▼
3. Validate IssuerAuth (COSE_Sign1)
   ├─ Extract Mobile Security Object (MSO) from payload
   ├─ Verify COSE signature with issuer certificate
   ├─ Validate issuer certificate chain
   └─ Check MSO validity info (dates)
   │
   ▼
4. Validate disclosed attributes
   ├─ For each issuerSignedItem:
   │   ├─ Compute digest of item
   │   ├─ Find matching digest in MSO
   │   └─ Verify digest matches
   └─ Ensure all required attributes disclosed
   │
   ▼
5. Validate DeviceAuthentication
   ├─ Extract DeviceKey from MSO
   ├─ Build SessionTranscript
   ├─ Compute DeviceAuthenticationBytes
   └─ Verify MAC or signature
   │
   ▼
6. Validate session binding
   ├─ Check mdocGeneratedNonce
   ├─ Check clientId
   └─ Verify verifier nonce binding
   │
   ▼
7. Check transaction data (if present)
   ├─ Hash disclosed attributes
   ├─ Compare with transaction_data
   └─ Ensure credential_ids match
   │
   ▼
Output: Result[VerifiablePresentation, ValidationError]
```

---

## 3. DATA STRUCTURES

### 3.1 CBOR Structures

```python
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Union
from enum import IntEnum
import cbor2

# ISO/IEC 18013-5 Section 8.3.2.1.2.2
@dataclass(frozen=True)
class DeviceResponse:
    """Top-level response from mobile document"""
    version: str  # "1.0"
    documents: Optional[List['Document']]
    document_errors: Optional[Dict[str, int]]  # docType → error code
    status: int  # 0 = OK

    @classmethod
    def from_cbor(cls, cbor_bytes: bytes) -> 'DeviceResponse':
        """Decode from CBOR bytes"""
        data = cbor2.loads(cbor_bytes)
        return cls(
            version=data['version'],
            documents=[Document.from_dict(d) for d in data.get('documents', [])],
            document_errors=data.get('documentErrors'),
            status=data['status']
        )

@dataclass(frozen=True)
class Document:
    """Single document within DeviceResponse"""
    doc_type: str  # e.g., "org.iso.18013.5.1.mDL"
    issuer_signed: 'IssuerSigned'
    device_signed: 'DeviceSigned'
    errors: Optional[Dict[str, int]]  # nameSpace → error code

@dataclass(frozen=True)
class IssuerSigned:
    """Issuer-signed portion of document"""
    name_spaces: Dict[str, List['IssuerSignedItem']]  # nameSpace → items
    issuer_auth: bytes  # COSE_Sign1 structure (tagged CBOR)

@dataclass(frozen=True)
class IssuerSignedItem:
    """Single attribute signed by issuer"""
    digest_id: int  # ID in MSO valueDigests
    random: bytes  # Random salt
    element_identifier: str  # Attribute name
    element_value: Any  # Attribute value (CBOR type)

    def compute_digest(self, algorithm: str = "SHA-256") -> bytes:
        """Compute digest of this item for verification"""
        import hashlib

        # Serialize as #6.24(bstr .cbor IssuerSignedItem)
        item_cbor = cbor2.dumps(self.__dict__)
        tagged = cbor2.CBORTag(24, item_cbor)
        tagged_cbor = cbor2.dumps(tagged)

        # Hash
        if algorithm == "SHA-256":
            return hashlib.sha256(tagged_cbor).digest()
        elif algorithm == "SHA-384":
            return hashlib.sha384(tagged_cbor).digest()
        elif algorithm == "SHA-512":
            return hashlib.sha512(tagged_cbor).digest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

@dataclass(frozen=True)
class DeviceSigned:
    """Device-signed portion of document"""
    name_spaces: bytes  # Encoded DeviceNameSpaces (usually empty)
    device_auth: 'DeviceAuth'

@dataclass(frozen=True)
class DeviceAuth:
    """Device authentication structure"""
    device_signature: Optional[bytes]  # COSE_Sign1 if signature
    device_mac: Optional[bytes]  # COSE_Mac0 if MAC

    def authentication_type(self) -> str:
        if self.device_signature:
            return "signature"
        elif self.device_mac:
            return "mac"
        else:
            raise ValueError("No device authentication present")
```

### 3.2 Mobile Security Object (MSO)

```python
from datetime import datetime

@dataclass(frozen=True)
class MobileSecurityObject:
    """Mobile Security Object (MSO) - ISO 18013-5 Section 9.1.2.4"""
    version: str  # "1.0"
    digest_algorithm: str  # e.g., "SHA-256"
    value_digests: Dict[str, Dict[int, bytes]]  # nameSpace → {digestID → digest}
    device_key_info: 'DeviceKeyInfo'
    doc_type: str
    validity_info: 'ValidityInfo'

    @classmethod
    def from_cbor(cls, cbor_bytes: bytes) -> 'MobileSecurityObject':
        """Decode MSO from CBOR payload of COSE_Sign1"""
        data = cbor2.loads(cbor_bytes)
        return cls(
            version=data['version'],
            digest_algorithm=data['digestAlgorithm'],
            value_digests=data['valueDigests'],
            device_key_info=DeviceKeyInfo.from_dict(data['deviceKeyInfo']),
            doc_type=data['docType'],
            validity_info=ValidityInfo.from_dict(data['validityInfo'])
        )

@dataclass(frozen=True)
class DeviceKeyInfo:
    """Device public key information"""
    device_key: Dict[str, Any]  # COSE_Key structure

    def get_public_key(self):
        """Extract public key for device authentication verification"""
        from cose.keys import CoseKey
        return CoseKey.decode(cbor2.dumps(self.device_key))

@dataclass(frozen=True)
class ValidityInfo:
    """Validity information for the MSO"""
    signed: datetime  # When MSO was signed
    valid_from: datetime  # Start of validity period
    valid_until: datetime  # End of validity period
    expected_update: Optional[datetime]  # When update is expected

    def is_valid_at(self, timestamp: datetime) -> bool:
        """Check if MSO is valid at given timestamp"""
        return self.valid_from <= timestamp <= self.valid_until
```

### 3.3 Session Transcript

```python
@dataclass(frozen=True)
class SessionTranscript:
    """Session transcript for device authentication"""
    device_engagement_bytes: Optional[bytes]
    e_reader_key_bytes: Optional[bytes]
    handover: bytes  # Often contains nonce and other session data

    def encode(self) -> bytes:
        """Encode as CBOR array"""
        return cbor2.dumps([
            self.device_engagement_bytes,
            self.e_reader_key_bytes,
            cbor2.loads(self.handover)  # Must be decoded then re-encoded
        ])

@dataclass(frozen=True)
class Handover:
    """Handover structure containing session binding"""
    # For OpenID4VP integration
    nonce: str  # Verifier nonce
    mdoc_generated_nonce: str  # Device-generated nonce
    client_id: str  # Verifier client ID
    response_uri: str  # Verifier response URI

    def encode(self) -> bytes:
        """Encode as CBOR"""
        return cbor2.dumps({
            "nonce": self.nonce,
            "mdocGeneratedNonce": self.mdoc_generated_nonce,
            "clientId": self.client_id,
            "responseUri": self.response_uri
        })
```

---

## 4. VALIDATION ALGORITHM

### 4.1 Main Validation Flow

```python
from returns.result import Result, Success, Failure
from pycose.messages import Sign1Message, Mac0Message
from pycose.keys import CoseKey

class DeviceResponseValidator:
    """Main validator for MSO MDoc credentials"""

    def __init__(
        self,
        document_validator: 'DocumentValidator',
        session_transcript_builder: 'SessionTranscriptBuilder',
        clock: Clock
    ):
        self.document_validator = document_validator
        self.session_transcript_builder = session_transcript_builder
        self.clock = clock

    async def validate(
        self,
        vp: VerifiablePresentation.Str,
        transaction_id: TransactionId,
        nonce: Nonce,
        transaction_data: Optional[List[TransactionData]],
        issuer_chain: Optional[List[X509Certificate]]
    ) -> Result[VerifiablePresentation, ValidationError]:
        """
        Main validation entry point

        Validation steps:
        1. Decode base64 and CBOR DeviceResponse
        2. Validate DeviceResponse structure
        3. Build SessionTranscript
        4. Validate each Document
        5. Validate transaction data (if present)
        """

        # Step 1: Decode
        try:
            cbor_bytes = base64.b64decode(vp.value)
            device_response = DeviceResponse.from_cbor(cbor_bytes)
        except Exception as e:
            return Failure(ValidationError.InvalidFormat(str(e)))

        # Step 2: Validate DeviceResponse structure
        if device_response.status != 0:
            return Failure(ValidationError.DeviceResponseError(device_response.status))

        if not device_response.documents or len(device_response.documents) == 0:
            return Failure(ValidationError.NoDocuments)

        # Step 3: Build SessionTranscript
        session_transcript_result = self.session_transcript_builder.build(
            nonce,
            transaction_id
        )
        if isinstance(session_transcript_result, Failure):
            return session_transcript_result
        session_transcript = session_transcript_result.unwrap()

        # Step 4: Validate each document
        validated_documents = []
        for document in device_response.documents:
            doc_result = await self.document_validator.validate(
                document,
                session_transcript,
                issuer_chain
            )
            if isinstance(doc_result, Failure):
                return doc_result
            validated_documents.append(doc_result.unwrap())

        # Step 5: Validate transaction data
        if transaction_data:
            tx_result = self._validate_transaction_data(
                validated_documents,
                transaction_data
            )
            if isinstance(tx_result, Failure):
                return tx_result

        return Success(vp)
```

### 4.2 Document Validation

```python
class DocumentValidator:
    """Validates individual Document structures"""

    def __init__(
        self,
        mso_validator: 'MsoValidator',
        issuer_auth_validator: 'IssuerAuthValidator',
        device_auth_validator: 'DeviceAuthValidator',
        clock: Clock
    ):
        self.mso_validator = mso_validator
        self.issuer_auth_validator = issuer_auth_validator
        self.device_auth_validator = device_auth_validator
        self.clock = clock

    async def validate(
        self,
        document: Document,
        session_transcript: SessionTranscript,
        issuer_chain: Optional[List[X509Certificate]]
    ) -> Result[Dict[str, Any], ValidationError]:
        """
        Validate single document

        Steps:
        1. Verify IssuerAuth COSE signature
        2. Extract and validate MSO
        3. Verify disclosed attribute digests
        4. Verify DeviceAuth
        """

        # Step 1 & 2: Verify IssuerAuth and extract MSO
        issuer_auth_result = await self.issuer_auth_validator.validate(
            document.issuer_signed.issuer_auth,
            issuer_chain
        )
        if isinstance(issuer_auth_result, Failure):
            return issuer_auth_result
        mso = issuer_auth_result.unwrap()

        # Validate MSO itself
        mso_validation_result = self.mso_validator.validate(
            mso,
            document.doc_type,
            self.clock.now()
        )
        if isinstance(mso_validation_result, Failure):
            return mso_validation_result

        # Step 3: Verify disclosed attributes
        disclosed_attrs_result = self._verify_disclosed_attributes(
            document.issuer_signed.name_spaces,
            mso
        )
        if isinstance(disclosed_attrs_result, Failure):
            return disclosed_attrs_result
        disclosed_attributes = disclosed_attrs_result.unwrap()

        # Step 4: Verify DeviceAuth
        device_auth_result = await self.device_auth_validator.validate(
            document.device_signed.device_auth,
            mso.device_key_info.get_public_key(),
            session_transcript,
            document
        )
        if isinstance(device_auth_result, Failure):
            return device_auth_result

        return Success(disclosed_attributes)

    def _verify_disclosed_attributes(
        self,
        name_spaces: Dict[str, List[IssuerSignedItem]],
        mso: MobileSecurityObject
    ) -> Result[Dict[str, Dict[str, Any]], ValidationError]:
        """Verify digests of all disclosed attributes"""

        disclosed_attributes = {}

        for namespace, items in name_spaces.items():
            if namespace not in mso.value_digests:
                return Failure(ValidationError.UnknownNamespace(namespace))

            namespace_attrs = {}
            for item in items:
                # Compute digest of item
                computed_digest = item.compute_digest(mso.digest_algorithm)

                # Find matching digest in MSO
                expected_digest = mso.value_digests[namespace].get(item.digest_id)
                if not expected_digest:
                    return Failure(ValidationError.DigestIdNotFound(
                        namespace, item.digest_id
                    ))

                # Verify match
                if computed_digest != expected_digest:
                    return Failure(ValidationError.DigestMismatch(
                        namespace, item.element_identifier
                    ))

                namespace_attrs[item.element_identifier] = item.element_value

            disclosed_attributes[namespace] = namespace_attrs

        return Success(disclosed_attributes)
```

### 4.3 IssuerAuth Validation

```python
class IssuerAuthValidator:
    """Validates IssuerAuth COSE_Sign1 structure"""

    def __init__(self, x5c_validator: X5CValidator):
        self.x5c_validator = x5c_validator

    async def validate(
        self,
        issuer_auth_bytes: bytes,
        trusted_chain: Optional[List[X509Certificate]]
    ) -> Result[MobileSecurityObject, ValidationError]:
        """
        Validate IssuerAuth and extract MSO

        Steps:
        1. Decode COSE_Sign1 structure
        2. Extract certificate chain from x5chain header
        3. Validate certificate chain
        4. Verify COSE signature
        5. Extract and parse MSO from payload
        """

        try:
            # Decode COSE_Sign1
            sign1_msg = Sign1Message.decode(issuer_auth_bytes)
        except Exception as e:
            return Failure(ValidationError.InvalidCoseStructure(str(e)))

        # Extract certificate chain
        x5chain = sign1_msg.phdr.get(33)  # Label 33 = x5chain
        if not x5chain:
            return Failure(ValidationError.MissingX5Chain)

        try:
            # Parse certificates
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            cert_chain = [
                x509.load_der_x509_certificate(cert_bytes, default_backend())
                for cert_bytes in x5chain
            ]
        except Exception as e:
            return Failure(ValidationError.InvalidCertificate(str(e)))

        # Validate chain
        chain_result = await self.x5c_validator.validate(
            cert_chain,
            trusted_chain
        )
        if isinstance(chain_result, Failure):
            return chain_result

        # Verify signature using leaf certificate
        try:
            leaf_cert = cert_chain[0]
            public_key = leaf_cert.public_key()

            # Convert to COSE key
            cose_key = self._public_key_to_cose_key(public_key)
            sign1_msg.key = cose_key

            # Verify
            if not sign1_msg.verify_signature():
                return Failure(ValidationError.InvalidIssuerSignature)
        except Exception as e:
            return Failure(ValidationError.SignatureVerificationFailed(str(e)))

        # Extract and parse MSO
        try:
            mso = MobileSecurityObject.from_cbor(sign1_msg.payload)
        except Exception as e:
            return Failure(ValidationError.InvalidMso(str(e)))

        return Success(mso)

    def _public_key_to_cose_key(self, public_key) -> CoseKey:
        """Convert cryptography public key to COSE key"""
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from pycose.keys import EC2Key, RSAKey

        if isinstance(public_key, ec.EllipticCurvePublicKey):
            # EC key
            public_numbers = public_key.public_numbers()
            # Convert to COSE EC2 key
            # ... (implementation details)
            return EC2Key(...)
        elif isinstance(public_key, rsa.RSAPublicKey):
            # RSA key
            public_numbers = public_key.public_numbers()
            return RSAKey(...)
        else:
            raise ValueError(f"Unsupported key type: {type(public_key)}")
```

### 4.4 DeviceAuth Validation

```python
class DeviceAuthValidator:
    """Validates DeviceAuth (MAC or signature)"""

    async def validate(
        self,
        device_auth: DeviceAuth,
        device_key: CoseKey,
        session_transcript: SessionTranscript,
        document: Document
    ) -> Result[None, ValidationError]:
        """
        Validate device authentication

        Steps:
        1. Build DeviceAuthenticationBytes
        2. Verify MAC or signature using device key
        """

        # Build DeviceAuthenticationBytes
        device_auth_bytes = self._build_device_authentication_bytes(
            session_transcript,
            document.doc_type,
            document.device_signed.name_spaces
        )

        # Verify based on authentication type
        try:
            if device_auth.authentication_type() == "mac":
                return self._verify_mac(
                    device_auth.device_mac,
                    device_auth_bytes,
                    device_key
                )
            else:  # signature
                return self._verify_signature(
                    device_auth.device_signature,
                    device_auth_bytes,
                    device_key
                )
        except Exception as e:
            return Failure(ValidationError.DeviceAuthFailed(str(e)))

    def _build_device_authentication_bytes(
        self,
        session_transcript: SessionTranscript,
        doc_type: str,
        device_name_spaces: bytes
    ) -> bytes:
        """
        Build DeviceAuthenticationBytes structure

        DeviceAuthenticationBytes = [
            "DeviceAuthentication",
            SessionTranscript,
            DocType,
            DeviceNameSpaces
        ]
        """
        return cbor2.dumps([
            "DeviceAuthentication",
            cbor2.loads(session_transcript.encode()),
            doc_type,
            cbor2.loads(device_name_spaces) if device_name_spaces else {}
        ])

    def _verify_mac(
        self,
        mac_bytes: bytes,
        data_to_verify: bytes,
        device_key: CoseKey
    ) -> Result[None, ValidationError]:
        """Verify COSE_Mac0"""
        try:
            mac0_msg = Mac0Message.decode(mac_bytes)
            mac0_msg.key = device_key

            # Set external_aad to DeviceAuthenticationBytes
            mac0_msg.external_aad = data_to_verify

            if not mac0_msg.verify_tag():
                return Failure(ValidationError.InvalidDeviceMac)

            return Success(None)
        except Exception as e:
            return Failure(ValidationError.MacVerificationFailed(str(e)))

    def _verify_signature(
        self,
        signature_bytes: bytes,
        data_to_verify: bytes,
        device_key: CoseKey
    ) -> Result[None, ValidationError]:
        """Verify COSE_Sign1"""
        try:
            sign1_msg = Sign1Message.decode(signature_bytes)
            sign1_msg.key = device_key

            # Set external_aad to DeviceAuthenticationBytes
            sign1_msg.external_aad = data_to_verify

            if not sign1_msg.verify_signature():
                return Failure(ValidationError.InvalidDeviceSignature)

            return Success(None)
        except Exception as e:
            return Failure(ValidationError.SignatureVerificationFailed(str(e)))
```

### 4.5 MSO Validation

```python
class MsoValidator:
    """Validates Mobile Security Object"""

    def validate(
        self,
        mso: MobileSecurityObject,
        expected_doc_type: str,
        current_time: datetime
    ) -> Result[None, ValidationError]:
        """
        Validate MSO

        Checks:
        1. Version
        2. DocType matches
        3. Validity period
        4. Digest algorithm is supported
        """

        # Check version
        if mso.version != "1.0":
            return Failure(ValidationError.UnsupportedMsoVersion(mso.version))

        # Check docType
        if mso.doc_type != expected_doc_type:
            return Failure(ValidationError.DocTypeMismatch(
                expected=expected_doc_type,
                actual=mso.doc_type
            ))

        # Check validity
        if not mso.validity_info.is_valid_at(current_time):
            if current_time < mso.validity_info.valid_from:
                return Failure(ValidationError.NotYetValid)
            else:
                return Failure(ValidationError.Expired)

        # Check digest algorithm
        if mso.digest_algorithm not in ["SHA-256", "SHA-384", "SHA-512"]:
            return Failure(ValidationError.UnsupportedDigestAlgorithm(
                mso.digest_algorithm
            ))

        return Success(None)
```

---

## 5. SESSION TRANSCRIPT BUILDING

### 5.1 SessionTranscript for OpenID4VP

```python
class SessionTranscriptBuilder:
    """Builds SessionTranscript for OpenID4VP integration"""

    def __init__(self, verifier_config: VerifierConfig):
        self.verifier_config = verifier_config

    def build(
        self,
        nonce: Nonce,
        transaction_id: TransactionId
    ) -> Result[SessionTranscript, ValidationError]:
        """
        Build SessionTranscript for OpenID4VP

        For OpenID4VP, the SessionTranscript is:
        [
            null,  # DeviceEngagement (not used in OpenID4VP)
            null,  # EReaderKey (not used in OpenID4VP)
            Handover
        ]

        Where Handover contains the OpenID4VP session binding
        """

        try:
            handover = Handover(
                nonce=nonce.value,
                mdoc_generated_nonce="",  # Will be filled by device
                client_id=self.verifier_config.verifier_id.client_id,
                response_uri=self.verifier_config.response_uri_builder(
                    RequestId(transaction_id.value)
                ).toString()
            )

            session_transcript = SessionTranscript(
                device_engagement_bytes=None,
                e_reader_key_bytes=None,
                handover=handover.encode()
            )

            return Success(session_transcript)
        except Exception as e:
            return Failure(ValidationError.SessionTranscriptBuildFailed(str(e)))
```

---

## 6. ERROR HANDLING

### 6.1 Error Types

```python
from enum import Enum

class MdocValidationErrorType(Enum):
    # Format errors
    INVALID_FORMAT = "invalid_format"
    INVALID_CBOR = "invalid_cbor"
    INVALID_COSE_STRUCTURE = "invalid_cose_structure"

    # Structure errors
    NO_DOCUMENTS = "no_documents"
    DEVICE_RESPONSE_ERROR = "device_response_error"
    UNKNOWN_NAMESPACE = "unknown_namespace"

    # Issuer authentication errors
    MISSING_X5_CHAIN = "missing_x5_chain"
    INVALID_CERTIFICATE = "invalid_certificate"
    INVALID_ISSUER_SIGNATURE = "invalid_issuer_signature"

    # MSO errors
    INVALID_MSO = "invalid_mso"
    UNSUPPORTED_MSO_VERSION = "unsupported_mso_version"
    DOCTYPE_MISMATCH = "doctype_mismatch"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"

    # Digest errors
    DIGEST_ID_NOT_FOUND = "digest_id_not_found"
    DIGEST_MISMATCH = "digest_mismatch"

    # Device authentication errors
    DEVICE_AUTH_FAILED = "device_auth_failed"
    INVALID_DEVICE_MAC = "invalid_device_mac"
    INVALID_DEVICE_SIGNATURE = "invalid_device_signature"

    # Session errors
    SESSION_TRANSCRIPT_BUILD_FAILED = "session_transcript_build_failed"
```

---

## 7. TESTING STRATEGY

### 7.1 Unit Tests

```python
import pytest
from unittest.mock import Mock

class TestDeviceResponseValidator:

    @pytest.fixture
    def validator(self):
        document_validator = Mock()
        session_transcript_builder = Mock()
        clock = Mock()
        return DeviceResponseValidator(
            document_validator,
            session_transcript_builder,
            clock
        )

    @pytest.mark.asyncio
    async def test_valid_mdoc(self, validator):
        """Test validation of valid mDL"""
        # Load test vector from ISO 18013-5 or 18013-7
        mdoc_bytes = load_test_mdoc("valid_mdl_001.cbor")
        vp = VerifiablePresentation.Str(
            base64.b64encode(mdoc_bytes).decode(),
            Format.MsoMdoc
        )

        result = await validator.validate(
            vp,
            TransactionId("tx-123"),
            Nonce("test-nonce"),
            None,
            None
        )

        assert isinstance(result, Success)

    def test_digest_verification(self):
        """Test digest computation and verification"""
        item = IssuerSignedItem(
            digest_id=0,
            random=b"random_salt",
            element_identifier="family_name",
            element_value="Doe"
        )

        digest = item.compute_digest("SHA-256")
        assert len(digest) == 32  # SHA-256 is 256 bits = 32 bytes

    @pytest.mark.asyncio
    async def test_expired_mdoc(self, validator):
        """Test validation fails for expired document"""
        mdoc_bytes = load_test_mdoc("expired_mdl_001.cbor")
        vp = VerifiablePresentation.Str(
            base64.b64encode(mdoc_bytes).decode(),
            Format.MsoMdoc
        )

        result = await validator.validate(vp, ...)

        assert isinstance(result, Failure)
        assert result.failure().type == MdocValidationErrorType.EXPIRED
```

---

## 8. IMPLEMENTATION NOTES

### 8.1 Python Library Challenges

**Problem**: No mature MSO MDoc library in Python (unlike Kotlin's walt.id mdoc)

**Solution**: Build custom implementation using:
- `cbor2` for CBOR encoding/decoding
- `pycose` for COSE operations
- `cryptography` for X.509 and crypto operations

### 8.2 CBOR Tagged Types

CBOR uses tags for type information. Key tags for mDocs:
- Tag 24: Encoded CBOR data item
- Tag 18: COSE_Sign1
- Tag 17: COSE_Mac0

```python
import cbor2

# Decode tagged CBOR
data = cbor2.loads(cbor_bytes)
if isinstance(data, cbor2.CBORTag):
    if data.tag == 24:
        # Encoded CBOR
        inner = cbor2.loads(data.value)
```

### 8.3 COSE Key Handling

```python
from pycose.keys import CoseKey, EC2Key, RSAKey, OKPKey
from pycose.algorithms import Es256, Es384, Es512

# Create COSE key from CBOR
cose_key_dict = {
    1: 2,  # kty: EC2
    -1: 1,  # crv: P-256
    -2: x_bytes,  # x coordinate
    -3: y_bytes,  # y coordinate
}
cose_key = CoseKey.decode(cbor2.dumps(cose_key_dict))
```

### 8.4 Performance Considerations

1. **CBOR Parsing**: Fast in Python with cbor2
2. **Crypto Operations**: Use cryptography library (backed by OpenSSL)
3. **Certificate Validation**: Can be slow, consider caching
4. **Digest Computation**: Multiple SHA operations per attribute

### 8.5 Dependencies

```
cbor2==5.6.0
pycose==1.1.0
cryptography==42.0.0
returns==0.22.0
```

---

## 9. ISO 18013-5 CONFORMANCE

### 9.1 Test Vectors

Use test vectors from:
- ISO/IEC 18013-7: Test guidelines
- AAMVA mDL Implementation Guidelines
- Open-source test suites

### 9.2 Conformance Checklist

- [ ] CBOR parsing
- [ ] COSE_Sign1 verification (IssuerAuth)
- [ ] MSO structure validation
- [ ] Digest verification for all namespaces
- [ ] COSE_Mac0 verification (DeviceAuth MAC)
- [ ] COSE_Sign1 verification (DeviceAuth signature)
- [ ] SessionTranscript building
- [ ] Certificate chain validation
- [ ] Validity period checking
- [ ] Age verification (if implementing age_over_NN)

---

## 10. REFERENCES

1. **ISO/IEC 18013-5:2021**: Personal identification - ISO-compliant driving licence - Part 5: Mobile driving licence (mDL) application
2. **ISO/IEC 18013-7**: mDL test guidelines (draft)
3. **RFC 9052**: CBOR Object Signing and Encryption (COSE): Structures and Process
4. **RFC 8949**: Concise Binary Object Representation (CBOR)
5. **OpenID4VP**: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
6. **PyCA Cryptography**: https://cryptography.io/
7. **pycose Library**: https://github.com/TimothyClaeys/pycose

---

**End of MSO MDoc Validation Design Document**
