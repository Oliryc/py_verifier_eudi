# SD-JWT VC Validation Subsystem - Detailed Design

**Document Version**: 1.0
**Last Updated**: 2025-01-03
**Status**: Design Phase

---

## 1. OVERVIEW

### 1.1 Purpose
The SD-JWT VC Validation subsystem is responsible for validating Selective Disclosure JSON Web Token Verifiable Credentials according to the IETF SD-JWT VC specification. This is one of two credential formats supported by the EUDI Verifier Endpoint (the other being MSO MDoc).

### 1.2 Scope
This subsystem handles:
- SD-JWT signature verification
- Holder binding validation (Key Binding JWT - KB-JWT)
- Selective disclosure verification
- Type metadata validation
- Status list token validation
- JSON Schema validation of disclosed claims
- Trust chain verification against configured trust sources

### 1.3 Key Specifications
- **IETF SD-JWT**: draft-ietf-oauth-selective-disclosure-jwt
- **SD-JWT VC**: draft-ietf-oauth-sd-jwt-vc
- **Status List**: draft-ietf-oauth-status-list
- **OpenID4VP**: OpenID for Verifiable Presentations 1.0

---

## 2. ARCHITECTURE

### 2.1 Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                  SD-JWT VC Validation Subsystem                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────────┐      ┌───────────────────┐                │
│  │  SdJwtVcValidator│─────▶│ StatusListValidator│               │
│  │   (Main Entry)   │      │                    │               │
│  └────────┬─────────┘      └───────────────────┘                │
│           │                                                       │
│           ├──────▶┌─────────────────────┐                       │
│           │       │ TypeMetadataLookup  │                       │
│           │       │                     │                       │
│           │       └─────────────────────┘                       │
│           │                                                       │
│           ├──────▶┌─────────────────────┐                       │
│           │       │  JsonSchemaValidator│                       │
│           │       │                     │                       │
│           │       └─────────────────────┘                       │
│           │                                                       │
│           └──────▶┌─────────────────────┐                       │
│                   │   X5CValidator      │                       │
│                   │ (Trust Verification)│                       │
│                   └─────────────────────┘                       │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow

```
Input: VerifiablePresentation.Str (SD-JWT VC string)
   │
   ▼
1. Parse SD-JWT structure
   ├─ Issuer-signed JWT (JWT + disclosures)
   └─ Optional Key Binding JWT
   │
   ▼
2. Verify Issuer JWT signature
   ├─ Extract x5c header or jwk
   ├─ Validate certificate chain (if x5c)
   └─ Verify JWT signature
   │
   ▼
3. Validate claims
   ├─ Check 'vct' (VC type)
   ├─ Check 'iat', 'exp', 'nbf'
   └─ Validate 'iss' (issuer)
   │
   ▼
4. Fetch and validate type metadata
   ├─ Lookup from vct URL
   ├─ Validate against schema
   └─ Cache for reuse
   │
   ▼
5. Verify selective disclosures
   ├─ Verify disclosure hashes
   ├─ Reconstruct disclosed claims
   └─ Validate against JSON Schema
   │
   ▼
6. Validate Key Binding (if present)
   ├─ Check nonce matches
   ├─ Check aud matches verifier
   ├─ Check iat timestamp
   └─ Verify KB-JWT signature with cnf key
   │
   ▼
7. Check credential status
   ├─ Extract status claim
   ├─ Fetch status list token
   ├─ Verify status list JWT
   └─ Check bit at index
   │
   ▼
8. Validate transaction data (if present)
   ├─ Hash disclosed claims
   ├─ Compare with transaction_data
   └─ Ensure all credential_ids present
   │
   ▼
Output: Result[VerifiablePresentation, ValidationError]
```

---

## 3. DATA STRUCTURES

### 3.1 Core Classes

```python
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from datetime import datetime
from returns.result import Result

@dataclass(frozen=True)
class SdJwtVc:
    """Parsed SD-JWT VC structure"""
    issuer_jwt: str  # The main JWT (with _sd claims)
    disclosures: List[str]  # Base64URL-encoded disclosures
    key_binding_jwt: Optional[str]  # Optional KB-JWT

    @classmethod
    def parse(cls, sd_jwt_string: str) -> Result['SdJwtVc', ParseError]:
        """Parse SD-JWT VC from concatenated format: <jwt>~<disclosure>~...~<kb_jwt>"""
        ...

@dataclass(frozen=True)
class IssuerJwtClaims:
    """Claims from the Issuer-signed JWT"""
    iss: str  # Issuer identifier
    iat: datetime  # Issued at
    exp: Optional[datetime]  # Expiration
    nbf: Optional[datetime]  # Not before
    vct: str  # VC type identifier (URL)
    status: Optional[Dict[str, Any]]  # Status list reference
    cnf: Optional[Dict[str, Any]]  # Confirmation method (holder public key)
    _sd: Optional[List[str]]  # Selective disclosure hashes
    _sd_alg: str = "sha-256"  # SD algorithm (default sha-256)
    # Additional claims as needed

@dataclass(frozen=True)
class KeyBindingJwtClaims:
    """Claims from the Key Binding JWT"""
    aud: str  # Verifier identifier
    iat: datetime  # Issued at
    nonce: str  # Nonce from verifier
    sd_hash: str  # Hash of issuer JWT + disclosures

@dataclass(frozen=True)
class Disclosure:
    """A single selective disclosure"""
    salt: str
    claim_name: str
    claim_value: Any

    @classmethod
    def from_base64(cls, encoded: str) -> Result['Disclosure', ParseError]:
        """Decode from base64url-encoded JSON array"""
        ...

    def hash(self, algorithm: str = "sha-256") -> str:
        """Compute disclosure hash"""
        ...

@dataclass(frozen=True)
class TypeMetadata:
    """VC Type Metadata from vct URL"""
    vct: str  # VC type identifier
    name: str  # Human-readable name
    description: Optional[str]
    claims: Optional[Dict[str, Any]]  # JSON Schema for claims
    schema: Optional[Dict[str, Any]]  # Complete JSON Schema
    extends: Optional[str]  # Parent type

@dataclass(frozen=True)
class StatusListToken:
    """Status List JWT"""
    iss: str  # Status list issuer
    sub: str  # Status list subject
    iat: datetime
    exp: Optional[datetime]
    status_list: StatusList  # The actual bit string

@dataclass(frozen=True)
class StatusList:
    """Status list bit array"""
    bits: int  # 1, 2, 4, or 8 bits per entry
    lst: str  # Base64-encoded compressed bit string

    def check_status(self, index: int) -> int:
        """Check status at given index"""
        ...
```

### 3.2 Configuration

```python
from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, Dict

class SdJwtVcValidationConfig(BaseModel):
    """Configuration for SD-JWT VC validation"""

    # Algorithm support
    allowed_sd_algorithms: List[str] = Field(
        default=["sha-256", "sha-384", "sha-512"],
        description="Allowed selective disclosure hash algorithms"
    )

    allowed_jwt_algorithms: List[str] = Field(
        default=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
        description="Allowed JWT signature algorithms"
    )

    # Key binding requirements
    require_key_binding: bool = Field(
        default=True,
        description="Whether to require key binding JWT"
    )

    key_binding_max_age_seconds: int = Field(
        default=300,
        description="Maximum age of key binding JWT in seconds"
    )

    # Type metadata
    type_metadata_cache_ttl_seconds: int = Field(
        default=3600,
        description="TTL for type metadata cache"
    )

    type_metadata_timeout_seconds: int = Field(
        default=10,
        description="Timeout for fetching type metadata"
    )

    # Status list
    check_status: bool = Field(
        default=True,
        description="Whether to check credential status"
    )

    status_list_cache_ttl_seconds: int = Field(
        default=300,
        description="TTL for status list cache"
    )

    # Trust
    trust_sources: Dict[str, Any] = Field(
        default_factory=dict,
        description="Trust source configuration per issuer"
    )

    # Validation
    validate_json_schema: bool = Field(
        default=True,
        description="Whether to validate disclosed claims against JSON Schema"
    )

    max_disclosure_count: int = Field(
        default=100,
        description="Maximum number of disclosures allowed"
    )
```

---

## 4. VALIDATION ALGORITHM

### 4.1 Main Validation Flow

```python
from returns.result import Result, Success, Failure
from returns.pipeline import flow

class SdJwtVcValidator:
    """Main validator for SD-JWT VC credentials"""

    def __init__(
        self,
        config: SdJwtVcValidationConfig,
        x5c_validator: X5CValidator,
        type_metadata_lookup: TypeMetadataLookup,
        json_schema_validator: JsonSchemaValidator,
        status_list_validator: StatusListTokenValidator,
        clock: Clock
    ):
        self.config = config
        self.x5c_validator = x5c_validator
        self.type_metadata_lookup = type_metadata_lookup
        self.json_schema_validator = json_schema_validator
        self.status_list_validator = status_list_validator
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
        1. Parse SD-JWT structure
        2. Verify issuer JWT signature and trust
        3. Validate basic claims (iat, exp, nbf)
        4. Fetch and validate type metadata
        5. Verify selective disclosures
        6. Validate disclosed claims against JSON Schema
        7. Validate key binding JWT (if present)
        8. Check credential status
        9. Validate transaction data (if present)
        """

        # Step 1: Parse
        sd_jwt_result = SdJwtVc.parse(vp.value)
        if isinstance(sd_jwt_result, Failure):
            return sd_jwt_result
        sd_jwt = sd_jwt_result.unwrap()

        # Step 2: Verify issuer JWT
        issuer_jwt_result = await self._verify_issuer_jwt(sd_jwt, issuer_chain)
        if isinstance(issuer_jwt_result, Failure):
            return issuer_jwt_result
        issuer_claims = issuer_jwt_result.unwrap()

        # Step 3: Validate temporal claims
        temporal_result = self._validate_temporal_claims(issuer_claims)
        if isinstance(temporal_result, Failure):
            return temporal_result

        # Step 4: Fetch type metadata
        metadata_result = await self.type_metadata_lookup.lookup(issuer_claims.vct)
        if isinstance(metadata_result, Failure):
            return metadata_result
        metadata = metadata_result.unwrap()

        # Step 5: Verify disclosures
        disclosed_claims_result = self._verify_disclosures(
            sd_jwt.disclosures,
            issuer_claims,
            metadata
        )
        if isinstance(disclosed_claims_result, Failure):
            return disclosed_claims_result
        disclosed_claims = disclosed_claims_result.unwrap()

        # Step 6: Validate JSON Schema
        if self.config.validate_json_schema and metadata.schema:
            schema_result = self.json_schema_validator.validate(
                disclosed_claims,
                metadata.schema
            )
            if isinstance(schema_result, Failure):
                return schema_result

        # Step 7: Validate key binding
        if sd_jwt.key_binding_jwt:
            kb_result = await self._validate_key_binding(
                sd_jwt,
                issuer_claims,
                nonce
            )
            if isinstance(kb_result, Failure):
                return kb_result
        elif self.config.require_key_binding:
            return Failure(ValidationError.MissingKeyBinding)

        # Step 8: Check status
        if self.config.check_status and issuer_claims.status:
            status_result = await self._check_status(issuer_claims.status)
            if isinstance(status_result, Failure):
                return status_result

        # Step 9: Validate transaction data
        if transaction_data:
            tx_result = self._validate_transaction_data(
                disclosed_claims,
                transaction_data,
                issuer_claims
            )
            if isinstance(tx_result, Failure):
                return tx_result

        return Success(vp)
```

### 4.2 Issuer JWT Verification

```python
async def _verify_issuer_jwt(
    self,
    sd_jwt: SdJwtVc,
    issuer_chain: Optional[List[X509Certificate]]
) -> Result[IssuerJwtClaims, ValidationError]:
    """
    Verify the issuer-signed JWT

    Steps:
    1. Decode JWT header (unverified)
    2. Extract signing key from x5c or jwk header
    3. Validate certificate chain if x5c
    4. Verify JWT signature
    5. Parse and validate claims
    """

    try:
        # Decode header without verification
        header = jwt.get_unverified_header(sd_jwt.issuer_jwt)

        # Extract signing key
        if 'x5c' in header:
            # Certificate chain in header
            cert_chain_result = self._parse_x5c_chain(header['x5c'])
            if isinstance(cert_chain_result, Failure):
                return cert_chain_result
            cert_chain = cert_chain_result.unwrap()

            # Validate chain
            validation_result = await self.x5c_validator.validate(
                cert_chain,
                issuer_chain
            )
            if isinstance(validation_result, Failure):
                return validation_result

            # Use leaf certificate for verification
            public_key = cert_chain[0].public_key()

        elif 'jwk' in header:
            # JWK in header
            jwk_dict = header['jwk']
            try:
                public_key = jwk.JWK(**jwk_dict).export_to_pem()
            except Exception as e:
                return Failure(ValidationError.InvalidJwk(str(e)))
        else:
            return Failure(ValidationError.MissingKeyMaterial)

        # Verify signature
        try:
            claims = jwt.decode(
                sd_jwt.issuer_jwt,
                public_key,
                algorithms=self.config.allowed_jwt_algorithms,
                options={
                    'verify_exp': False,  # We'll verify manually
                    'verify_nbf': False,
                    'verify_iat': False,
                }
            )
        except jwt.JWTError as e:
            return Failure(ValidationError.InvalidSignature(str(e)))

        # Parse claims
        try:
            issuer_claims = IssuerJwtClaims(
                iss=claims['iss'],
                iat=datetime.fromtimestamp(claims['iat']),
                exp=datetime.fromtimestamp(claims['exp']) if 'exp' in claims else None,
                nbf=datetime.fromtimestamp(claims['nbf']) if 'nbf' in claims else None,
                vct=claims['vct'],
                status=claims.get('status'),
                cnf=claims.get('cnf'),
                _sd=claims.get('_sd'),
                _sd_alg=claims.get('_sd_alg', 'sha-256')
            )
        except KeyError as e:
            return Failure(ValidationError.MissingClaim(str(e)))

        return Success(issuer_claims)

    except Exception as e:
        return Failure(ValidationError.UnexpectedError(str(e)))
```

### 4.3 Selective Disclosure Verification

```python
def _verify_disclosures(
    self,
    disclosure_strings: List[str],
    issuer_claims: IssuerJwtClaims,
    metadata: TypeMetadata
) -> Result[Dict[str, Any], ValidationError]:
    """
    Verify selective disclosures and reconstruct claims

    Steps:
    1. Check disclosure count limit
    2. Decode each disclosure
    3. Compute disclosure hashes
    4. Verify hashes match _sd array in JWT
    5. Reconstruct full claims object
    """

    if len(disclosure_strings) > self.config.max_disclosure_count:
        return Failure(ValidationError.TooManyDisclosures)

    # Decode all disclosures
    disclosures: List[Disclosure] = []
    for ds in disclosure_strings:
        disclosure_result = Disclosure.from_base64(ds)
        if isinstance(disclosure_result, Failure):
            return disclosure_result
        disclosures.append(disclosure_result.unwrap())

    # Compute hashes
    disclosure_hashes = {
        d.hash(issuer_claims._sd_alg): d
        for d in disclosures
    }

    # Verify all disclosure hashes are in _sd array
    if issuer_claims._sd:
        expected_hashes = set(issuer_claims._sd)
        actual_hashes = set(disclosure_hashes.keys())

        if not actual_hashes.issubset(expected_hashes):
            unknown = actual_hashes - expected_hashes
            return Failure(ValidationError.UnknownDisclosureHash(list(unknown)))

    # Reconstruct claims
    # Start with non-selective claims from JWT
    reconstructed_claims = {
        k: v for k, v in issuer_claims.__dict__.items()
        if not k.startswith('_') and v is not None
    }

    # Add disclosed claims
    for hash_value, disclosure in disclosure_hashes.items():
        if hash_value in (issuer_claims._sd or []):
            reconstructed_claims[disclosure.claim_name] = disclosure.claim_value

    return Success(reconstructed_claims)
```

### 4.4 Key Binding Validation

```python
async def _validate_key_binding(
    self,
    sd_jwt: SdJwtVc,
    issuer_claims: IssuerJwtClaims,
    expected_nonce: Nonce
) -> Result[None, ValidationError]:
    """
    Validate Key Binding JWT

    Steps:
    1. Extract holder public key from cnf claim
    2. Verify KB-JWT signature with holder key
    3. Validate KB-JWT claims (nonce, aud, iat)
    4. Verify sd_hash
    """

    if not issuer_claims.cnf:
        return Failure(ValidationError.MissingConfirmation)

    # Extract holder public key
    try:
        if 'jwk' in issuer_claims.cnf:
            holder_key = jwk.JWK(**issuer_claims.cnf['jwk'])
        elif 'kid' in issuer_claims.cnf:
            # Would need to resolve kid to actual key
            return Failure(ValidationError.UnsupportedConfirmationMethod)
        else:
            return Failure(ValidationError.InvalidConfirmation)
    except Exception as e:
        return Failure(ValidationError.InvalidHolderKey(str(e)))

    # Verify KB-JWT signature
    try:
        kb_claims = jwt.decode(
            sd_jwt.key_binding_jwt,
            holder_key.export_to_pem(),
            algorithms=self.config.allowed_jwt_algorithms
        )
    except jwt.JWTError as e:
        return Failure(ValidationError.InvalidKeyBindingSignature(str(e)))

    # Parse claims
    try:
        kb_jwt_claims = KeyBindingJwtClaims(
            aud=kb_claims['aud'],
            iat=datetime.fromtimestamp(kb_claims['iat']),
            nonce=kb_claims['nonce'],
            sd_hash=kb_claims['sd_hash']
        )
    except KeyError as e:
        return Failure(ValidationError.MissingKeyBindingClaim(str(e)))

    # Verify nonce
    if kb_jwt_claims.nonce != expected_nonce.value:
        return Failure(ValidationError.NonceMismatch)

    # Verify iat is recent
    now = self.clock.now()
    age = (now - kb_jwt_claims.iat).total_seconds()
    if age > self.config.key_binding_max_age_seconds:
        return Failure(ValidationError.KeyBindingTooOld)
    if age < 0:
        return Failure(ValidationError.KeyBindingInFuture)

    # Verify sd_hash
    # Compute hash of <issuer_jwt>~<disclosure>~<disclosure>~...
    to_hash = sd_jwt.issuer_jwt
    for disclosure in sd_jwt.disclosures:
        to_hash += f"~{disclosure}"

    computed_hash = self._compute_sd_hash(to_hash, kb_jwt_claims.sd_hash_alg)
    if computed_hash != kb_jwt_claims.sd_hash:
        return Failure(ValidationError.SdHashMismatch)

    return Success(None)
```

### 4.5 Status List Validation

```python
async def _check_status(
    self,
    status_claim: Dict[str, Any]
) -> Result[None, ValidationError]:
    """
    Check credential status using status list

    Steps:
    1. Extract status list URI and index
    2. Fetch status list token
    3. Verify status list JWT
    4. Check bit at index
    """

    try:
        status_list_uri = status_claim['status_list']['uri']
        status_list_index = int(status_claim['status_list']['idx'])
    except (KeyError, ValueError) as e:
        return Failure(ValidationError.InvalidStatusClaim(str(e)))

    # Fetch and validate status list
    status_list_result = await self.status_list_validator.fetch_and_validate(
        status_list_uri
    )
    if isinstance(status_list_result, Failure):
        return status_list_result

    status_list_token = status_list_result.unwrap()

    # Check status at index
    try:
        status = status_list_token.status_list.check_status(status_list_index)
    except IndexError:
        return Failure(ValidationError.StatusIndexOutOfBounds)

    # 0 = valid, 1 = revoked (for 1-bit status lists)
    if status != 0:
        return Failure(ValidationError.CredentialRevoked(status))

    return Success(None)
```

---

## 5. SUPPORTING COMPONENTS

### 5.1 Type Metadata Lookup

```python
import httpx
from cachetools import TTLCache

class TypeMetadataLookup:
    """Fetches and caches VC type metadata"""

    def __init__(self, config: SdJwtVcValidationConfig):
        self.config = config
        self.cache = TTLCache(
            maxsize=100,
            ttl=config.type_metadata_cache_ttl_seconds
        )
        self.client = httpx.AsyncClient(
            timeout=config.type_metadata_timeout_seconds
        )

    async def lookup(self, vct: str) -> Result[TypeMetadata, ValidationError]:
        """
        Lookup type metadata from vct URL

        The vct claim should be a URL pointing to type metadata
        """

        # Check cache
        if vct in self.cache:
            return Success(self.cache[vct])

        # Fetch from URL
        try:
            response = await self.client.get(vct)
            response.raise_for_status()
            metadata_dict = response.json()
        except httpx.HTTPError as e:
            return Failure(ValidationError.TypeMetadataFetchFailed(str(e)))
        except ValueError as e:
            return Failure(ValidationError.TypeMetadataInvalidJson(str(e)))

        # Parse metadata
        try:
            metadata = TypeMetadata(
                vct=metadata_dict['vct'],
                name=metadata_dict.get('name', ''),
                description=metadata_dict.get('description'),
                claims=metadata_dict.get('claims'),
                schema=metadata_dict.get('schema'),
                extends=metadata_dict.get('extends')
            )
        except KeyError as e:
            return Failure(ValidationError.TypeMetadataInvalidStructure(str(e)))

        # Cache
        self.cache[vct] = metadata

        return Success(metadata)
```

### 5.2 Status List Token Validator

```python
class StatusListTokenValidator:
    """Validates status list tokens"""

    def __init__(self, config: SdJwtVcValidationConfig):
        self.config = config
        self.cache = TTLCache(
            maxsize=50,
            ttl=config.status_list_cache_ttl_seconds
        )
        self.client = httpx.AsyncClient()

    async def fetch_and_validate(
        self,
        uri: str
    ) -> Result[StatusListToken, ValidationError]:
        """Fetch and validate status list token"""

        # Check cache
        if uri in self.cache:
            return Success(self.cache[uri])

        # Fetch token
        try:
            response = await self.client.get(uri)
            response.raise_for_status()
            token_string = response.text
        except httpx.HTTPError as e:
            return Failure(ValidationError.StatusListFetchFailed(str(e)))

        # Verify JWT (status list issuer should be trusted)
        try:
            # Note: In production, would verify with status list issuer's key
            claims = jwt.decode(
                token_string,
                options={'verify_signature': False}  # TODO: Proper verification
            )
        except jwt.JWTError as e:
            return Failure(ValidationError.InvalidStatusListToken(str(e)))

        # Parse status list
        try:
            status_list_token = StatusListToken(
                iss=claims['iss'],
                sub=claims['sub'],
                iat=datetime.fromtimestamp(claims['iat']),
                exp=datetime.fromtimestamp(claims['exp']) if 'exp' in claims else None,
                status_list=StatusList(
                    bits=claims['status_list']['bits'],
                    lst=claims['status_list']['lst']
                )
            )
        except KeyError as e:
            return Failure(ValidationError.InvalidStatusListStructure(str(e)))

        # Cache
        self.cache[uri] = status_list_token

        return Success(status_list_token)
```

### 5.3 JSON Schema Validator

```python
from jsonschema import validate, ValidationError as JsonSchemaValidationError

class JsonSchemaValidator:
    """Validates disclosed claims against JSON Schema"""

    def validate(
        self,
        claims: Dict[str, Any],
        schema: Dict[str, Any]
    ) -> Result[None, ValidationError]:
        """Validate claims against JSON Schema"""

        try:
            validate(instance=claims, schema=schema)
            return Success(None)
        except JsonSchemaValidationError as e:
            return Failure(ValidationError.SchemaValidationFailed(str(e)))
```

---

## 6. ERROR HANDLING

### 6.1 Error Types

```python
from enum import Enum
from dataclasses import dataclass

class ValidationErrorType(Enum):
    # Parsing errors
    INVALID_FORMAT = "invalid_format"
    PARSE_ERROR = "parse_error"

    # JWT errors
    INVALID_SIGNATURE = "invalid_signature"
    MISSING_KEY_MATERIAL = "missing_key_material"
    INVALID_JWK = "invalid_jwk"
    MISSING_CLAIM = "missing_claim"

    # Temporal errors
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"

    # Disclosure errors
    TOO_MANY_DISCLOSURES = "too_many_disclosures"
    UNKNOWN_DISCLOSURE_HASH = "unknown_disclosure_hash"
    INVALID_DISCLOSURE = "invalid_disclosure"

    # Key binding errors
    MISSING_KEY_BINDING = "missing_key_binding"
    INVALID_KEY_BINDING_SIGNATURE = "invalid_key_binding_signature"
    NONCE_MISMATCH = "nonce_mismatch"
    KEY_BINDING_TOO_OLD = "key_binding_too_old"
    SD_HASH_MISMATCH = "sd_hash_mismatch"

    # Status errors
    STATUS_LIST_FETCH_FAILED = "status_list_fetch_failed"
    CREDENTIAL_REVOKED = "credential_revoked"

    # Type metadata errors
    TYPE_METADATA_FETCH_FAILED = "type_metadata_fetch_failed"
    TYPE_METADATA_INVALID = "type_metadata_invalid"

    # Schema errors
    SCHEMA_VALIDATION_FAILED = "schema_validation_failed"

    # Transaction data errors
    TRANSACTION_DATA_MISMATCH = "transaction_data_mismatch"

@dataclass(frozen=True)
class ValidationError:
    """Validation error"""
    type: ValidationErrorType
    message: str
    cause: Optional[Exception] = None
```

---

## 7. TESTING STRATEGY

### 7.1 Unit Tests

```python
import pytest
from unittest.mock import AsyncMock, Mock

class TestSdJwtVcValidator:

    @pytest.fixture
    def validator(self):
        config = SdJwtVcValidationConfig()
        x5c_validator = Mock()
        type_metadata_lookup = Mock()
        json_schema_validator = Mock()
        status_list_validator = Mock()
        clock = Mock()

        return SdJwtVcValidator(
            config,
            x5c_validator,
            type_metadata_lookup,
            json_schema_validator,
            status_list_validator,
            clock
        )

    @pytest.mark.asyncio
    async def test_valid_sd_jwt_vc_with_key_binding(self, validator):
        """Test validation of valid SD-JWT VC with key binding"""
        # Arrange
        sd_jwt_string = create_valid_sd_jwt_vc()
        vp = VerifiablePresentation.Str(sd_jwt_string, Format.SdJwtVc)

        # Act
        result = await validator.validate(
            vp,
            TransactionId("tx-123"),
            Nonce("nonce-456"),
            None,
            None
        )

        # Assert
        assert isinstance(result, Success)

    @pytest.mark.asyncio
    async def test_expired_sd_jwt_vc(self, validator):
        """Test validation fails for expired credential"""
        # Arrange
        sd_jwt_string = create_expired_sd_jwt_vc()
        vp = VerifiablePresentation.Str(sd_jwt_string, Format.SdJwtVc)

        # Act
        result = await validator.validate(vp, ...)

        # Assert
        assert isinstance(result, Failure)
        assert result.failure().type == ValidationErrorType.EXPIRED

    @pytest.mark.asyncio
    async def test_invalid_disclosure_hash(self, validator):
        """Test validation fails for tampered disclosure"""
        # Arrange
        sd_jwt_string = create_sd_jwt_with_invalid_disclosure()
        vp = VerifiablePresentation.Str(sd_jwt_string, Format.SdJwtVc)

        # Act
        result = await validator.validate(vp, ...)

        # Assert
        assert isinstance(result, Failure)
        assert result.failure().type == ValidationErrorType.UNKNOWN_DISCLOSURE_HASH
```

### 7.2 Integration Tests

```python
@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_sd_jwt_vc_validation_flow():
    """Test complete SD-JWT VC validation with real HTTP calls"""

    # Create real validator with actual dependencies
    config = SdJwtVcValidationConfig()
    validator = create_real_validator(config)

    # Use test credential from conformance suite
    sd_jwt_vc = load_test_credential("valid_sd_jwt_vc_001.txt")

    # Validate
    result = await validator.validate(
        VerifiablePresentation.Str(sd_jwt_vc, Format.SdJwtVc),
        TransactionId("test-tx"),
        Nonce("test-nonce"),
        None,
        None
    )

    assert isinstance(result, Success)
```

---

## 8. IMPLEMENTATION NOTES

### 8.1 Performance Considerations

1. **Caching**: Type metadata and status lists must be cached
2. **Async Operations**: HTTP fetches must be async
3. **Cryptographic Operations**: Signature verification is CPU-intensive
4. **Hash Computation**: Disclosure hashing should use fast implementations

### 8.2 Security Considerations

1. **Certificate Validation**: Must properly validate X.509 chains
2. **Algorithm Restrictions**: Only allow strong algorithms
3. **Nonce Validation**: Must prevent replay attacks
4. **Status Checking**: Must check revocation status
5. **Timeout**: HTTP fetches must have timeouts

### 8.3 Python-Specific Implementation

1. Use `sd-jwt-python` library as reference: https://github.com/openwallet-foundation-labs/sd-jwt-python
2. Consider `joserfc` instead of `python-jose` for better JWT support
3. Use `httpx` for async HTTP client
4. Use `cachetools` for TTL caching
5. Use `jsonschema` library for schema validation

### 8.4 Dependencies

```
sd-jwt==0.10.0
joserfc==0.9.0
httpx==0.26.0
cryptography==42.0.0
jsonschema==4.21.1
cachetools==5.3.2
returns==0.22.0
```

---

## 9. REFERENCES

1. **IETF SD-JWT**: https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/
2. **SD-JWT VC**: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/
3. **Status List**: https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/
4. **OpenID4VP**: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
5. **Reference Implementation**: https://github.com/openwallet-foundation-labs/sd-jwt-python

---

**End of SD-JWT VC Validation Design Document**
