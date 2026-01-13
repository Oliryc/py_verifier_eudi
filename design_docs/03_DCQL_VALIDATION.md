# DCQL Validation and Satisfaction - Detailed Design

**Document Version**: 1.0
**Last Updated**: 2025-01-03
**Status**: Design Phase

---

## 1. OVERVIEW

DCQL (Digital Credential Query Language) is the query language used by verifiers to request specific credentials and claims from wallets. This subsystem handles parsing, validation, and satisfaction checking of DCQL queries.

### Key Responsibilities
- Parse and validate DCQL structure
- Validate cross-references between credentials, claims, and sets
- Check format-specific constraints (SD-JWT VC vs MSO MDoc)
- Evaluate whether a wallet's response satisfies the query

---

## 2. DATA STRUCTURES

```python
from pydantic import BaseModel, validator, root_validator
from typing import Optional, List, Dict, Any
from enum import Enum

class Format(str, Enum):
    MSO_MDOC = "mso_mdoc"
    SD_JWT_VC = "dc+sd-jwt"
    W3C_JWT_VC = "jwt_vc_json"

class QueryId(BaseModel):
    value: str

    @validator('value')
    def validate_format(cls, v):
        # Must be alphanumeric, underscore, or hyphen
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError("QueryId must contain only alphanumeric, underscore, or hyphen characters")
        return v

class ClaimId(BaseModel):
    value: str

    @validator('value')
    def validate_format(cls, v):
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError("ClaimId must contain only alphanumeric, underscore, or hyphen characters")
        return v

class ClaimPath(BaseModel):
    """JSON path to a claim"""
    value: List[Union[str, int]]  # Mix of keys and array indices

class ClaimsQuery(BaseModel):
    """Query for a specific claim"""
    id: Optional[ClaimId] = None
    path: ClaimPath
    values: Optional[List[Any]] = None  # Allowed values
    intent_to_retain: Optional[bool] = None  # MSO MDoc only

    @validator('values')
    def validate_values_are_primitives(cls, v):
        if v is not None:
            for val in v:
                if isinstance(val, (dict, list)):
                    raise ValueError("values must contain only primitives")
        return v

class TrustedAuthorityType(str, Enum):
    AKI = "aki"  # Authority Key Identifier
    ETSI_TL = "etsi_tl"  # ETSI Trusted List
    OPENID_FEDERATION = "openid_federation"

class TrustedAuthority(BaseModel):
    type: TrustedAuthorityType
    values: List[str]

    @validator('values')
    def validate_not_empty(cls, v):
        if not v:
            raise ValueError("TrustedAuthority values cannot be empty")
        return v

class CredentialQuery(BaseModel):
    """Query for a single credential"""
    id: QueryId
    format: Format
    meta: Dict[str, Any]  # Format-specific metadata
    multiple: Optional[bool] = None
    trusted_authorities: Optional[List[TrustedAuthority]] = None
    require_cryptographic_holder_binding: Optional[bool] = None
    claims: Optional[List[ClaimsQuery]] = None
    claim_sets: Optional[List['ClaimSet']] = None

    @root_validator
    def validate_claims_consistency(cls, values):
        claims = values.get('claims')
        claim_sets = values.get('claim_sets')
        format = values.get('format')

        # Cannot have claim_sets without claims
        if claim_sets and not claims:
            raise ValueError("Cannot have claim_sets without claims")

        # Format-specific validation for claims
        if claims:
            for claim in claims:
                if format == Format.MSO_MDOC:
                    cls._validate_mdoc_claim(claim)
                else:
                    cls._validate_non_mdoc_claim(claim)

            # Check claim IDs are unique
            claim_ids = [c.id.value for c in claims if c.id]
            if len(claim_ids) != len(set(claim_ids)):
                raise ValueError("Claim IDs must be unique within a CredentialQuery")

        # Validate claim_sets reference existing claim IDs
        if claim_sets and claims:
            claim_ids = [c.id.value for c in claims if c.id]
            for claim_set in claim_sets:
                for claim_id in claim_set.value:
                    if claim_id.value not in claim_ids:
                        raise ValueError(f"ClaimSet references unknown claim ID: {claim_id.value}")

        return values

    @staticmethod
    def _validate_mdoc_claim(claim: ClaimsQuery):
        """MSO MDoc claims must have exactly 2-element paths"""
        if len(claim.path.value) != 2:
            raise ValueError("MSO MDoc ClaimPaths must have exactly 2 elements (namespace, claim)")
        if not all(isinstance(elem, str) for elem in claim.path.value):
            raise ValueError("MSO MDoc ClaimPaths must contain only string elements")

    @staticmethod
    def _validate_non_mdoc_claim(claim: ClaimsQuery):
        """Non-MSO MDoc claims cannot have intent_to_retain"""
        if claim.intent_to_retain is not None:
            raise ValueError("intent_to_retain can only be used with MSO MDoc")

class ClaimSet(BaseModel):
    """Set of claim IDs that must be provided together"""
    value: List[ClaimId]

    @validator('value')
    def validate_not_empty_and_unique(cls, v):
        if not v:
            raise ValueError("ClaimSet cannot be empty")
        ids = [claim_id.value for claim_id in v]
        if len(ids) != len(set(ids)):
            raise ValueError("ClaimSet cannot contain duplicate IDs")
        return v

class Credentials(BaseModel):
    """Non-empty list of credential queries with unique IDs"""
    value: List[CredentialQuery]

    @validator('value')
    def validate_unique_ids(cls, v):
        if not v:
            raise ValueError("Credentials cannot be empty")
        ids = [cq.id.value for cq in v]
        if len(ids) != len(set(ids)):
            raise ValueError("Credential query IDs must be unique")
        return v

    @property
    def ids(self) -> List[QueryId]:
        return [cq.id for cq in self.value]

class CredentialQueryIds(BaseModel):
    """Non-empty list of query IDs"""
    value: List[QueryId]

    @validator('value')
    def validate_not_empty_and_unique(cls, v):
        if not v:
            raise ValueError("CredentialQueryIds cannot be empty")
        ids = [qid.value for qid in v]
        if len(ids) != len(set(ids)):
            raise ValueError("CredentialQueryIds must be unique")
        return v

class CredentialSetQuery(BaseModel):
    """Constraints on which credentials must be provided"""
    options: List[CredentialQueryIds]
    required: Optional[bool] = None

    @validator('options')
    def validate_options_not_empty(cls, v):
        if not v:
            raise ValueError("CredentialSetQuery options cannot be empty")
        for option in v:
            if not option.value:
                raise ValueError("CredentialSetQuery options must contain non-empty arrays")
        return v

    @property
    def required_or_default(self) -> bool:
        return self.required if self.required is not None else True

class CredentialSets(BaseModel):
    """Non-empty list of credential set queries"""
    value: List[CredentialSetQuery]

    @validator('value')
    def validate_not_empty(cls, v):
        if not v:
            raise ValueError("CredentialSets cannot be empty if provided")
        return v

    def ensure_known_ids(self, credentials: Credentials) -> 'CredentialSets':
        """Validate all referenced query IDs exist in credentials"""
        credential_ids = {cq.id.value for cq in credentials.value}

        violations = []
        for set_idx, credential_set in enumerate(self.value):
            for opt_idx, option in enumerate(credential_set.options):
                unknown = [qid.value for qid in option.value if qid.value not in credential_ids]
                if unknown:
                    violations.append({
                        'set_index': set_idx,
                        'option_index': opt_idx,
                        'unknown_ids': unknown
                    })

        if violations:
            raise ValueError(f"CredentialSets reference unknown credential query IDs: {violations}")

        return self

class DCQL(BaseModel):
    """Digital Credential Query Language"""
    credentials: Credentials
    credential_sets: Optional[CredentialSets] = None

    @root_validator
    def validate_credential_sets(cls, values):
        credentials = values.get('credentials')
        credential_sets = values.get('credential_sets')

        if credential_sets and credentials:
            credential_sets.ensure_known_ids(credentials)

        return values

    class Config:
        json_schema_extra = {
            "example": {
                "credentials": [
                    {
                        "id": "pid",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://example.com/pid"]
                        }
                    }
                ]
            }
        }
```

---

## 3. SATISFACTION CHECKING

### 3.1 Satisfaction Algorithm

```python
from typing import Dict, List
from returns.result import Result, Success, Failure

class DcqlSatisfactionChecker:
    """Checks if a wallet response satisfies a DCQL query"""

    def satisfies(
        self,
        dcql: DCQL,
        wallet_response: Dict[QueryId, List[VerifiablePresentation]]
    ) -> Result[bool, ValidationError]:
        """
        Check if wallet response satisfies DCQL query

        Algorithm:
        1. If no credential_sets: all credentials must be present
        2. If credential_sets exist:
           - All required sets must be satisfied
           - A set is satisfied if at least one option is fully covered
        """

        # Check basic coverage: all credential IDs in response must be in query
        query_ids = {cq.id.value for cq in dcql.credentials.value}
        response_ids = {qid.value for qid in wallet_response.keys()}

        if not response_ids.issubset(query_ids):
            unknown = response_ids - query_ids
            return Failure(ValidationError.UnknownCredentialIds(list(unknown)))

        # If no credential_sets, all credentials must be present
        if not dcql.credential_sets:
            if response_ids != query_ids:
                missing = query_ids - response_ids
                return Failure(ValidationError.MissingCredentials(list(missing)))
            return Success(True)

        # Check credential_sets satisfaction
        for credential_set in dcql.credential_sets.value:
            if credential_set.required_or_default:
                if not self._is_set_satisfied(credential_set, response_ids):
                    return Failure(ValidationError.RequiredCredentialSetNotSatisfied)

        return Success(True)

    def _is_set_satisfied(
        self,
        credential_set: CredentialSetQuery,
        response_ids: set
    ) -> bool:
        """
        A credential set is satisfied if at least one option is fully covered
        by the response
        """
        for option in credential_set.options:
            option_ids = {qid.value for qid in option.value}
            if option_ids.issubset(response_ids):
                return True
        return False
```

### 3.2 Multiplicity Validation

```python
class DcqlMultiplicityValidator:
    """Validates that multiple flag is respected"""

    def validate(
        self,
        credential_query: CredentialQuery,
        presentations: List[VerifiablePresentation]
    ) -> Result[None, ValidationError]:
        """
        Validate multiplicity constraint

        If multiple=false (or not set), only one credential should be provided
        If multiple=true, multiple credentials are allowed
        """
        multiple_allowed = credential_query.multiple if credential_query.multiple is not None else False

        if not multiple_allowed and len(presentations) > 1:
            return Failure(ValidationError.MultipleCredentialsNotAllowed(
                credential_query.id.value
            ))

        return Success(None)
```

---

## 4. FORMAT-SPECIFIC METADATA

### 4.1 SD-JWT VC Metadata

```python
class DCQLMetaSdJwtVc(BaseModel):
    """SD-JWT VC specific metadata"""
    vct_values: List[str]

    @validator('vct_values')
    def validate_not_empty(cls, v):
        if not v:
            raise ValueError("vct_values cannot be empty")
        if any(not val.strip() for val in v):
            raise ValueError("vct_values cannot contain blank values")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "vct_values": ["https://example.com/credentials/pid"]
            }
        }
```

### 4.2 MSO MDoc Metadata

```python
class MsoMdocDocType(BaseModel):
    value: str

    @validator('value')
    def validate_not_blank(cls, v):
        if not v.strip():
            raise ValueError("DocType cannot be blank")
        return v

class DCQLMetaMsoMdoc(BaseModel):
    """MSO MDoc specific metadata"""
    doctype_value: MsoMdocDocType

    class Config:
        json_schema_extra = {
            "example": {
                "doctype_value": "org.iso.18013.5.1.mDL"
            }
        }
```

---

## 5. HELPER FUNCTIONS

### 5.1 Query Building

```python
class DcqlBuilder:
    """Helper for building DCQL queries"""

    @staticmethod
    def sd_jwt_vc_query(
        id: str,
        vct_values: List[str],
        claims: Optional[List[ClaimsQuery]] = None,
        multiple: bool = False
    ) -> CredentialQuery:
        """Build SD-JWT VC credential query"""
        return CredentialQuery(
            id=QueryId(value=id),
            format=Format.SD_JWT_VC,
            meta=DCQLMetaSdJwtVc(vct_values=vct_values).dict(),
            claims=claims,
            multiple=multiple
        )

    @staticmethod
    def mdoc_query(
        id: str,
        doctype: str,
        claims: Optional[List[ClaimsQuery]] = None,
        multiple: bool = False
    ) -> CredentialQuery:
        """Build MSO MDoc credential query"""
        return CredentialQuery(
            id=QueryId(value=id),
            format=Format.MSO_MDOC,
            meta=DCQLMetaMsoMdoc(doctype_value=MsoMdocDocType(value=doctype)).dict(),
            claims=claims,
            multiple=multiple
        )

    @staticmethod
    def mdoc_claim(
        namespace: str,
        claim_name: str,
        id: Optional[str] = None,
        values: Optional[List[Any]] = None,
        intent_to_retain: Optional[bool] = None
    ) -> ClaimsQuery:
        """Build MSO MDoc claim query"""
        return ClaimsQuery(
            id=ClaimId(value=id) if id else None,
            path=ClaimPath(value=[namespace, claim_name]),
            values=values,
            intent_to_retain=intent_to_retain
        )
```

---

## 6. TESTING EXAMPLES

```python
import pytest

class TestDCQLValidation:

    def test_valid_simple_dcql(self):
        """Test simple valid DCQL"""
        dcql = DCQL(
            credentials=Credentials(value=[
                CredentialQuery(
                    id=QueryId(value="pid"),
                    format=Format.SD_JWT_VC,
                    meta={"vct_values": ["https://example.com/pid"]}
                )
            ])
        )
        assert dcql is not None

    def test_duplicate_credential_ids_rejected(self):
        """Test that duplicate credential IDs are rejected"""
        with pytest.raises(ValueError, match="unique"):
            DCQL(
                credentials=Credentials(value=[
                    CredentialQuery(
                        id=QueryId(value="pid"),
                        format=Format.SD_JWT_VC,
                        meta={"vct_values": ["https://example.com/pid"]}
                    ),
                    CredentialQuery(
                        id=QueryId(value="pid"),  # Duplicate
                        format=Format.SD_JWT_VC,
                        meta={"vct_values": ["https://example.com/pid2"]}
                    )
                ])
            )

    def test_mdoc_claim_validation(self):
        """Test MSO MDoc claim must have 2 elements"""
        with pytest.raises(ValueError, match="exactly 2 elements"):
            CredentialQuery(
                id=QueryId(value="mdl"),
                format=Format.MSO_MDOC,
                meta={"doctype_value": "org.iso.18013.5.1.mDL"},
                claims=[
                    ClaimsQuery(
                        path=ClaimPath(value=["namespace", "claim", "extra"])  # Too many
                    )
                ]
            )

    def test_satisfaction_checking(self):
        """Test DCQL satisfaction checking"""
        dcql = DCQL(
            credentials=Credentials(value=[
                CredentialQuery(
                    id=QueryId(value="pid"),
                    format=Format.SD_JWT_VC,
                    meta={"vct_values": ["https://example.com/pid"]}
                ),
                CredentialQuery(
                    id=QueryId(value="mdl"),
                    format=Format.MSO_MDOC,
                    meta={"doctype_value": "org.iso.18013.5.1.mDL"}
                )
            ])
        )

        # Response satisfies query
        response = {
            QueryId(value="pid"): [Mock()],
            QueryId(value="mdl"): [Mock()]
        }

        checker = DcqlSatisfactionChecker()
        result = checker.satisfies(dcql, response)
        assert isinstance(result, Success)

        # Response missing credential
        incomplete_response = {
            QueryId(value="pid"): [Mock()]
        }

        result = checker.satisfies(dcql, incomplete_response)
        assert isinstance(result, Failure)

    def test_credential_sets_satisfaction(self):
        """Test credential sets (OR logic)"""
        dcql = DCQL(
            credentials=Credentials(value=[
                CredentialQuery(id=QueryId(value="pid"), format=Format.SD_JWT_VC, meta={}),
                CredentialQuery(id=QueryId(value="passport"), format=Format.SD_JWT_VC, meta={}),
                CredentialQuery(id=QueryId(value="mdl"), format=Format.MSO_MDOC, meta={})
            ]),
            credential_sets=CredentialSets(value=[
                CredentialSetQuery(
                    options=[
                        CredentialQueryIds(value=[QueryId(value="pid")]),
                        CredentialQueryIds(value=[QueryId(value="passport"), QueryId(value="mdl")])
                    ],
                    required=True
                )
            ])
        )

        # Option 1: Just PID
        response1 = {QueryId(value="pid"): [Mock()]}
        checker = DcqlSatisfactionChecker()
        assert checker.satisfies(dcql, response1).unwrap() is True

        # Option 2: Passport + mDL
        response2 = {
            QueryId(value="passport"): [Mock()],
            QueryId(value="mdl"): [Mock()]
        }
        assert checker.satisfies(dcql, response2).unwrap() is True

        # Incomplete (neither option satisfied)
        response3 = {QueryId(value="passport"): [Mock()]}
        result = checker.satisfies(dcql, response3)
        assert isinstance(result, Failure)
```

---

## 7. KEY IMPLEMENTATION NOTES

### 7.1 Validation Order

1. **Parse JSON** → Pydantic models with validators
2. **Validate structure** → Unique IDs, non-empty lists
3. **Validate cross-references** → credential_sets reference valid IDs
4. **Validate format-specific** → MSO MDoc 2-element paths, etc.
5. **Validate satisfaction** → Check wallet response matches query

### 7.2 Performance Considerations

- DCQL validation is synchronous (no I/O)
- Use sets for ID lookups (O(1) vs O(n))
- Cache parsed/validated DCQL objects
- Satisfaction checking is O(n*m) where n=sets, m=options

### 7.3 Common Pitfalls

1. **Claim IDs are optional** - not all claims need IDs
2. **claim_sets without claims** - invalid
3. **MSO MDoc path lengths** - must be exactly 2
4. **Credential sets logic** - OR between options, AND for required sets
5. **Query ID format** - only alphanumeric, underscore, hyphen

---

## 8. REFERENCES

1. **OpenID4VP DCQL**: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-query-language
2. **JSON Path**: RFC 9535 (JSONPath)
3. **Pydantic**: https://docs.pydantic.dev/

---

**End of DCQL Validation Design Document**
