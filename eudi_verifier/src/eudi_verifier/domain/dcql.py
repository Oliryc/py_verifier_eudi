"""DCQL (Digital Credential Query Language) models

This module implements the DCQL specification for requesting verifiable credentials
from wallets. DCQL provides a flexible query language that supports:

- Multiple credential formats (SD-JWT VC, MSO MDoc)
- Selective disclosure (requesting specific claims)
- Complex credential sets (AND/OR logic)
- Format-specific validation rules

Reference: https://openid.github.io/credential-query-language/
"""

from typing import Annotated, Any, Dict, List, Literal, Optional, Set

from pydantic import BaseModel, Field, field_validator, model_validator, BeforeValidator


# ======================
# Value Objects
# ======================


class QueryId(BaseModel):
    """Unique identifier for a credential query"""

    value: str = Field(..., min_length=1, description="Unique query identifier")

    @field_validator("value")
    @classmethod
    def validate_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("QueryId cannot be blank")
        return v

    def __str__(self) -> str:
        return self.value

    def __hash__(self) -> int:
        return hash(self.value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, QueryId):
            return False
        return self.value == other.value


def parse_query_id(v: Any) -> QueryId:
    """Parse QueryId from string or dict"""
    if isinstance(v, QueryId):
        return v
    if isinstance(v, str):
        return QueryId(value=v)
    if isinstance(v, dict) and 'value' in v:
        return QueryId(**v)
    raise ValueError(f"Cannot parse QueryId from {type(v)}")


class ClaimId(BaseModel):
    """Unique identifier for a claim query"""

    value: str = Field(..., min_length=1, description="Unique claim identifier")

    @field_validator("value")
    @classmethod
    def validate_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("ClaimId cannot be blank")
        return v

    def __str__(self) -> str:
        return self.value

    def __hash__(self) -> int:
        return hash(self.value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ClaimId):
            return False
        return self.value == other.value


def parse_claim_id(v: Any) -> ClaimId:
    """Parse ClaimId from string or dict"""
    if isinstance(v, ClaimId):
        return v
    if isinstance(v, str):
        return ClaimId(value=v)
    if isinstance(v, dict) and 'value' in v:
        return ClaimId(**v)
    raise ValueError(f"Cannot parse ClaimId from {type(v)}")


# ======================
# Claim Value Models
# ======================


class ClaimValue(BaseModel):
    """
    Value constraint for a claim.

    Can specify exact value, list of allowed values, or pattern matching.
    """

    value: Optional[Any] = Field(None, description="Exact value expected")
    values: Optional[List[Any]] = Field(None, description="List of allowed values")
    pattern: Optional[str] = Field(None, description="Regex pattern for string values")

    @model_validator(mode="after")
    def validate_exactly_one_constraint(self) -> "ClaimValue":
        """Ensure exactly one of value, values, or pattern is set"""
        constraints = [self.value is not None, self.values is not None, self.pattern is not None]
        if sum(constraints) != 1:
            raise ValueError("Exactly one of 'value', 'values', or 'pattern' must be specified")
        return self

    @field_validator("values")
    @classmethod
    def validate_values_not_empty(cls, v: Optional[List[Any]]) -> Optional[List[Any]]:
        if v is not None and len(v) == 0:
            raise ValueError("'values' must contain at least one element")
        return v


# ======================
# Claims Query Models
# ======================


class ClaimConstraint(BaseModel):
    """
    Constraint for a single claim.

    Attributes:
        path: JSON path to the claim (e.g., ["given_name"] or ["address", "street"])
        values: Optional value constraints
        intent_to_retain: Whether verifier intends to retain this claim
        purpose: Human-readable purpose for requesting this claim
    """

    path: List[str] = Field(..., min_items=1, description="JSON path to claim")
    values: Optional[ClaimValue] = Field(None, description="Value constraints")
    intent_to_retain: Optional[bool] = Field(None, description="Intent to retain claim")
    purpose: Optional[str] = Field(None, description="Purpose for requesting claim")

    @field_validator("path")
    @classmethod
    def validate_path_not_empty_strings(cls, v: List[str]) -> List[str]:
        """Ensure no path element is empty"""
        for element in v:
            if not element.strip():
                raise ValueError("Path elements cannot be blank")
        return v

    @model_validator(mode="after")
    def validate_format_specific_rules(self) -> "ClaimConstraint":
        """Apply format-specific validation (will be enhanced per format)"""
        # MSO MDoc paths must be exactly 2 elements: [namespace, claim_name]
        # This is validated at the CredentialQuery level where format is known
        return self


class ClaimsQuery(BaseModel):
    """
    Query for specific claims within a credential.

    Attributes:
        id: Optional unique identifier for this claims query
        claims: List of claim constraints
    """

    id: Optional[Annotated[ClaimId, BeforeValidator(parse_claim_id)]] = Field(None, description="Unique identifier for this query")
    claims: List[ClaimConstraint] = Field(..., min_items=1, description="Claim constraints")

    @field_validator("claims")
    @classmethod
    def validate_unique_paths(cls, v: List[ClaimConstraint]) -> List[ClaimConstraint]:
        """Ensure no duplicate claim paths"""
        paths_seen: Set[tuple] = set()
        for constraint in v:
            path_tuple = tuple(constraint.path)
            if path_tuple in paths_seen:
                raise ValueError(f"Duplicate claim path: {constraint.path}")
            paths_seen.add(path_tuple)
        return v


# ======================
# Credential Query Models
# ======================


class CredentialMeta(BaseModel):
    """
    Metadata constraints for credential selection.

    Attributes:
        vct: Verifiable Credential Type (for SD-JWT VC)
        doctype: Document type (for MSO MDoc)
        issuer_trust_list: List of trusted issuer identifiers
    """

    vct: Optional[List[str]] = Field(None, description="Allowed VC types (SD-JWT VC)")
    doctype: Optional[List[str]] = Field(None, description="Allowed doctypes (MSO MDoc)")
    issuer_trust_list: Optional[List[str]] = Field(None, description="Trusted issuer identifiers")

    @field_validator("vct", "doctype", "issuer_trust_list", mode='before')
    @classmethod
    def normalize_to_list(cls, v: Optional[str | List[str]]) -> Optional[List[str]]:
        """Accept single string or list, normalize to list"""
        if v is None:
            return None
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            if len(v) == 0:
                raise ValueError("List must contain at least one element")
            return v
        raise ValueError(f"Expected string or list, got {type(v)}")



class CredentialQuery(BaseModel):
    """
    Query for a single credential.

    Combines format specification, metadata constraints, and claim selection.

    Attributes:
        id: Unique identifier for this credential query
        format: Credential format (mso_mdoc, dc+sd-jwt, etc.)
        meta: Metadata constraints for credential selection
        claims: Claims to request from the credential
    """

    id: Annotated[QueryId, BeforeValidator(parse_query_id)] = Field(..., description="Unique query identifier")
    format: Literal["mso_mdoc", "dc+sd-jwt", "jwt_vc_json"] = Field(..., description="Credential format")
    meta: Optional[CredentialMeta] = Field(None, description="Metadata constraints")
    claims: Optional[ClaimsQuery] = Field(None, description="Claims query")

    @field_validator("claims", mode='before')
    @classmethod
    def parse_claims_from_list(cls, v: Any) -> Optional[ClaimsQuery]:
        """Accept list of claim dicts and convert to ClaimsQuery"""
        if v is None:
            return None
        if isinstance(v, ClaimsQuery):
            return v
        if isinstance(v, list):
            # Convert list of dicts to ClaimConstraint objects
            claim_constraints = []
            for item in v:
                if isinstance(item, dict):
                    # Extract path from dict
                    if 'path' in item:
                        claim_constraints.append(ClaimConstraint(**item))
                    else:
                        raise ValueError("Each claim must have a 'path' field")
                else:
                    raise ValueError(f"Expected dict, got {type(item)}")
            return ClaimsQuery(claims=claim_constraints)
        raise ValueError(f"Expected ClaimsQuery or list, got {type(v)}")

    @model_validator(mode="after")
    def validate_format_specific_constraints(self) -> "CredentialQuery":
        """Apply format-specific validation rules"""
        # MSO MDoc validation
        if self.format == "mso_mdoc":
            # MSO MDoc must use doctype, not vct
            if self.meta and self.meta.vct:
                raise ValueError("MSO MDoc cannot use 'vct' in meta (use 'doctype' instead)")

            # MSO MDoc claim paths must be exactly 2 elements
            if self.claims:
                for constraint in self.claims.claims:
                    if len(constraint.path) != 2:
                        raise ValueError(
                            f"MSO MDoc claim paths must have exactly 2 elements [namespace, claim_name], "
                            f"got: {constraint.path}"
                        )

        # SD-JWT VC validation
        elif self.format == "dc+sd-jwt":
            # SD-JWT VC must use vct, not doctype
            if self.meta and self.meta.doctype:
                raise ValueError("SD-JWT VC cannot use 'doctype' in meta (use 'vct' instead)")

        return self


# ======================
# Credential Sets (AND/OR Logic)
# ======================


class CredentialSet(BaseModel):
    """
    Set of credential queries with AND/OR semantics.

    Attributes:
        options: List of credential query IDs (OR semantics: any one satisfies)
        required: If True, at least one option must be satisfied (AND semantics with other sets)
        purpose: Human-readable purpose for requesting these credentials
    """

    options: List[Annotated[QueryId, BeforeValidator(parse_query_id)]] = Field(..., min_items=1, description="Query IDs with OR semantics")
    required: bool = Field(True, description="Whether this set is required")
    purpose: Optional[str] = Field(None, description="Purpose for requesting credentials")

    @field_validator("options")
    @classmethod
    def validate_unique_options(cls, v: List[QueryId]) -> List[QueryId]:
        """Ensure no duplicate query IDs in options"""
        seen: Set[str] = set()
        for query_id in v:
            if query_id.value in seen:
                raise ValueError(f"Duplicate query ID in options: {query_id.value}")
            seen.add(query_id.value)
        return v


# ======================
# Root DCQL Model
# ======================


class DCQL(BaseModel):
    """
    Root Digital Credential Query Language model.

    Defines what credentials and claims the verifier is requesting from the wallet.

    Attributes:
        credentials: List of credential queries (defines available credentials)
        credential_sets: List of credential sets (defines required combinations)
    """

    credentials: List[CredentialQuery] = Field(..., min_items=1, description="Credential queries")
    credential_sets: Optional[List[CredentialSet]] = Field(None, description="Credential sets with AND/OR logic")

    @field_validator("credentials")
    @classmethod
    def validate_unique_credential_ids(cls, v: List[CredentialQuery]) -> List[CredentialQuery]:
        """Ensure all credential query IDs are unique"""
        seen: Set[str] = set()
        for query in v:
            if query.id.value in seen:
                raise ValueError(f"Duplicate credential query ID: {query.id.value}")
            seen.add(query.id.value)
        return v

    @model_validator(mode="after")
    def validate_credential_sets_reference_valid_queries(self) -> "DCQL":
        """Ensure credential_sets only reference existing credential query IDs"""
        if not self.credential_sets:
            return self

        # Build set of valid query IDs
        valid_ids = {query.id.value for query in self.credentials}

        # Check all credential_sets references
        for i, cred_set in enumerate(self.credential_sets):
            for option in cred_set.options:
                if option.value not in valid_ids:
                    raise ValueError(
                        f"credential_sets[{i}] references non-existent query ID: {option.value}. "
                        f"Valid IDs are: {valid_ids}"
                    )

        return self

    @field_validator("credential_sets")
    @classmethod
    def validate_credential_sets_not_empty(cls, v: Optional[List[CredentialSet]]) -> Optional[List[CredentialSet]]:
        """Ensure credential_sets is None or non-empty list"""
        if v is not None and len(v) == 0:
            raise ValueError("credential_sets must be None or contain at least one set")
        return v

    def get_credential_query(self, query_id: QueryId) -> Optional[CredentialQuery]:
        """
        Retrieve credential query by ID.

        Args:
            query_id: Query identifier

        Returns:
            CredentialQuery if found, None otherwise
        """
        for query in self.credentials:
            if query.id == query_id:
                return query
        return None

    def get_required_query_ids(self) -> Set[QueryId]:
        """
        Get all required credential query IDs.

        If credential_sets is None, all credentials are optional.
        If credential_sets is defined, returns all options from required sets.

        Returns:
            Set of required query IDs
        """
        if not self.credential_sets:
            return set()

        required_ids: Set[QueryId] = set()
        for cred_set in self.credential_sets:
            if cred_set.required:
                required_ids.update(cred_set.options)

        return required_ids

    def is_query_required(self, query_id: QueryId) -> bool:
        """
        Check if a credential query is required.

        Args:
            query_id: Query identifier

        Returns:
            True if query is in a required credential set
        """
        return query_id in self.get_required_query_ids()

    def get_all_formats(self) -> Set[str]:
        """
        Get all credential formats referenced in this DCQL.

        Returns:
            Set of format strings
        """
        return {query.format for query in self.credentials}

    def get_queries_by_format(self, format: str) -> List[CredentialQuery]:
        """
        Get all credential queries for a specific format.

        Args:
            format: Credential format (mso_mdoc, dc+sd-jwt, etc.)

        Returns:
            List of matching credential queries
        """
        return [query for query in self.credentials if query.format == format]


# ======================
# Factory Functions
# ======================


def create_simple_dcql(
    format: Literal["mso_mdoc", "dc+sd-jwt", "jwt_vc_json"],
    query_id: str,
    doctype: Optional[str] = None,
    vct: Optional[str] = None,
    claim_paths: Optional[List[List[str]]] = None,
) -> DCQL:
    """
    Create a simple DCQL with a single credential query.

    Convenience factory for common use case of requesting one credential type.

    Args:
        format: Credential format
        query_id: Unique identifier for the query
        doctype: Document type (for MSO MDoc)
        vct: Verifiable Credential Type (for SD-JWT VC)
        claim_paths: Optional list of claim paths to request

    Returns:
        DCQL instance
    """
    # Build meta
    meta = None
    if doctype or vct:
        meta = CredentialMeta(
            doctype=[doctype] if doctype else None,
            vct=[vct] if vct else None,
        )

    # Build claims
    claims = None
    if claim_paths:
        claim_constraints = [ClaimConstraint(path=path) for path in claim_paths]
        claims = ClaimsQuery(claims=claim_constraints)

    # Build credential query
    credential_query = CredentialQuery(
        id=QueryId(value=query_id),
        format=format,
        meta=meta,
        claims=claims,
    )

    return DCQL(credentials=[credential_query])


def create_mdoc_pid_query(query_id: str = "pid") -> DCQL:
    """
    Create DCQL for EU Digital Identity (PID) in MSO MDoc format.

    Requests common PID claims from the eu.europa.ec.eudi.pid.1 namespace.

    Args:
        query_id: Unique identifier for the query

    Returns:
        DCQL instance for PID request
    """
    return create_simple_dcql(
        format="mso_mdoc",
        query_id=query_id,
        doctype="eu.europa.ec.eudi.pid.1",
        claim_paths=[
            ["eu.europa.ec.eudi.pid.1", "family_name"],
            ["eu.europa.ec.eudi.pid.1", "given_name"],
            ["eu.europa.ec.eudi.pid.1", "birth_date"],
            ["eu.europa.ec.eudi.pid.1", "age_over_18"],
            ["eu.europa.ec.eudi.pid.1", "issuance_date"],
            ["eu.europa.ec.eudi.pid.1", "expiry_date"],
            ["eu.europa.ec.eudi.pid.1", "issuing_country"],
        ],
    )


def create_sd_jwt_vc_query(query_id: str, vct: str, claim_paths: Optional[List[List[str]]] = None) -> DCQL:
    """
    Create DCQL for SD-JWT VC credential.

    Args:
        query_id: Unique identifier for the query
        vct: Verifiable Credential Type
        claim_paths: Optional list of claim paths

    Returns:
        DCQL instance for SD-JWT VC request
    """
    return create_simple_dcql(
        format="dc+sd-jwt",
        query_id=query_id,
        vct=vct,
        claim_paths=claim_paths,
    )
