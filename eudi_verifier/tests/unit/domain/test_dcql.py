"""Tests for DCQL (Digital Credential Query Language)"""

import pytest
from pydantic import ValidationError

from eudi_verifier.domain import (
    QueryId,
    ClaimId,
    ClaimValue,
    ClaimConstraint,
    ClaimsQuery,
    CredentialMeta,
    CredentialQuery,
    CredentialSet,
    DCQL,
    create_simple_dcql,
    create_mdoc_pid_query,
    create_sd_jwt_vc_query,
)


class TestQueryId:
    """Tests for QueryId value object"""

    def test_create_valid_query_id(self):
        """Can create QueryId with valid value"""
        query_id = QueryId(value="query_123")
        assert query_id.value == "query_123"

    def test_str_representation(self):
        """str() returns the value"""
        query_id = QueryId(value="query_abc")
        assert str(query_id) == "query_abc"

    def test_blank_value_raises_error(self):
        """Blank value raises ValidationError"""
        with pytest.raises(ValidationError):
            QueryId(value="")

    def test_whitespace_only_raises_error(self):
        """Whitespace-only value raises ValidationError"""
        with pytest.raises(ValidationError):
            QueryId(value="   ")

    def test_equality(self):
        """QueryIds with same value are equal"""
        id1 = QueryId(value="query_1")
        id2 = QueryId(value="query_1")
        id3 = QueryId(value="query_2")

        assert id1 == id2
        assert id1 != id3

    def test_hashable(self):
        """QueryId can be used in sets/dicts"""
        id1 = QueryId(value="query_1")
        id2 = QueryId(value="query_1")

        query_set = {id1, id2}
        assert len(query_set) == 1


class TestClaimValue:
    """Tests for ClaimValue constraints"""

    def test_create_with_exact_value(self):
        """Can create ClaimValue with exact value"""
        claim_value = ClaimValue(value="US")
        assert claim_value.value == "US"
        assert claim_value.values is None
        assert claim_value.pattern is None

    def test_create_with_values_list(self):
        """Can create ClaimValue with list of values"""
        claim_value = ClaimValue(values=["US", "CA", "MX"])
        assert claim_value.values == ["US", "CA", "MX"]
        assert claim_value.value is None

    def test_create_with_pattern(self):
        """Can create ClaimValue with regex pattern"""
        claim_value = ClaimValue(pattern="^[A-Z]{2}$")
        assert claim_value.pattern == "^[A-Z]{2}$"
        assert claim_value.value is None

    def test_exactly_one_constraint_required(self):
        """Exactly one of value/values/pattern must be set"""
        # No constraint
        with pytest.raises(ValidationError, match="Exactly one"):
            ClaimValue()

        # Multiple constraints
        with pytest.raises(ValidationError, match="Exactly one"):
            ClaimValue(value="US", values=["US", "CA"])

    def test_empty_values_list_raises_error(self):
        """Empty values list raises ValidationError"""
        with pytest.raises(ValidationError, match="at least one element"):
            ClaimValue(values=[])


class TestClaimConstraint:
    """Tests for ClaimConstraint"""

    def test_create_simple_claim_constraint(self):
        """Can create simple claim constraint"""
        constraint = ClaimConstraint(path=["given_name"])
        assert constraint.path == ["given_name"]
        assert constraint.values is None

    def test_create_nested_path(self):
        """Can create constraint with nested path"""
        constraint = ClaimConstraint(path=["address", "street", "number"])
        assert len(constraint.path) == 3

    def test_create_with_value_constraint(self):
        """Can create constraint with value requirements"""
        claim_value = ClaimValue(value="US")
        constraint = ClaimConstraint(path=["country"], values=claim_value)
        assert constraint.values == claim_value

    def test_empty_path_raises_error(self):
        """Empty path raises ValidationError"""
        with pytest.raises(ValidationError):
            ClaimConstraint(path=[])

    def test_blank_path_element_raises_error(self):
        """Blank path element raises ValidationError"""
        with pytest.raises(ValidationError, match="cannot be blank"):
            ClaimConstraint(path=["address", "", "street"])

    def test_with_intent_to_retain(self):
        """Can set intent_to_retain"""
        constraint = ClaimConstraint(path=["ssn"], intent_to_retain=True, purpose="For verification")
        assert constraint.intent_to_retain is True
        assert constraint.purpose == "For verification"


class TestClaimsQuery:
    """Tests for ClaimsQuery"""

    def test_create_claims_query(self):
        """Can create ClaimsQuery with constraints"""
        constraints = [
            ClaimConstraint(path=["given_name"]),
            ClaimConstraint(path=["family_name"]),
        ]
        query = ClaimsQuery(claims=constraints)
        assert len(query.claims) == 2

    def test_create_with_id(self):
        """Can create ClaimsQuery with ID"""
        constraints = [ClaimConstraint(path=["age"])]
        query = ClaimsQuery(id=ClaimId(value="claims_1"), claims=constraints)
        assert query.id.value == "claims_1"

    def test_empty_claims_list_raises_error(self):
        """Empty claims list raises ValidationError"""
        with pytest.raises(ValidationError):
            ClaimsQuery(claims=[])

    def test_duplicate_claim_paths_raises_error(self):
        """Duplicate claim paths raise ValidationError"""
        constraints = [
            ClaimConstraint(path=["given_name"]),
            ClaimConstraint(path=["family_name"]),
            ClaimConstraint(path=["given_name"]),  # Duplicate
        ]
        with pytest.raises(ValidationError, match="Duplicate claim path"):
            ClaimsQuery(claims=constraints)


class TestCredentialMeta:
    """Tests for CredentialMeta"""

    def test_create_with_vct(self):
        """Can create meta with vct for SD-JWT VC"""
        meta = CredentialMeta(vct=["https://example.com/vc/pid"])
        assert meta.vct == ["https://example.com/vc/pid"]
        assert meta.doctype is None

    def test_create_with_doctype(self):
        """Can create meta with doctype for MSO MDoc"""
        meta = CredentialMeta(doctype=["eu.europa.ec.eudi.pid.1"])
        assert meta.doctype == ["eu.europa.ec.eudi.pid.1"]
        assert meta.vct is None

    def test_create_with_issuer_trust_list(self):
        """Can create meta with trusted issuers"""
        meta = CredentialMeta(issuer_trust_list=["did:web:issuer1.com", "did:web:issuer2.com"])
        assert len(meta.issuer_trust_list) == 2

    def test_empty_lists_raise_error(self):
        """Empty lists raise ValidationError"""
        with pytest.raises(ValidationError, match="at least one element"):
            CredentialMeta(vct=[])


class TestCredentialQuery:
    """Tests for CredentialQuery"""

    def test_create_mso_mdoc_query(self):
        """Can create MSO MDoc credential query"""
        query = CredentialQuery(
            id=QueryId(value="mdoc_1"),
            format="mso_mdoc",
            meta=CredentialMeta(doctype=["org.iso.18013.5.1.mDL"]),
            claims=ClaimsQuery(claims=[ClaimConstraint(path=["org.iso.18013.5.1", "family_name"])]),
        )
        assert query.format == "mso_mdoc"

    def test_create_sd_jwt_vc_query(self):
        """Can create SD-JWT VC credential query"""
        query = CredentialQuery(
            id=QueryId(value="sdjwt_1"),
            format="dc+sd-jwt",
            meta=CredentialMeta(vct=["https://example.com/pid"]),
            claims=ClaimsQuery(claims=[ClaimConstraint(path=["given_name"])]),
        )
        assert query.format == "dc+sd-jwt"

    def test_mso_mdoc_with_vct_raises_error(self):
        """MSO MDoc cannot use vct in meta"""
        with pytest.raises(ValidationError, match="cannot use 'vct'"):
            CredentialQuery(
                id=QueryId(value="mdoc_1"),
                format="mso_mdoc",
                meta=CredentialMeta(vct=["invalid"]),
            )

    def test_sd_jwt_vc_with_doctype_raises_error(self):
        """SD-JWT VC cannot use doctype in meta"""
        with pytest.raises(ValidationError, match="cannot use 'doctype'"):
            CredentialQuery(
                id=QueryId(value="sdjwt_1"),
                format="dc+sd-jwt",
                meta=CredentialMeta(doctype=["invalid"]),
            )

    def test_mso_mdoc_claim_paths_must_be_two_elements(self):
        """MSO MDoc claim paths must be exactly [namespace, claim_name]"""
        # Valid 2-element path
        query = CredentialQuery(
            id=QueryId(value="mdoc_1"),
            format="mso_mdoc",
            claims=ClaimsQuery(claims=[ClaimConstraint(path=["org.iso.18013.5.1", "family_name"])]),
        )
        assert query is not None

        # Invalid 1-element path
        with pytest.raises(ValidationError, match="exactly 2 elements"):
            CredentialQuery(
                id=QueryId(value="mdoc_2"),
                format="mso_mdoc",
                claims=ClaimsQuery(claims=[ClaimConstraint(path=["family_name"])]),
            )

        # Invalid 3-element path
        with pytest.raises(ValidationError, match="exactly 2 elements"):
            CredentialQuery(
                id=QueryId(value="mdoc_3"),
                format="mso_mdoc",
                claims=ClaimsQuery(claims=[ClaimConstraint(path=["ns", "claim", "extra"])]),
            )

    def test_sd_jwt_vc_allows_any_path_length(self):
        """SD-JWT VC allows nested claim paths"""
        query = CredentialQuery(
            id=QueryId(value="sdjwt_1"),
            format="dc+sd-jwt",
            claims=ClaimsQuery(
                claims=[
                    ClaimConstraint(path=["given_name"]),  # 1 element
                    ClaimConstraint(path=["address", "street"]),  # 2 elements
                    ClaimConstraint(path=["address", "city", "name"]),  # 3 elements
                ]
            ),
        )
        assert query is not None


class TestCredentialSet:
    """Tests for CredentialSet"""

    def test_create_credential_set(self):
        """Can create credential set with options"""
        cred_set = CredentialSet(
            options=[QueryId(value="query_1"), QueryId(value="query_2")], required=True, purpose="Age verification"
        )
        assert len(cred_set.options) == 2
        assert cred_set.required is True

    def test_empty_options_raises_error(self):
        """Empty options list raises ValidationError"""
        with pytest.raises(ValidationError):
            CredentialSet(options=[])

    def test_duplicate_query_ids_raises_error(self):
        """Duplicate query IDs in options raise ValidationError"""
        with pytest.raises(ValidationError, match="Duplicate query ID"):
            CredentialSet(
                options=[
                    QueryId(value="query_1"),
                    QueryId(value="query_2"),
                    QueryId(value="query_1"),  # Duplicate
                ]
            )

    def test_optional_credential_set(self):
        """Can create optional credential set"""
        cred_set = CredentialSet(options=[QueryId(value="query_1")], required=False)
        assert cred_set.required is False


class TestDCQL:
    """Tests for DCQL root model"""

    def test_create_simple_dcql(self):
        """Can create simple DCQL with one credential"""
        dcql = DCQL(
            credentials=[
                CredentialQuery(
                    id=QueryId(value="query_1"),
                    format="dc+sd-jwt",
                    meta=CredentialMeta(vct=["https://example.com/pid"]),
                )
            ]
        )
        assert len(dcql.credentials) == 1

    def test_empty_credentials_raises_error(self):
        """Empty credentials list raises ValidationError"""
        with pytest.raises(ValidationError):
            DCQL(credentials=[])

    def test_duplicate_credential_ids_raises_error(self):
        """Duplicate credential query IDs raise ValidationError"""
        with pytest.raises(ValidationError, match="Duplicate credential query ID"):
            DCQL(
                credentials=[
                    CredentialQuery(id=QueryId(value="query_1"), format="dc+sd-jwt"),
                    CredentialQuery(id=QueryId(value="query_2"), format="mso_mdoc"),
                    CredentialQuery(id=QueryId(value="query_1"), format="dc+sd-jwt"),  # Duplicate
                ]
            )

    def test_credential_sets_reference_valid_queries(self):
        """credential_sets must reference existing query IDs"""
        dcql = DCQL(
            credentials=[
                CredentialQuery(id=QueryId(value="query_1"), format="dc+sd-jwt"),
                CredentialQuery(id=QueryId(value="query_2"), format="mso_mdoc"),
            ],
            credential_sets=[
                CredentialSet(options=[QueryId(value="query_1")]),
                CredentialSet(options=[QueryId(value="query_1"), QueryId(value="query_2")]),
            ],
        )
        assert len(dcql.credential_sets) == 2

    def test_credential_sets_invalid_reference_raises_error(self):
        """credential_sets referencing non-existent query raises ValidationError"""
        with pytest.raises(ValidationError, match="non-existent query ID"):
            DCQL(
                credentials=[
                    CredentialQuery(id=QueryId(value="query_1"), format="dc+sd-jwt"),
                ],
                credential_sets=[
                    CredentialSet(options=[QueryId(value="query_1")]),
                    CredentialSet(options=[QueryId(value="query_999")]),  # Invalid reference
                ],
            )

    def test_get_credential_query(self):
        """get_credential_query returns query by ID"""
        query1 = CredentialQuery(id=QueryId(value="query_1"), format="dc+sd-jwt")
        query2 = CredentialQuery(id=QueryId(value="query_2"), format="mso_mdoc")
        dcql = DCQL(credentials=[query1, query2])

        result = dcql.get_credential_query(QueryId(value="query_1"))
        assert result == query1

        result = dcql.get_credential_query(QueryId(value="query_999"))
        assert result is None

    def test_get_required_query_ids_with_no_sets(self):
        """get_required_query_ids returns empty set when no credential_sets"""
        dcql = DCQL(
            credentials=[
                CredentialQuery(id=QueryId(value="query_1"), format="dc+sd-jwt"),
            ]
        )
        assert dcql.get_required_query_ids() == set()

    def test_get_required_query_ids_with_sets(self):
        """get_required_query_ids returns IDs from required sets"""
        dcql = DCQL(
            credentials=[
                CredentialQuery(id=QueryId(value="query_1"), format="dc+sd-jwt"),
                CredentialQuery(id=QueryId(value="query_2"), format="mso_mdoc"),
                CredentialQuery(id=QueryId(value="query_3"), format="dc+sd-jwt"),
            ],
            credential_sets=[
                CredentialSet(options=[QueryId(value="query_1")], required=True),
                CredentialSet(options=[QueryId(value="query_2"), QueryId(value="query_3")], required=True),
                CredentialSet(options=[QueryId(value="query_3")], required=False),  # Optional
            ],
        )

        required = dcql.get_required_query_ids()
        assert QueryId(value="query_1") in required
        assert QueryId(value="query_2") in required
        assert QueryId(value="query_3") in required

    def test_is_query_required(self):
        """is_query_required checks if query is in required set"""
        dcql = DCQL(
            credentials=[
                CredentialQuery(id=QueryId(value="query_1"), format="dc+sd-jwt"),
                CredentialQuery(id=QueryId(value="query_2"), format="mso_mdoc"),
            ],
            credential_sets=[CredentialSet(options=[QueryId(value="query_1")], required=True)],
        )

        assert dcql.is_query_required(QueryId(value="query_1"))
        assert not dcql.is_query_required(QueryId(value="query_2"))

    def test_get_all_formats(self):
        """get_all_formats returns all unique formats"""
        dcql = DCQL(
            credentials=[
                CredentialQuery(id=QueryId(value="query_1"), format="dc+sd-jwt"),
                CredentialQuery(id=QueryId(value="query_2"), format="mso_mdoc"),
                CredentialQuery(id=QueryId(value="query_3"), format="dc+sd-jwt"),
            ]
        )

        formats = dcql.get_all_formats()
        assert formats == {"dc+sd-jwt", "mso_mdoc"}

    def test_get_queries_by_format(self):
        """get_queries_by_format returns matching queries"""
        query1 = CredentialQuery(id=QueryId(value="query_1"), format="dc+sd-jwt")
        query2 = CredentialQuery(id=QueryId(value="query_2"), format="mso_mdoc")
        query3 = CredentialQuery(id=QueryId(value="query_3"), format="dc+sd-jwt")

        dcql = DCQL(credentials=[query1, query2, query3])

        sd_jwt_queries = dcql.get_queries_by_format("dc+sd-jwt")
        assert len(sd_jwt_queries) == 2
        assert query1 in sd_jwt_queries
        assert query3 in sd_jwt_queries

        mdoc_queries = dcql.get_queries_by_format("mso_mdoc")
        assert len(mdoc_queries) == 1
        assert query2 in mdoc_queries


class TestFactoryFunctions:
    """Tests for DCQL factory functions"""

    def test_create_simple_dcql(self):
        """create_simple_dcql creates valid DCQL"""
        dcql = create_simple_dcql(
            format="dc+sd-jwt",
            query_id="query_1",
            vct="https://example.com/pid",
            claim_paths=[["given_name"], ["family_name"]],
        )

        assert len(dcql.credentials) == 1
        assert dcql.credentials[0].id.value == "query_1"
        assert dcql.credentials[0].format == "dc+sd-jwt"
        assert dcql.credentials[0].meta.vct == ["https://example.com/pid"]
        assert len(dcql.credentials[0].claims.claims) == 2

    def test_create_mdoc_pid_query(self):
        """create_mdoc_pid_query creates PID MSO MDoc query"""
        dcql = create_mdoc_pid_query("pid_query")

        assert len(dcql.credentials) == 1
        query = dcql.credentials[0]
        assert query.id.value == "pid_query"
        assert query.format == "mso_mdoc"
        assert query.meta.doctype == ["eu.europa.ec.eudi.pid.1"]
        assert len(query.claims.claims) == 7  # 7 PID claims

        # Verify all paths are 2 elements (MSO MDoc format)
        for claim in query.claims.claims:
            assert len(claim.path) == 2

    def test_create_sd_jwt_vc_query(self):
        """create_sd_jwt_vc_query creates SD-JWT VC query"""
        dcql = create_sd_jwt_vc_query(query_id="vc_1", vct="https://example.com/diploma", claim_paths=[["degree"]])

        assert len(dcql.credentials) == 1
        query = dcql.credentials[0]
        assert query.id.value == "vc_1"
        assert query.format == "dc+sd-jwt"
        assert query.meta.vct == ["https://example.com/diploma"]
        assert len(query.claims.claims) == 1
