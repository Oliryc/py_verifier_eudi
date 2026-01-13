"""Tests for WalletResponse models"""

import pytest
from pydantic import ValidationError

from eudi_verifier.domain import (
    VpTokenStr,
    VpTokenArray,
    PresentationSubmission,
    WalletResponseVpToken,
    WalletResponseError,
    ValidationError as DomainValidationError,
    InvalidFormat,
    UnsupportedFormat,
    InvalidSignature,
    UntrustedIssuer,
    CredentialExpired,
    CredentialRevoked,
    InvalidNonce,
    MissingRequiredClaim,
    DcqlNotSatisfied,
    InvalidKeyBinding,
    create_vp_token_response,
    create_error_response,
    is_successful_response,
    is_error_response,
)


class TestVpTokenStr:
    """Tests for VpTokenStr"""

    def test_create_vp_token_str(self):
        """Can create VpTokenStr with valid value"""
        vp = VpTokenStr(value="eyJhbGciOiJSUzI1NiJ9...")
        assert vp.value.startswith("eyJ")

    def test_blank_value_raises_error(self):
        """Blank value raises ValueError"""
        with pytest.raises(ValueError, match="cannot be blank"):
            VpTokenStr(value="")

    def test_immutable(self):
        """VpTokenStr is immutable"""
        vp = VpTokenStr(value="test")
        with pytest.raises(Exception):
            vp.value = "modified"


class TestVpTokenArray:
    """Tests for VpTokenArray"""

    def test_create_vp_token_array(self):
        """Can create VpTokenArray with multiple VPs"""
        vp = VpTokenArray(values=["vp1", "vp2", "vp3"])
        assert len(vp.values) == 3

    def test_empty_array_raises_error(self):
        """Empty array raises ValueError"""
        with pytest.raises(ValueError, match="cannot be empty"):
            VpTokenArray(values=[])

    def test_blank_element_raises_error(self):
        """Blank element raises ValueError"""
        with pytest.raises(ValueError, match="cannot be blank"):
            VpTokenArray(values=["vp1", "", "vp3"])

    def test_immutable(self):
        """VpTokenArray is immutable"""
        vp = VpTokenArray(values=["vp1", "vp2"])
        with pytest.raises(Exception):
            vp.values = ["modified"]


class TestPresentationSubmission:
    """Tests for PresentationSubmission"""

    def test_create_presentation_submission(self):
        """Can create PresentationSubmission"""
        ps = PresentationSubmission(
            id="submission_1",
            definition_id="def_1",
            descriptor_map=[{"id": "input_1", "format": "jwt_vc", "path": "$.verifiableCredential[0]"}],
        )
        assert ps.id == "submission_1"
        assert ps.definition_id == "def_1"

    def test_blank_id_raises_error(self):
        """Blank id raises ValidationError"""
        with pytest.raises(ValidationError):
            PresentationSubmission(id="", definition_id="def_1", descriptor_map=[{"id": "test"}])

    def test_empty_descriptor_map_raises_error(self):
        """Empty descriptor_map raises ValidationError"""
        with pytest.raises(ValidationError):
            PresentationSubmission(id="sub_1", definition_id="def_1", descriptor_map=[])


class TestWalletResponseVpToken:
    """Tests for WalletResponseVpToken"""

    def test_create_with_single_vp(self):
        """Can create with single VP token"""
        vp = VpTokenStr(value="eyJ...")
        response = WalletResponseVpToken(vp_token=vp, presentation_submission=None, state="state_123")
        assert response.state == "state_123"

    def test_create_with_multiple_vps(self):
        """Can create with multiple VP tokens"""
        vp = VpTokenArray(values=["vp1", "vp2"])
        response = WalletResponseVpToken(vp_token=vp, presentation_submission=None, state="state_123")
        assert isinstance(response.vp_token, VpTokenArray)

    def test_with_presentation_submission(self):
        """Can create with presentation_submission"""
        vp = VpTokenStr(value="eyJ...")
        ps = PresentationSubmission(id="sub_1", definition_id="def_1", descriptor_map=[{"id": "test"}])
        response = WalletResponseVpToken(vp_token=vp, presentation_submission=ps, state="state_123")
        assert response.presentation_submission == ps

    def test_blank_state_raises_error(self):
        """Blank state raises ValueError"""
        vp = VpTokenStr(value="eyJ...")
        with pytest.raises(ValueError, match="cannot be blank"):
            WalletResponseVpToken(vp_token=vp, presentation_submission=None, state="")

    def test_get_vp_tokens_as_list_single(self):
        """get_vp_tokens_as_list returns list for single VP"""
        vp = VpTokenStr(value="eyJ...")
        response = WalletResponseVpToken(vp_token=vp, presentation_submission=None, state="state_123")
        result = response.get_vp_tokens_as_list()
        assert result == ["eyJ..."]

    def test_get_vp_tokens_as_list_array(self):
        """get_vp_tokens_as_list returns list for array VP"""
        vp = VpTokenArray(values=["vp1", "vp2", "vp3"])
        response = WalletResponseVpToken(vp_token=vp, presentation_submission=None, state="state_123")
        result = response.get_vp_tokens_as_list()
        assert result == ["vp1", "vp2", "vp3"]


class TestWalletResponseError:
    """Tests for WalletResponseError"""

    def test_create_error_response(self):
        """Can create WalletResponseError"""
        error = WalletResponseError(error="access_denied", error_description="User denied", state="state_123")
        assert error.error == "access_denied"
        assert error.error_description == "User denied"

    def test_blank_error_raises_error(self):
        """Blank error raises ValueError"""
        with pytest.raises(ValueError, match="cannot be blank"):
            WalletResponseError(error="", error_description=None, state="state_123")

    def test_blank_state_raises_error(self):
        """Blank state raises ValueError"""
        with pytest.raises(ValueError, match="cannot be blank"):
            WalletResponseError(error="access_denied", error_description=None, state="")

    def test_is_user_cancelled_true(self):
        """is_user_cancelled returns True for user cancellation errors"""
        error1 = WalletResponseError(error="access_denied", error_description=None, state="state_123")
        assert error1.is_user_cancelled()

        error2 = WalletResponseError(error="consent_required", error_description=None, state="state_123")
        assert error2.is_user_cancelled()

    def test_is_user_cancelled_false(self):
        """is_user_cancelled returns False for other errors"""
        error = WalletResponseError(error="invalid_request", error_description=None, state="state_123")
        assert not error.is_user_cancelled()


class TestValidationErrors:
    """Tests for validation error types"""

    def test_invalid_format(self):
        """InvalidFormat error"""
        error = InvalidFormat(format="invalid_format")
        assert "Invalid VP format" in error.message
        assert "invalid_format" in error.message

    def test_unsupported_format(self):
        """UnsupportedFormat error"""
        error = UnsupportedFormat(format="jwt_vc_json")
        assert "Unsupported VP format" in error.message

    def test_invalid_signature(self):
        """InvalidSignature error"""
        error = InvalidSignature(reason="Key not found")
        assert "Invalid signature" in error.message
        assert "Key not found" in error.message

    def test_untrusted_issuer(self):
        """UntrustedIssuer error"""
        error = UntrustedIssuer(issuer="did:web:untrusted.com")
        assert "Untrusted issuer" in error.message
        assert "did:web:untrusted.com" in error.message

    def test_credential_expired(self):
        """CredentialExpired error"""
        error = CredentialExpired(expiry_date="2024-01-01")
        assert "expired" in error.message.lower()
        assert "2024-01-01" in error.message

    def test_credential_revoked_with_date(self):
        """CredentialRevoked error with revocation date"""
        error = CredentialRevoked(revocation_date="2024-06-15")
        assert "revoked" in error.message.lower()
        assert "2024-06-15" in error.message

    def test_credential_revoked_without_date(self):
        """CredentialRevoked error without revocation date"""
        error = CredentialRevoked()
        assert "revoked" in error.message.lower()

    def test_invalid_nonce(self):
        """InvalidNonce error"""
        error = InvalidNonce(expected="nonce_123", actual="nonce_456")
        assert "mismatch" in error.message.lower()
        assert "nonce_123" in error.message
        assert "nonce_456" in error.message

    def test_missing_required_claim(self):
        """MissingRequiredClaim error"""
        error = MissingRequiredClaim(claim_path=["address", "street"])
        assert "Missing required claim" in error.message
        assert "address -> street" in error.message

    def test_dcql_not_satisfied(self):
        """DcqlNotSatisfied error"""
        error = DcqlNotSatisfied(query_id="query_1", reason="No matching credential")
        assert "query_1" in error.message
        assert "not satisfied" in error.message
        assert "No matching credential" in error.message

    def test_invalid_key_binding(self):
        """InvalidKeyBinding error"""
        error = InvalidKeyBinding(reason="Signature verification failed")
        assert "Invalid key binding" in error.message
        assert "Signature verification failed" in error.message

    def test_validation_error_with_details(self):
        """ValidationError can have details"""
        error = DomainValidationError(message="Test error", details={"key": "value"})
        assert error.message == "Test error"
        assert error.details == {"key": "value"}


class TestFactoryFunctions:
    """Tests for factory functions"""

    def test_create_vp_token_response_with_string(self):
        """create_vp_token_response creates response with string VP"""
        response = create_vp_token_response(vp_token="eyJ...", state="state_123")

        assert isinstance(response, WalletResponseVpToken)
        assert isinstance(response.vp_token, VpTokenStr)
        assert response.state == "state_123"

    def test_create_vp_token_response_with_list(self):
        """create_vp_token_response creates response with list of VPs"""
        response = create_vp_token_response(vp_token=["vp1", "vp2"], state="state_123")

        assert isinstance(response, WalletResponseVpToken)
        assert isinstance(response.vp_token, VpTokenArray)

    def test_create_vp_token_response_with_submission(self):
        """create_vp_token_response can include presentation_submission"""
        ps = PresentationSubmission(id="sub_1", definition_id="def_1", descriptor_map=[{"id": "test"}])
        response = create_vp_token_response(vp_token="eyJ...", state="state_123", presentation_submission=ps)

        assert response.presentation_submission == ps

    def test_create_error_response(self):
        """create_error_response creates error response"""
        response = create_error_response(error="access_denied", state="state_123", error_description="User denied")

        assert isinstance(response, WalletResponseError)
        assert response.error == "access_denied"
        assert response.error_description == "User denied"

    def test_is_successful_response_true(self):
        """is_successful_response returns True for VpToken response"""
        response = create_vp_token_response(vp_token="eyJ...", state="state_123")
        assert is_successful_response(response)

    def test_is_successful_response_false(self):
        """is_successful_response returns False for error response"""
        response = create_error_response(error="access_denied", state="state_123")
        assert not is_successful_response(response)

    def test_is_error_response_true(self):
        """is_error_response returns True for error response"""
        response = create_error_response(error="access_denied", state="state_123")
        assert is_error_response(response)

    def test_is_error_response_false(self):
        """is_error_response returns False for VpToken response"""
        response = create_vp_token_response(vp_token="eyJ...", state="state_123")
        assert not is_error_response(response)
