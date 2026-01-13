"""Tests for domain value objects"""

import pytest

from eudi_verifier.domain import (
    TransactionId,
    RequestId,
    Nonce,
    ResponseCode,
    Format,
    RequestUriMethod,
    ResponseModeOption,
)


class TestTransactionId:
    """Tests for TransactionId"""

    def test_create_valid_transaction_id(self):
        """Can create TransactionId with valid value"""
        txn_id = TransactionId(value="txn_123")
        assert txn_id.value == "txn_123"

    def test_str_representation(self):
        """str() returns the value"""
        txn_id = TransactionId(value="txn_abc")
        assert str(txn_id) == "txn_abc"

    def test_immutable(self):
        """TransactionId is immutable"""
        txn_id = TransactionId(value="txn_123")
        with pytest.raises(Exception):  # FrozenInstanceError
            txn_id.value = "txn_456"

    def test_blank_value_raises_error(self):
        """Blank value raises ValueError"""
        with pytest.raises(ValueError, match="cannot be blank"):
            TransactionId(value="")

    def test_whitespace_only_raises_error(self):
        """Whitespace-only value raises ValueError"""
        with pytest.raises(ValueError, match="cannot be blank"):
            TransactionId(value="   ")


class TestRequestId:
    """Tests for RequestId"""

    def test_create_valid_request_id(self):
        """Can create RequestId with valid value"""
        req_id = RequestId(value="req_xyz")
        assert req_id.value == "req_xyz"

    def test_str_representation(self):
        """str() returns the value"""
        req_id = RequestId(value="req_abc")
        assert str(req_id) == "req_abc"

    def test_immutable(self):
        """RequestId is immutable"""
        req_id = RequestId(value="req_123")
        with pytest.raises(Exception):
            req_id.value = "req_456"

    def test_blank_value_raises_error(self):
        """Blank value raises ValueError"""
        with pytest.raises(ValueError, match="cannot be blank"):
            RequestId(value="")


class TestNonce:
    """Tests for Nonce"""

    def test_create_valid_nonce(self):
        """Can create Nonce with valid value"""
        nonce = Nonce(value="abc123xyz")
        assert nonce.value == "abc123xyz"

    def test_str_representation(self):
        """str() returns the value"""
        nonce = Nonce(value="random_nonce")
        assert str(nonce) == "random_nonce"

    def test_immutable(self):
        """Nonce is immutable"""
        nonce = Nonce(value="nonce1")
        with pytest.raises(Exception):
            nonce.value = "nonce2"

    def test_blank_value_raises_error(self):
        """Blank value raises ValueError"""
        with pytest.raises(ValueError, match="cannot be blank"):
            Nonce(value="")


class TestResponseCode:
    """Tests for ResponseCode"""

    def test_create_valid_response_code(self):
        """Can create ResponseCode with valid value"""
        code = ResponseCode(value="code_abc123")
        assert code.value == "code_abc123"

    def test_str_representation(self):
        """str() returns the value"""
        code = ResponseCode(value="response_code")
        assert str(code) == "response_code"

    def test_immutable(self):
        """ResponseCode is immutable"""
        code = ResponseCode(value="code1")
        with pytest.raises(Exception):
            code.value = "code2"

    def test_blank_value_raises_error(self):
        """Blank value raises ValueError"""
        with pytest.raises(ValueError, match="cannot be blank"):
            ResponseCode(value="")


class TestFormat:
    """Tests for Format enum"""

    def test_mso_mdoc_format(self):
        """MSO_MDOC format has correct value"""
        assert Format.MSO_MDOC == "mso_mdoc"
        assert str(Format.MSO_MDOC) == "mso_mdoc"

    def test_sd_jwt_vc_format(self):
        """SD_JWT_VC format has correct value"""
        assert Format.SD_JWT_VC == "dc+sd-jwt"
        assert str(Format.SD_JWT_VC) == "dc+sd-jwt"

    def test_w3c_jwt_vc_format(self):
        """W3C_JWT_VC format has correct value"""
        assert Format.W3C_JWT_VC == "jwt_vc_json"
        assert str(Format.W3C_JWT_VC) == "jwt_vc_json"

    def test_enum_comparison(self):
        """Can compare Format enum values"""
        assert Format.MSO_MDOC == Format.MSO_MDOC
        assert Format.MSO_MDOC != Format.SD_JWT_VC

    def test_can_iterate_formats(self):
        """Can iterate over Format enum"""
        formats = list(Format)
        assert len(formats) == 3
        assert Format.MSO_MDOC in formats
        assert Format.SD_JWT_VC in formats
        assert Format.W3C_JWT_VC in formats


class TestRequestUriMethod:
    """Tests for RequestUriMethod enum"""

    def test_get_method(self):
        """GET method has correct value"""
        assert RequestUriMethod.GET == "get"

    def test_post_method(self):
        """POST method has correct value"""
        assert RequestUriMethod.POST == "post"

    def test_enum_comparison(self):
        """Can compare RequestUriMethod enum values"""
        assert RequestUriMethod.GET != RequestUriMethod.POST


class TestResponseModeOption:
    """Tests for ResponseModeOption enum"""

    def test_direct_post(self):
        """DIRECT_POST has correct value"""
        assert ResponseModeOption.DIRECT_POST == "direct_post"

    def test_direct_post_jwt(self):
        """DIRECT_POST_JWT has correct value"""
        assert ResponseModeOption.DIRECT_POST_JWT == "direct_post.jwt"

    def test_enum_comparison(self):
        """Can compare ResponseModeOption enum values"""
        assert ResponseModeOption.DIRECT_POST != ResponseModeOption.DIRECT_POST_JWT
