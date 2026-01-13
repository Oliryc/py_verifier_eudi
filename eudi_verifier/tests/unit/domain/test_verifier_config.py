"""Tests for VerifierConfig and related models"""

import pytest
from pydantic import ValidationError

from eudi_verifier.domain import (
    SigningConfig,
    PreRegisteredClientId,
    X509SanDnsClientId,
    X509HashClientId,
    SdJwtVcConfig,
    MsoMdocConfig,
    VpFormatsSupported,
    ResponseEncryption,
    ClientMetaData,
    VerifierConfig,
)


class TestSigningConfig:
    """Tests for SigningConfig"""

    def test_create_valid_signing_config(self, sample_jwk: dict):
        """Can create valid SigningConfig"""
        config = SigningConfig(algorithm="RS256", jwk=sample_jwk)
        assert config.algorithm == "RS256"
        assert config.jwk == sample_jwk

    def test_valid_algorithms(self, sample_jwk: dict):
        """Accepts all valid JWT signing algorithms"""
        valid_algs = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"]
        for alg in valid_algs:
            config = SigningConfig(algorithm=alg, jwk=sample_jwk)
            assert config.algorithm == alg

    def test_invalid_algorithm_raises_error(self, sample_jwk: dict):
        """Invalid algorithm raises ValidationError"""
        with pytest.raises(ValidationError, match="Invalid signing algorithm"):
            SigningConfig(algorithm="HS256", jwk=sample_jwk)

    def test_jwk_must_have_kty(self):
        """JWK must contain 'kty' field"""
        with pytest.raises(ValidationError, match="must contain 'kty'"):
            SigningConfig(algorithm="RS256", jwk={"use": "sig"})

    def test_jwk_use_validation(self, sample_jwk: dict):
        """JWK 'use' must be 'sig' or 'enc'"""
        valid_jwk = {**sample_jwk, "use": "sig"}
        config = SigningConfig(algorithm="RS256", jwk=valid_jwk)
        assert config.jwk["use"] == "sig"

        invalid_jwk = {**sample_jwk, "use": "invalid"}
        with pytest.raises(ValidationError, match="must be 'sig' or 'enc'"):
            SigningConfig(algorithm="RS256", jwk=invalid_jwk)

    def test_with_certificate_chain(self, sample_jwk: dict, sample_certificate: str):
        """Can add certificate chain"""
        config = SigningConfig(algorithm="RS256", jwk=sample_jwk, certificate_chain=[sample_certificate])
        assert len(config.certificate_chain) == 1

    def test_empty_certificate_chain_raises_error(self, sample_jwk: dict):
        """Empty certificate chain raises ValidationError"""
        with pytest.raises(ValidationError, match="at least one certificate"):
            SigningConfig(algorithm="RS256", jwk=sample_jwk, certificate_chain=[])


class TestPreRegisteredClientId:
    """Tests for PreRegisteredClientId"""

    def test_create_valid_client_id(self):
        """Can create PreRegisteredClientId"""
        client_id = PreRegisteredClientId(client_id="https://verifier.example.com")
        assert client_id.scheme == "pre-registered"
        assert client_id.client_id == "https://verifier.example.com"

    def test_get_client_id(self):
        """get_client_id returns the client_id value"""
        client_id = PreRegisteredClientId(client_id="https://verifier.example.com")
        assert client_id.get_client_id() == "https://verifier.example.com"

    def test_blank_client_id_raises_error(self):
        """Blank client_id raises ValueError"""
        with pytest.raises(ValueError, match="cannot be blank"):
            PreRegisteredClientId(client_id="")

    def test_immutable(self):
        """PreRegisteredClientId is immutable"""
        client_id = PreRegisteredClientId(client_id="https://verifier.example.com")
        with pytest.raises(Exception):
            client_id.client_id = "modified"


class TestX509SanDnsClientId:
    """Tests for X509SanDnsClientId"""

    def test_create_with_valid_certificate(self, sample_certificate: str):
        """Can create X509SanDnsClientId with valid certificate"""
        client_id = X509SanDnsClientId(certificate=sample_certificate)
        assert client_id.scheme == "x509_san_dns"
        assert "-----BEGIN CERTIFICATE-----" in client_id.certificate

    def test_blank_certificate_raises_error(self):
        """Blank certificate raises ValueError"""
        with pytest.raises(ValueError, match="cannot be blank"):
            X509SanDnsClientId(certificate="")

    def test_non_pem_certificate_raises_error(self):
        """Non-PEM certificate raises ValueError"""
        with pytest.raises(ValueError, match="must be in PEM format"):
            X509SanDnsClientId(certificate="not a certificate")

    def test_get_client_id_placeholder(self, sample_certificate: str):
        """get_client_id returns placeholder (TODO: implement X.509 parsing)"""
        client_id = X509SanDnsClientId(certificate=sample_certificate)
        result = client_id.get_client_id()
        # Placeholder implementation
        assert result == "placeholder-san-dns"


class TestX509HashClientId:
    """Tests for X509HashClientId"""

    def test_create_with_valid_certificate(self, sample_certificate: str):
        """Can create X509HashClientId with valid certificate"""
        client_id = X509HashClientId(certificate=sample_certificate)
        assert client_id.scheme == "x509_hash"

    def test_get_client_id_placeholder(self, sample_certificate: str):
        """get_client_id returns placeholder hash (TODO: implement hashing)"""
        client_id = X509HashClientId(certificate=sample_certificate)
        result = client_id.get_client_id()
        # Placeholder implementation
        assert result == "sha256-placeholder-hash"

    def test_non_pem_certificate_raises_error(self):
        """Non-PEM certificate raises ValueError"""
        with pytest.raises(ValueError, match="must be in PEM format"):
            X509HashClientId(certificate="invalid")


class TestSdJwtVcConfig:
    """Tests for SdJwtVcConfig"""

    def test_create_valid_config(self):
        """Can create valid SdJwtVcConfig"""
        config = SdJwtVcConfig(
            algorithms=["RS256", "ES256"],
            kb_jwt_algorithms=["RS256", "ES256"],
            check_status=True,
            validate_json_schema=True,
        )
        assert config.algorithms == ["RS256", "ES256"]
        assert config.check_status is True

    def test_empty_algorithms_raises_error(self):
        """Empty algorithms list raises ValidationError"""
        with pytest.raises(ValidationError):
            SdJwtVcConfig(algorithms=[], kb_jwt_algorithms=["RS256"])

    def test_invalid_algorithm_raises_error(self):
        """Invalid algorithm raises ValidationError"""
        with pytest.raises(ValidationError, match="Invalid algorithm"):
            SdJwtVcConfig(algorithms=["HS256"], kb_jwt_algorithms=["RS256"])


class TestMsoMdocConfig:
    """Tests for MsoMdocConfig"""

    def test_create_valid_config(self):
        """Can create valid MsoMdocConfig"""
        config = MsoMdocConfig(
            issuer_auth_algorithms=[-7, -35, -36],
            device_auth_algorithms=[-7, -35],
            check_validity_period=True,
        )
        assert config.issuer_auth_algorithms == [-7, -35, -36]
        assert config.check_validity_period is True

    def test_empty_algorithms_raises_error(self):
        """Empty algorithms list raises ValidationError"""
        with pytest.raises(ValidationError):
            MsoMdocConfig(issuer_auth_algorithms=[], device_auth_algorithms=[-7])

    def test_allows_cose_algorithm_ids(self):
        """Accepts COSE algorithm IDs (negative numbers)"""
        config = MsoMdocConfig(issuer_auth_algorithms=[-7, -35, -36], device_auth_algorithms=[-7])
        assert -7 in config.issuer_auth_algorithms


class TestVpFormatsSupported:
    """Tests for VpFormatsSupported"""

    def test_create_with_both_formats(self):
        """Can create with both SD-JWT VC and MSO MDoc"""
        formats = VpFormatsSupported(
            sd_jwt_vc=SdJwtVcConfig(algorithms=["RS256"], kb_jwt_algorithms=["RS256"]),
            mso_mdoc=MsoMdocConfig(issuer_auth_algorithms=[-7], device_auth_algorithms=[-7]),
        )
        assert formats.sd_jwt_vc is not None
        assert formats.mso_mdoc is not None

    def test_create_with_only_sd_jwt_vc(self):
        """Can create with only SD-JWT VC"""
        formats = VpFormatsSupported(
            sd_jwt_vc=SdJwtVcConfig(algorithms=["RS256"], kb_jwt_algorithms=["RS256"]), mso_mdoc=None
        )
        assert formats.sd_jwt_vc is not None
        assert formats.mso_mdoc is None

    def test_create_with_only_mso_mdoc(self):
        """Can create with only MSO MDoc"""
        formats = VpFormatsSupported(
            sd_jwt_vc=None, mso_mdoc=MsoMdocConfig(issuer_auth_algorithms=[-7], device_auth_algorithms=[-7])
        )
        assert formats.sd_jwt_vc is None
        assert formats.mso_mdoc is not None

    def test_at_least_one_format_required(self):
        """At least one format must be supported"""
        with pytest.raises(ValidationError, match="At least one VP format"):
            VpFormatsSupported(sd_jwt_vc=None, mso_mdoc=None)


class TestResponseEncryption:
    """Tests for ResponseEncryption"""

    def test_create_valid_encryption_config(self):
        """Can create valid ResponseEncryption"""
        config = ResponseEncryption(algorithm="ECDH-ES", encryption_method="A256GCM")
        assert config.algorithm == "ECDH-ES"
        assert config.encryption_method == "A256GCM"

    def test_invalid_algorithm_raises_error(self):
        """Invalid JWE algorithm raises ValidationError"""
        with pytest.raises(ValidationError, match="Invalid JWE algorithm"):
            ResponseEncryption(algorithm="INVALID", encryption_method="A256GCM")

    def test_invalid_encryption_method_raises_error(self):
        """Invalid encryption method raises ValidationError"""
        with pytest.raises(ValidationError, match="Invalid JWE encryption method"):
            ResponseEncryption(algorithm="ECDH-ES", encryption_method="INVALID")

    def test_all_valid_algorithms(self):
        """Accepts all valid JWE algorithms"""
        valid_algs = ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW", "RSA-OAEP", "RSA-OAEP-256"]
        for alg in valid_algs:
            config = ResponseEncryption(algorithm=alg, encryption_method="A256GCM")
            assert config.algorithm == alg


class TestClientMetaData:
    """Tests for ClientMetaData"""

    def test_create_with_jwks(self, sample_jwk: dict):
        """Can create ClientMetaData with jwks"""
        metadata = ClientMetaData(jwks={"keys": [sample_jwk]})
        assert metadata.jwks is not None
        assert metadata.jwks_uri is None

    def test_create_with_jwks_uri(self):
        """Can create ClientMetaData with jwks_uri"""
        metadata = ClientMetaData(jwks_uri="https://verifier.example.com/.well-known/jwks.json")
        assert metadata.jwks_uri is not None
        assert metadata.jwks is None

    def test_jwks_or_jwks_uri_required(self):
        """Either jwks or jwks_uri must be provided"""
        with pytest.raises(ValidationError, match="Either 'jwks' or 'jwks_uri'"):
            ClientMetaData()

    def test_cannot_have_both_jwks_and_jwks_uri(self, sample_jwk: dict):
        """Cannot have both jwks and jwks_uri"""
        with pytest.raises(ValidationError, match="Only one of"):
            ClientMetaData(jwks={"keys": [sample_jwk]}, jwks_uri="https://example.com/jwks")

    def test_with_response_algorithms(self, sample_jwk: dict):
        """Can set response algorithms"""
        metadata = ClientMetaData(
            jwks={"keys": [sample_jwk]},
            authorization_signed_response_alg="RS256",
            authorization_encrypted_response_alg="ECDH-ES",
            authorization_encrypted_response_enc="A256GCM",
        )
        assert metadata.authorization_signed_response_alg == "RS256"


class TestVerifierConfig:
    """Tests for VerifierConfig"""

    def test_create_valid_verifier_config(self, sample_jwk: dict):
        """Can create valid VerifierConfig"""
        config = VerifierConfig(
            verifier_id=PreRegisteredClientId(client_id="https://verifier.example.com"),
            public_url="https://verifier.example.com",
            signing_config=SigningConfig(algorithm="RS256", jwk=sample_jwk),
            vp_formats_supported=VpFormatsSupported(
                sd_jwt_vc=SdJwtVcConfig(algorithms=["RS256"], kb_jwt_algorithms=["RS256"])
            ),
            default_response_mode="direct_post",
            max_age_seconds=3600,
            client_metadata=ClientMetaData(jwks={"keys": [sample_jwk]}),
        )
        assert config.public_url == "https://verifier.example.com"

    def test_get_client_id(self, sample_jwk: dict):
        """get_client_id returns client_id from verifier_id"""
        config = VerifierConfig(
            verifier_id=PreRegisteredClientId(client_id="https://verifier.example.com"),
            public_url="https://verifier.example.com",
            signing_config=SigningConfig(algorithm="RS256", jwk=sample_jwk),
            vp_formats_supported=VpFormatsSupported(
                sd_jwt_vc=SdJwtVcConfig(algorithms=["RS256"], kb_jwt_algorithms=["RS256"])
            ),
            client_metadata=ClientMetaData(jwks={"keys": [sample_jwk]}),
        )
        assert config.get_client_id() == "https://verifier.example.com"

    def test_public_url_must_be_https(self, sample_jwk: dict):
        """public_url must be HTTPS (or http://localhost)"""
        # Valid HTTPS
        config = VerifierConfig(
            verifier_id=PreRegisteredClientId(client_id="https://verifier.example.com"),
            public_url="https://verifier.example.com",
            signing_config=SigningConfig(algorithm="RS256", jwk=sample_jwk),
            vp_formats_supported=VpFormatsSupported(
                sd_jwt_vc=SdJwtVcConfig(algorithms=["RS256"], kb_jwt_algorithms=["RS256"])
            ),
            client_metadata=ClientMetaData(jwks={"keys": [sample_jwk]}),
        )
        assert config.public_url.startswith("https://")

        # Valid localhost HTTP
        config_localhost = VerifierConfig(
            verifier_id=PreRegisteredClientId(client_id="http://localhost:8080"),
            public_url="http://localhost:8080",
            signing_config=SigningConfig(algorithm="RS256", jwk=sample_jwk),
            vp_formats_supported=VpFormatsSupported(
                sd_jwt_vc=SdJwtVcConfig(algorithms=["RS256"], kb_jwt_algorithms=["RS256"])
            ),
            client_metadata=ClientMetaData(jwks={"keys": [sample_jwk]}),
        )
        assert config_localhost.public_url.startswith("http://localhost")

        # Invalid HTTP (non-localhost)
        with pytest.raises(ValidationError, match="must be HTTPS"):
            VerifierConfig(
                verifier_id=PreRegisteredClientId(client_id="http://verifier.example.com"),
                public_url="http://verifier.example.com",
                signing_config=SigningConfig(algorithm="RS256", jwk=sample_jwk),
                vp_formats_supported=VpFormatsSupported(
                    sd_jwt_vc=SdJwtVcConfig(algorithms=["RS256"], kb_jwt_algorithms=["RS256"])
                ),
                client_metadata=ClientMetaData(jwks={"keys": [sample_jwk]}),
            )

    def test_max_age_bounds(self, sample_jwk: dict):
        """max_age_seconds must be between 60 and 86400"""
        # Valid
        config = VerifierConfig(
            verifier_id=PreRegisteredClientId(client_id="https://verifier.example.com"),
            public_url="https://verifier.example.com",
            signing_config=SigningConfig(algorithm="RS256", jwk=sample_jwk),
            vp_formats_supported=VpFormatsSupported(
                sd_jwt_vc=SdJwtVcConfig(algorithms=["RS256"], kb_jwt_algorithms=["RS256"])
            ),
            max_age_seconds=3600,
            client_metadata=ClientMetaData(jwks={"keys": [sample_jwk]}),
        )
        assert config.max_age_seconds == 3600

        # Too small
        with pytest.raises(ValidationError):
            VerifierConfig(
                verifier_id=PreRegisteredClientId(client_id="https://verifier.example.com"),
                public_url="https://verifier.example.com",
                signing_config=SigningConfig(algorithm="RS256", jwk=sample_jwk),
                vp_formats_supported=VpFormatsSupported(
                    sd_jwt_vc=SdJwtVcConfig(algorithms=["RS256"], kb_jwt_algorithms=["RS256"])
                ),
                max_age_seconds=30,
                client_metadata=ClientMetaData(jwks={"keys": [sample_jwk]}),
            )

    def test_direct_post_jwt_requires_encryption(self, sample_jwk: dict):
        """direct_post.jwt mode requires response_encryption"""
        # Without encryption - should fail
        with pytest.raises(ValidationError, match="response_encryption required"):
            VerifierConfig(
                verifier_id=PreRegisteredClientId(client_id="https://verifier.example.com"),
                public_url="https://verifier.example.com",
                signing_config=SigningConfig(algorithm="RS256", jwk=sample_jwk),
                vp_formats_supported=VpFormatsSupported(
                    sd_jwt_vc=SdJwtVcConfig(algorithms=["RS256"], kb_jwt_algorithms=["RS256"])
                ),
                default_response_mode="direct_post.jwt",
                client_metadata=ClientMetaData(jwks={"keys": [sample_jwk]}),
            )

        # With encryption - should succeed
        config = VerifierConfig(
            verifier_id=PreRegisteredClientId(client_id="https://verifier.example.com"),
            public_url="https://verifier.example.com",
            signing_config=SigningConfig(algorithm="RS256", jwk=sample_jwk),
            vp_formats_supported=VpFormatsSupported(
                sd_jwt_vc=SdJwtVcConfig(algorithms=["RS256"], kb_jwt_algorithms=["RS256"])
            ),
            default_response_mode="direct_post.jwt",
            response_encryption=ResponseEncryption(algorithm="ECDH-ES", encryption_method="A256GCM"),
            client_metadata=ClientMetaData(jwks={"keys": [sample_jwk]}),
        )
        assert config.default_response_mode == "direct_post.jwt"

    def test_supports_format(self, sample_jwk: dict):
        """supports_format checks if format is supported"""
        config = VerifierConfig(
            verifier_id=PreRegisteredClientId(client_id="https://verifier.example.com"),
            public_url="https://verifier.example.com",
            signing_config=SigningConfig(algorithm="RS256", jwk=sample_jwk),
            vp_formats_supported=VpFormatsSupported(
                sd_jwt_vc=SdJwtVcConfig(algorithms=["RS256"], kb_jwt_algorithms=["RS256"]),
                mso_mdoc=MsoMdocConfig(issuer_auth_algorithms=[-7], device_auth_algorithms=[-7]),
            ),
            client_metadata=ClientMetaData(jwks={"keys": [sample_jwk]}),
        )

        assert config.supports_format("dc+sd-jwt")
        assert config.supports_format("mso_mdoc")
        assert not config.supports_format("jwt_vc_json")
