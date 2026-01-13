"""Configuration loader for EUDI Verifier"""

import json
import os
from pathlib import Path
from typing import Any

from eudi_verifier.domain import (
    ClientMetaData,
    PreRegisteredClientId,
    ResponseEncryption,
    SigningConfig,
    VerifierConfig,
    VerifierId,
    VpFormatsSupported,
    MsoMdocConfig,
    SdJwtVcConfig,
)


def load_config_from_env() -> VerifierConfig | None:
    """
    Load verifier configuration from environment variables.

    Environment variables:
    - VERIFIER_ID: Verifier identifier
    - VERIFIER_SIGNING_KEY: Path to JWK file for signing
    - VERIFIER_SIGNING_ALGORITHM: JWT signing algorithm (default: ES256)
    - VERIFIER_BASE_URL: Base URL for verifier endpoints
    - VERIFIER_CLIENT_ID: Client ID for pre-registered scheme

    Returns:
        VerifierConfig if environment is properly configured, None otherwise
    """
    verifier_id = os.getenv("VERIFIER_ID")
    signing_key_path = os.getenv("VERIFIER_SIGNING_KEY")
    base_url = os.getenv("VERIFIER_BASE_URL")
    client_id = os.getenv("VERIFIER_CLIENT_ID")

    if not all([verifier_id, signing_key_path, base_url, client_id]):
        return None

    # Load signing key
    signing_key_file = Path(signing_key_path)
    if not signing_key_file.exists():
        raise FileNotFoundError(f"Signing key not found: {signing_key_path}")

    with open(signing_key_file, "r") as f:
        signing_key = json.load(f)

    # Create signing config
    algorithm = os.getenv("VERIFIER_SIGNING_ALGORITHM", "ES256")
    signing_config = SigningConfig(
        algorithm=algorithm,
        jwk=signing_key,
        jwk_set_url=None,
        certificate_chain=None,
    )

    # Create client ID scheme
    client_id_scheme = PreRegisteredClientId(client_id=client_id)

    # Create VP formats config
    # COSE algorithm IDs: -7 (ES256), -35 (ES384), -36 (ES512)
    vp_formats = VpFormatsSupported(
        mso_mdoc=MsoMdocConfig(
            issuer_auth_algorithms=[-7, -35, -36],
            device_auth_algorithms=[-7, -35, -36],
            check_validity_period=True,
        ),
        sd_jwt_vc=SdJwtVcConfig(
            algorithms=["ES256", "ES384", "ES512"],
            kb_jwt_algorithms=["ES256", "ES384", "ES512"],
            check_status=True,
            validate_json_schema=True,
        ),
    )

    # Create client metadata
    client_metadata = ClientMetaData(
        jwks_uri=f"{base_url}/.well-known/jwks.json",
        authorization_encrypted_response_alg=None,
        authorization_encrypted_response_enc=None,
    )

    # Create verifier config
    config = VerifierConfig(
        verifier_id=client_id_scheme,
        public_url=base_url,
        signing_config=signing_config,
        vp_formats_supported=vp_formats,
        client_metadata=client_metadata,
        default_response_mode="direct_post",
        max_age_seconds=600,
        response_encryption=None,
        authorization_request_scheme="eudi-openid4vp",
    )

    return config


def create_test_config() -> VerifierConfig:
    """
    Create a test configuration with ephemeral keys.

    This is useful for testing and development when no real keys are available.

    Returns:
        VerifierConfig with test settings
    """
    # Generate a real EC P-256 key for testing
    from joserfc.jwk import ECKey
    ec_key = ECKey.generate_key("P-256")
    test_jwk = ec_key.as_dict(private=True)

    signing_config = SigningConfig(
        algorithm="ES256",
        jwk=test_jwk,
        jwk_set_url=None,
        certificate_chain=None,
    )

    client_id_scheme = PreRegisteredClientId(client_id="test-verifier")

    # COSE algorithm IDs: -7 (ES256), -35 (ES384), -36 (ES512)
    vp_formats = VpFormatsSupported(
        mso_mdoc=MsoMdocConfig(
            issuer_auth_algorithms=[-7, -35, -36],
            device_auth_algorithms=[-7, -35, -36],
            check_validity_period=True,
        ),
        sd_jwt_vc=SdJwtVcConfig(
            algorithms=["ES256", "ES384", "ES512"],
            kb_jwt_algorithms=["ES256", "ES384", "ES512"],
            check_status=True,
            validate_json_schema=True,
        ),
    )

    client_metadata = ClientMetaData(
        jwks_uri="https://test-verifier.example.com/.well-known/jwks.json",
        authorization_encrypted_response_alg=None,
        authorization_encrypted_response_enc=None,
    )

    config = VerifierConfig(
        verifier_id=client_id_scheme,
        public_url="http://localhost:8000",
        signing_config=signing_config,
        vp_formats_supported=vp_formats,
        client_metadata=client_metadata,
        default_response_mode="direct_post",
        max_age_seconds=600,
        response_encryption=None,
        authorization_request_scheme="eudi-openid4vp",
    )

    return config


def load_or_create_config() -> VerifierConfig:
    """
    Load configuration from environment or create test config.

    First tries to load from environment variables.
    If not available, creates a test configuration.

    Returns:
        VerifierConfig
    """
    config = load_config_from_env()
    if config is None:
        print("⚠ No environment configuration found, using test config")
        config = create_test_config()
    else:
        print("✓ Loaded configuration from environment")

    return config
