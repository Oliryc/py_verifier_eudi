"""Common test fixtures for domain tests"""

from datetime import datetime, timedelta, timezone

import pytest

from eudi_verifier.domain import (
    Clock,
    FixedClock,
    TransactionId,
    RequestId,
    Nonce,
)


@pytest.fixture
def fixed_clock() -> FixedClock:
    """Fixed clock at 2024-01-15 12:00:00 UTC"""
    return FixedClock(datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc))


@pytest.fixture
def transaction_id() -> TransactionId:
    """Sample transaction ID"""
    return TransactionId(value="txn_123456")


@pytest.fixture
def request_id() -> RequestId:
    """Sample request ID"""
    return RequestId(value="req_abcdef")


@pytest.fixture
def nonce() -> Nonce:
    """Sample nonce"""
    return Nonce(value="nonce_xyz789")


@pytest.fixture
def sample_jwk() -> dict:
    """Sample JWK for testing"""
    return {
        "kty": "RSA",
        "use": "sig",
        "kid": "test-key-1",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtV",
        "e": "AQAB",
    }


@pytest.fixture
def sample_certificate() -> str:
    """Sample X.509 certificate (PEM format)"""
    return """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU7KVMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yNDAxMTUwMDAwMDBaFw0yNTAxMTQwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA0vx7agoebGcQSuuP
-----END CERTIFICATE-----"""
