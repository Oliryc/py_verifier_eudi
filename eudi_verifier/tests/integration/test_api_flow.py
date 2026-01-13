"""Integration test for full OpenID4VP flow via API"""

import pytest
from fastapi.testclient import TestClient

from eudi_verifier.api.app import create_app
from eudi_verifier.api.dependencies import DependencyContainer, set_container
from eudi_verifier.config import create_test_config


@pytest.fixture
def client():
    """Create test client with fresh dependency container"""
    # Create test config and container
    config = create_test_config()
    container = DependencyContainer(config=config)
    set_container(container)

    # Create FastAPI app
    app = create_app()

    # Create test client
    with TestClient(app) as test_client:
        yield test_client


def test_health_check(client):
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "eudi-verifier"}


def test_full_openid4vp_flow_happy_path(client):
    """
    Test complete OpenID4VP flow.

    Flow:
    1. Verifier initiates transaction (POST /ui/presentations)
    2. Wallet retrieves JAR (GET /wallet/request.jwt/{request_id})
    3. Wallet submits credentials (POST /wallet/direct_post)
    4. Verifier retrieves wallet response (GET /ui/presentations/{transaction_id})
    """

    # Step 1: Initiate transaction
    dcql_query = {
        "credentials": [
            {
                "id": "pid_credential",
                "format": "dc+sd-jwt",
                "meta": {"vct": "https://example.com/credentials/person_identification_data"},
                "claims": [{"path": ["given_name"]}, {"path": ["family_name"]}, {"path": ["birthdate"]}],
            }
        ]
    }

    init_response = client.post(
        "/ui/presentations",
        json={
            "dcql_query": dcql_query,
            "nonce": "test-nonce-12345",
            "response_mode": "direct_post",
        },
    )

    assert init_response.status_code == 201
    init_data = init_response.json()

    assert "transaction_id" in init_data
    assert "request_id" in init_data
    assert "authorization_request_uri" in init_data
    assert "qr_code_url" in init_data

    transaction_id = init_data["transaction_id"]
    request_id = init_data["request_id"]

    print(f"\n✓ Step 1: Transaction initiated")
    print(f"  - transaction_id: {transaction_id}")
    print(f"  - request_id: {request_id}")

    # Step 2: Wallet retrieves JAR
    jar_response = client.get(f"/wallet/request.jwt/{request_id}")

    assert jar_response.status_code == 200
    assert jar_response.headers["content-type"] == "application/oauth-authz-req+jwt; charset=utf-8"

    jar = jar_response.text
    assert jar  # JAR should not be empty
    assert "." in jar  # JWT format (header.payload.signature)

    print(f"\n✓ Step 2: JAR retrieved")
    print(f"  - JAR length: {len(jar)} bytes")

    # Step 3: Wallet submits credentials
    # Simulate wallet submitting a VP token
    wallet_response = client.post(
        "/wallet/direct_post",
        data={
            "state": request_id,
            "vp_token": "eyJ...fake-vp-token....",
            "presentation_submission": '{"definition_id": "pid_request", "descriptor_map": []}',
        },
    )

    assert wallet_response.status_code == 200
    wallet_data = wallet_response.json()
    assert wallet_data["status"] == "accepted"

    print(f"\n✓ Step 3: Credentials submitted")

    # Step 4: Verifier retrieves wallet response
    get_response = client.get(f"/ui/presentations/{transaction_id}")

    assert get_response.status_code == 200
    get_data = get_response.json()

    assert get_data["transaction_id"] == transaction_id
    assert get_data["is_completed"] is True
    assert get_data["is_successful"] is True
    assert "wallet_response" in get_data
    assert get_data["presentation_state"] == "PresentationSubmitted"

    print(f"\n✓ Step 4: Wallet response retrieved")
    print(f"  - State: {get_data['presentation_state']}")
    print(f"  - Completed: {get_data['is_completed']}")
    print(f"  - Successful: {get_data['is_successful']}")


def test_wallet_error_flow(client):
    """
    Test flow when wallet reports an error.

    Flow:
    1. Verifier initiates transaction
    2. Wallet retrieves JAR
    3. Wallet reports error (user declined)
    4. Verifier retrieves wallet response with error
    """

    # Step 1: Initiate transaction
    dcql_query = {
        "credentials": [
            {
                "id": "pid_credential",
                "format": "dc+sd-jwt",
                "meta": {"vct": "https://example.com/credentials/person_identification_data"},
            }
        ]
    }

    init_response = client.post(
        "/ui/presentations",
        json={
            "dcql_query": dcql_query,
            "nonce": "test-nonce-67890",
        },
    )

    assert init_response.status_code == 201
    init_data = init_response.json()
    request_id = init_data["request_id"]
    transaction_id = init_data["transaction_id"]

    # Step 2: Wallet retrieves JAR
    jar_response = client.get(f"/wallet/request.jwt/{request_id}")
    assert jar_response.status_code == 200

    # Step 3: Wallet reports error
    wallet_response = client.post(
        "/wallet/direct_post",
        data={
            "state": request_id,
            "error": "user_declined",
            "error_description": "User declined to share credentials",
        },
    )

    assert wallet_response.status_code == 200

    # Step 4: Verifier retrieves error response
    get_response = client.get(f"/ui/presentations/{transaction_id}")

    assert get_response.status_code == 200
    get_data = get_response.json()

    assert get_data["is_completed"] is True
    assert get_data["is_successful"] is True  # State machine accepts error responses
    assert "wallet_response" in get_data
    wallet_resp = get_data["wallet_response"]
    assert wallet_resp["error"] == "user_declined"

    print(f"\n✓ Wallet error flow completed")
    print(f"  - Error: {wallet_resp['error']}")
    print(f"  - Description: {wallet_resp.get('error_description')}")


def test_qrcode_generation(client):
    """Test QR code generation for authorization request"""

    # Initiate transaction
    dcql_query = {
        "credentials": [
            {
                "id": "test_cred",
                "format": "dc+sd-jwt",
            }
        ]
    }

    init_response = client.post(
        "/ui/presentations",
        json={"dcql_query": dcql_query},
    )

    assert init_response.status_code == 201
    transaction_id = init_response.json()["transaction_id"]

    # Get QR code (PNG)
    qr_response = client.get(f"/ui/presentations/{transaction_id}/qrcode?format=png")

    assert qr_response.status_code == 200
    assert qr_response.headers["content-type"] == "image/png"
    assert len(qr_response.content) > 0

    print(f"\n✓ QR code generated")
    print(f"  - Format: PNG")
    print(f"  - Size: {len(qr_response.content)} bytes")


def test_invalid_request_id(client):
    """Test error handling for invalid request_id"""

    # Try to get JAR with non-existent request_id
    response = client.get("/wallet/request.jwt/invalid-request-id-12345")

    assert response.status_code == 404
    error_data = response.json()
    assert "detail" in error_data
    assert error_data["detail"]["error"] == "request_not_found"


def test_invalid_transaction_id(client):
    """Test error handling for invalid transaction_id"""

    # Try to get wallet response with non-existent transaction_id
    response = client.get("/ui/presentations/invalid-transaction-id-12345")

    assert response.status_code == 404
    error_data = response.json()
    assert "detail" in error_data
    assert error_data["detail"]["error"] == "presentation_not_found"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
