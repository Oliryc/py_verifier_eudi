"""
Basic usage example for EUDI Verifier

This script demonstrates:
1. Creating a verifier configuration
2. Initializing a presentation transaction
3. Retrieving the JAR
4. Submitting a wallet response
5. Retrieving the final result
"""

import asyncio
from datetime import datetime, timedelta, timezone

from eudi_verifier.adapter import (
    InMemoryPresentationRepository,
    JoseServiceImpl,
    ValidationServiceImpl,
)
from eudi_verifier.application import (
    GetRequestObjectImpl,
    GetWalletResponseImpl,
    InitTransactionImpl,
    PostWalletResponseImpl,
)
from eudi_verifier.config import create_test_config
from eudi_verifier.domain import (
    DCQL,
    CredentialQuery,
    Nonce,
    QueryId,
    SystemClock,
    TransactionId,
)
from eudi_verifier.port.input import (
    GetRequestObjectRequest,
    GetWalletResponseRequest,
    InitTransactionRequest,
    PostWalletResponseRequest,
)


async def main():
    """Run the example"""

    print("=" * 60)
    print("EUDI Verifier - Basic Usage Example")
    print("=" * 60)

    # 1. Setup: Create configuration and dependencies
    print("\n1. Setting up verifier...")

    config = create_test_config()
    clock = SystemClock()
    repository = InMemoryPresentationRepository(clock=clock)
    jose_service = JoseServiceImpl()
    validation_service = ValidationServiceImpl()

    # Create use case instances
    init_transaction = InitTransactionImpl(
        repository=repository, jose_service=jose_service, clock=clock
    )

    get_request_object = GetRequestObjectImpl(repository=repository, clock=clock)

    post_wallet_response = PostWalletResponseImpl(
        repository=repository, validation_service=validation_service, clock=clock
    )

    get_wallet_response = GetWalletResponseImpl(repository=repository)

    print("✓ Verifier configured")

    # 2. Create a DCQL query for PID (Person Identification Data)
    print("\n2. Creating DCQL query...")

    dcql = DCQL(
        credentials=[
            CredentialQuery(
                id=QueryId(value="pid_credential"),
                format="dc+sd-jwt",
                meta={"vct": "https://example.com/credentials/person_identification_data"},
                claims={
                    "claims": [
                        {"path": ["given_name"]},
                        {"path": ["family_name"]},
                        {"path": ["birthdate"]},
                        {"path": ["age_over_18"]},
                    ]
                },
            )
        ]
    )

    print(f"✓ DCQL query created with {len(dcql.credentials)} credential(s)")

    # 3. Initiate transaction
    print("\n3. Initiating presentation transaction...")

    nonce = Nonce.generate()
    init_request = InitTransactionRequest(
        dcql_query=dcql, nonce=nonce, response_mode="direct_post"
    )

    init_result = await init_transaction.execute(init_request)

    if init_result.is_err():
        print(f"✗ Failed to initiate transaction: {init_result.failure()}")
        return

    init_response = init_result.unwrap()

    print(f"✓ Transaction initiated")
    print(f"  - Transaction ID: {init_response.transaction_id.value}")
    print(f"  - Request ID: {init_response.request_id.value}")
    print(f"  - Authorization Request URI: {init_response.authorization_request_uri}")

    # 4. Wallet retrieves JAR
    print("\n4. Wallet retrieving JAR...")

    jar_request = GetRequestObjectRequest(request_id=init_response.request_id)
    jar_result = await get_request_object.execute(jar_request)

    if jar_result.is_err():
        print(f"✗ Failed to retrieve JAR: {jar_result.failure()}")
        return

    jar_response = jar_result.unwrap()

    print(f"✓ JAR retrieved")
    print(f"  - Request ID: {jar_response.request_id.value}")
    print(f"  - JAR length: {len(jar_response.jar)} bytes")
    print(f"  - JAR preview: {jar_response.jar[:50]}...")

    # 5. Wallet submits credentials (simulated)
    print("\n5. Wallet submitting credentials...")

    # In a real scenario, the wallet would:
    # - Parse the JAR
    # - Identify matching credentials
    # - Create VP tokens with selective disclosure
    # - Sign with key binding
    # - Submit via direct_post

    wallet_submit_request = PostWalletResponseRequest(
        request_id=init_response.request_id,
        vp_token="eyJ...simulated-vp-token...",
        presentation_submission={
            "id": "submission_1",
            "definition_id": "pid_request",
            "descriptor_map": [
                {
                    "id": "pid_credential",
                    "format": "dc+sd-jwt",
                    "path": "$",
                }
            ],
        },
    )

    submit_result = await post_wallet_response.execute(wallet_submit_request)

    if submit_result.is_err():
        print(f"✗ Failed to submit credentials: {submit_result.failure()}")
        return

    submit_response = submit_result.unwrap()

    print(f"✓ Credentials submitted")
    print(f"  - Validated: {submit_response.is_satisfied}")
    print(f"  - Credentials: {len(submit_response.validated_credentials)}")

    # 6. Verifier retrieves wallet response
    print("\n6. Verifier retrieving wallet response...")

    get_response_request = GetWalletResponseRequest(transaction_id=init_response.transaction_id)
    get_response_result = await get_wallet_response.execute(get_response_request)

    if get_response_result.is_err():
        print(f"✗ Failed to retrieve response: {get_response_result.failure()}")
        return

    final_response = get_response_result.unwrap()

    print(f"✓ Wallet response retrieved")
    print(f"  - Transaction ID: {final_response.transaction_id.value}")
    print(f"  - Completed: {final_response.is_completed}")
    print(f"  - Successful: {final_response.is_successful}")
    print(f"  - State: {type(final_response.presentation).__name__}")

    if final_response.wallet_response:
        print(f"  - Response keys: {list(final_response.wallet_response.keys())}")

    # 7. Summary
    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)
    print("\nThis example demonstrated the full OpenID4VP flow:")
    print("1. ✓ Verifier initiates transaction with DCQL query")
    print("2. ✓ Wallet retrieves JAR (JWT-Secured Authorization Request)")
    print("3. ✓ Wallet submits credentials with VP tokens")
    print("4. ✓ Verifier validates and retrieves wallet response")
    print("\nIn a production environment:")
    print("- JAR would contain real signed JWTs")
    print("- VP tokens would be validated against trust anchors")
    print("- Credentials would be checked for revocation")
    print("- DCQL satisfaction would be fully enforced")


if __name__ == "__main__":
    asyncio.run(main())
