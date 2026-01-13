"""InitTransaction use case implementation"""

import secrets
from datetime import timedelta
from typing import Any, Dict

from returns.result import Failure, Result, Success

from eudi_verifier.domain import (
    Clock,
    RequestId,
    TransactionId,
    VerifierConfig,
    create_presentation_requested,
)
from eudi_verifier.port.input import (
    InitTransaction,
    InitTransactionRequest,
    InitTransactionResponse,
    InitTransactionError,
)
from eudi_verifier.port.output import (
    PresentationRepository,
    JoseService,
    QrCodeService,
)


class InitTransactionImpl(InitTransaction):
    """
    Implementation of InitTransaction use case.

    Orchestrates the creation of a new presentation transaction.
    """

    def __init__(
        self,
        repository: PresentationRepository,
        jose_service: JoseService,
        qrcode_service: QrCodeService,
        config: VerifierConfig,
        clock: Clock,
    ):
        self.repository = repository
        self.jose_service = jose_service
        self.qrcode_service = qrcode_service
        self.config = config
        self.clock = clock

    async def execute(self, request: InitTransactionRequest) -> Result[InitTransactionResponse, InitTransactionError]:
        """
        Execute the init transaction use case.

        Flow:
        1. Generate transaction and request IDs
        2. Determine response mode
        3. Generate ephemeral key if needed (direct_post.jwt)
        4. Create presentation in Requested state
        5. Build JAR payload
        6. Sign (and optionally encrypt) JAR
        7. Save presentation
        8. Build authorization request URI
        9. Return response
        """
        try:
            # Generate unique identifiers
            transaction_id = TransactionId(value=self._generate_id())
            request_id = RequestId(value=self._generate_id())

            # Determine response mode
            response_mode = request.response_mode or self.config.default_response_mode

            # Generate ephemeral key for response encryption if needed
            ephemeral_public_jwk = None
            ephemeral_private_jwk = None
            if response_mode == "direct_post.jwt":
                key_result = await self.jose_service.generate_ephemeral_key()
                if isinstance(key_result, Failure):
                    return Failure(InitTransactionError(f"Failed to generate ephemeral key: {key_result.failure()}"))
                ephemeral_public_jwk, ephemeral_private_jwk = key_result.unwrap()

            # Build JAR payload
            jar_payload = self._build_jar_payload(
                request=request,
                request_id=request_id,
                response_mode=str(response_mode),
                ephemeral_public_jwk=ephemeral_public_jwk,
            )

            # Create signed JWT (JAR)
            jar_result = await self.jose_service.create_signed_jwt(
                payload=jar_payload,
                config=self.config,
                include_x5c=(self.config.verifier_id.scheme != "pre-registered"),
            )
            if isinstance(jar_result, Failure):
                return Failure(InitTransactionError(f"Failed to create JAR: {jar_result.failure()}"))

            jar = jar_result.unwrap()

            # Create presentation in Requested state
            presentation = create_presentation_requested(
                transaction_id=transaction_id,
                request_id=request_id,
                jar=jar,
                nonce=request.nonce,
                response_mode=str(response_mode),
                presentation_definition=request.presentation_definition,
                max_age=timedelta(seconds=self.config.max_age_seconds),
                clock=self.clock,
            )

            # Save presentation
            save_result = await self.repository.save(presentation)
            if isinstance(save_result, Failure):
                return Failure(InitTransactionError(f"Failed to save presentation: {save_result.failure()}"))

            # Build authorization request URI
            client_id = self.config.get_client_id()
            request_uri = f"{self.config.public_url}/wallet/request.jwt/{request_id}"
            authorization_request = self._build_authorization_request_uri(
                client_id=client_id, request_uri=request_uri, request_id=request_id
            )

            # Return response
            return Success(
                InitTransactionResponse(
                    transaction_id=transaction_id,
                    request_id=request_id,
                    client_id=client_id,
                    request_uri=request_uri,
                    request=None,  # Using by_reference (request_uri)
                    authorization_request=authorization_request,
                )
            )

        except Exception as e:
            return Failure(InitTransactionError(f"Unexpected error: {e}"))

    def _generate_id(self) -> str:
        """Generate a secure random identifier"""
        return secrets.token_urlsafe(32)

    def _build_jar_payload(
        self,
        request: InitTransactionRequest,
        request_id: RequestId,
        response_mode: str,
        ephemeral_public_jwk: Dict[str, Any] | None,
    ) -> Dict[str, Any]:
        """
        Build JWT payload for JAR (JWT-Secured Authorization Request).

        Args:
            request: Init transaction request
            request_id: Request identifier
            response_mode: Response mode (direct_post or direct_post.jwt)
            ephemeral_public_jwk: Public key for response encryption (if direct_post.jwt)

        Returns:
            JWT claims dict
        """
        now = self.clock.now()
        iat = int(now.timestamp())
        exp = iat + self.config.max_age_seconds

        payload: Dict[str, Any] = {
            "iss": self.config.get_client_id(),
            "aud": "https://self-issued.me/v2",
            "iat": iat,
            "exp": exp,
            "response_type": "vp_token",
            "response_mode": response_mode,
            "client_id": self.config.get_client_id(),
            "response_uri": f"{self.config.public_url}/wallet/direct_post/{request_id}",
            "nonce": str(request.nonce),
            "state": str(request_id),
        }

        # Add presentation definition or DCQL
        if request.presentation_definition:
            payload["presentation_definition"] = request.presentation_definition
        else:
            # Convert DCQL to dict
            payload["dcql_query"] = request.dcql_query.model_dump(exclude_none=True)

        # Add client metadata
        payload["client_metadata"] = self.config.client_metadata.model_dump(exclude_none=True)

        # Add ephemeral key for response encryption
        if ephemeral_public_jwk:
            payload["client_metadata"]["authorization_encrypted_response_alg"] = (
                self.config.response_encryption.algorithm
            )
            payload["client_metadata"]["authorization_encrypted_response_enc"] = (
                self.config.response_encryption.encryption_method
            )
            payload["client_metadata"]["jwks"] = {"keys": [ephemeral_public_jwk]}

        # Add transaction data if present (RQES)
        if request.transaction_data:
            from eudi_verifier.domain.transaction_data import HashAlgorithm

            payload["transaction_data"] = request.transaction_data.to_base64url()
            payload["transaction_data_hashes"] = {
                "alg": "sha-256",
                "value": request.transaction_data.compute_hash(HashAlgorithm.SHA256),
            }

        return payload

    def _build_authorization_request_uri(self, client_id: str, request_uri: str, request_id: RequestId) -> str:
        """
        Build complete authorization request URI for QR code.

        Format: eudi-openid4vp://authorize?client_id=...&request_uri=...

        Args:
            client_id: Verifier client identifier
            request_uri: URI where JAR can be retrieved
            request_id: Request identifier

        Returns:
            Authorization request URI
        """
        scheme = self.config.authorization_request_scheme
        # URL-encode parameters
        from urllib.parse import urlencode

        params = {"client_id": client_id, "request_uri": request_uri}

        return f"{scheme}://authorize?{urlencode(params)}"
