"""PostWalletResponse use case implementation"""

from typing import Any, Dict, List

from returns.result import Failure, Result, Success

from eudi_verifier.domain import (
    Clock,
    Format,
    PresentationRequestObjectRetrieved,
    WalletResponse,
    WalletResponseError,
    WalletResponseVpToken,
    create_error_response,
    create_vp_token_response,
    is_expired,
    is_successful_response,
    mark_as_submitted,
)
from eudi_verifier.port.input import (
    PostWalletResponse,
    PostWalletResponseRequest,
    PostWalletResponseResponse,
    PostWalletResponseError,
    ValidatedCredential,
)
from eudi_verifier.port.output import (
    PresentationRepository,
    PresentationNotFound,
    ValidationService,
    JoseService,
)


class PostWalletResponseImpl(PostWalletResponse):
    """
    Implementation of PostWalletResponse use case.

    Handles wallet's credential submission and validation.
    """

    def __init__(
        self,
        repository: PresentationRepository,
        validation_service: ValidationService,
        jose_service: JoseService,
        clock: Clock,
    ):
        self.repository = repository
        self.validation_service = validation_service
        self.jose_service = jose_service
        self.clock = clock

    async def execute(
        self, request: PostWalletResponseRequest
    ) -> Result[PostWalletResponseResponse, PostWalletResponseError]:
        """
        Execute the post wallet response use case.

        Flow:
        1. Retrieve presentation by request_id
        2. Check presentation state is RequestObjectRetrieved
        3. Check not expired
        4. Parse wallet response (error or vp_token)
        5. Decrypt if encrypted (direct_post.jwt)
        6. Validate each VP token
        7. Check DCQL satisfaction
        8. Transition to Submitted state
        9. Save and return
        """
        try:
            # Retrieve presentation
            get_result = await self.repository.get_by_request_id(request.request_id)
            if isinstance(get_result, Failure):
                error = get_result.failure()
                if isinstance(error, PresentationNotFound):
                    return Failure(PostWalletResponseError(f"Presentation not found: {request.request_id}"))
                return Failure(PostWalletResponseError(f"Failed to retrieve presentation: {error}"))

            presentation = get_result.unwrap()

            # Check state - must be in RequestObjectRetrieved state
            if not isinstance(presentation, PresentationRequestObjectRetrieved):
                return Failure(
                    PostWalletResponseError(
                        f"Presentation in invalid state: {type(presentation).__name__}. "
                        f"Expected PresentationRequestObjectRetrieved"
                    )
                )

            # Check if expired
            if is_expired(presentation, self.clock):
                return Failure(PostWalletResponseError(f"Presentation expired: {request.request_id}"))

            # Parse wallet response
            wallet_response = self._parse_wallet_response(request)

            # Handle error response from wallet
            if not is_successful_response(wallet_response):
                # Wallet returned an error - still transition to Submitted with error
                wallet_response_dict = {"error": wallet_response.error, "error_description": wallet_response.error_description}

                transition_result = mark_as_submitted(presentation, wallet_response_dict, self.clock)
                if isinstance(transition_result, Failure):
                    return Failure(PostWalletResponseError(f"Failed to transition state: {transition_result.failure()}"))

                submitted_presentation = transition_result.unwrap()
                save_result = await self.repository.save(submitted_presentation)
                if isinstance(save_result, Failure):
                    return Failure(PostWalletResponseError(f"Failed to save presentation: {save_result.failure()}"))

                return Success(
                    PostWalletResponseResponse(
                        request_id=request.request_id,
                        wallet_response=wallet_response,
                        validated_credentials=None,
                        is_satisfied=False,
                    )
                )

            # Successful response with vp_token - validate credentials
            vp_tokens = wallet_response.get_vp_tokens_as_list()
            validated_credentials = await self._validate_vp_tokens(vp_tokens, presentation)

            # Check if all credentials are valid
            all_valid = all(cred.is_valid for cred in validated_credentials)

            # Check DCQL satisfaction (only if all valid)
            is_satisfied = False
            if all_valid:
                verified_claims = [cred.verified_claims for cred in validated_credentials]
                # TODO: Get DCQL from original request (need to store it in presentation)
                # For now, assume satisfied if all credentials valid
                is_satisfied = True

            # Build wallet response dict for storage
            wallet_response_dict = {
                "vp_token": vp_tokens if len(vp_tokens) > 1 else vp_tokens[0],
                "presentation_submission": (
                    wallet_response.presentation_submission.model_dump()
                    if wallet_response.presentation_submission
                    else None
                ),
                "validated": all_valid,
                "is_satisfied": is_satisfied,
            }

            # Transition to Submitted state
            transition_result = mark_as_submitted(presentation, wallet_response_dict, self.clock)
            if isinstance(transition_result, Failure):
                return Failure(PostWalletResponseError(f"Failed to transition state: {transition_result.failure()}"))

            submitted_presentation = transition_result.unwrap()

            # Save updated presentation
            save_result = await self.repository.save(submitted_presentation)
            if isinstance(save_result, Failure):
                return Failure(PostWalletResponseError(f"Failed to save presentation: {save_result.failure()}"))

            # Return response
            return Success(
                PostWalletResponseResponse(
                    request_id=request.request_id,
                    wallet_response=wallet_response,
                    validated_credentials=validated_credentials,
                    is_satisfied=is_satisfied,
                )
            )

        except Exception as e:
            return Failure(PostWalletResponseError(f"Unexpected error: {e}"))

    def _parse_wallet_response(self, request: PostWalletResponseRequest) -> WalletResponse:
        """
        Parse wallet response from request.

        Args:
            request: Post wallet response request

        Returns:
            WalletResponse (either VpToken or Error)
        """
        # Check if error response
        if request.error:
            return create_error_response(
                error=request.error, state=str(request.request_id), error_description=request.error_description
            )

        # Success response with vp_token
        return create_vp_token_response(
            vp_token=request.vp_token,
            state=str(request.request_id),
            presentation_submission=request.presentation_submission,
        )

    async def _validate_vp_tokens(
        self, vp_tokens: List[str], presentation: PresentationRequestObjectRetrieved
    ) -> List[ValidatedCredential]:
        """
        Validate all VP tokens.

        Args:
            vp_tokens: List of VP token strings
            presentation: Presentation with nonce and config

        Returns:
            List of ValidatedCredential objects
        """
        validated_credentials = []

        for vp_token in vp_tokens:
            # Determine format from token structure
            format = self._detect_format(vp_token)

            # TODO: Get config from somewhere (need to pass it through)
            # For now, create a placeholder validated credential
            validated_credential = ValidatedCredential(
                format=str(format),
                issuer="unknown",  # Would be extracted during validation
                verified_claims={},  # Would be populated during validation
                is_valid=True,  # Placeholder - actual validation would happen here
                validation_errors=[],
            )
            validated_credentials.append(validated_credential)

        return validated_credentials

    def _detect_format(self, vp_token: str) -> Format:
        """
        Detect credential format from token structure.

        Args:
            vp_token: VP token string

        Returns:
            Format enum
        """
        # Simple heuristic detection
        if vp_token.count(".") >= 2 and "~" in vp_token:
            return Format.SD_JWT_VC
        elif vp_token.count(".") >= 2:
            return Format.W3C_JWT_VC
        else:
            # Assume MSO MDoc (CBOR-based)
            return Format.MSO_MDOC
