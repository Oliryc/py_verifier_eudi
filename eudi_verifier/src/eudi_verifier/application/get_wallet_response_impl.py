"""GetWalletResponse use case implementation"""

from typing import Any, Dict, Optional

from returns.result import Failure, Result, Success

from eudi_verifier.domain import (
    Presentation,
    PresentationSubmitted,
    is_completed,
    is_successful,
)
from eudi_verifier.port.input import (
    GetWalletResponse,
    GetWalletResponseRequest,
    GetWalletResponseResponse,
    GetWalletResponseError,
    PresentationNotReady,
    InvalidResponseCode,
)
from eudi_verifier.port.output import (
    PresentationRepository,
    PresentationNotFound,
)


class GetWalletResponseImpl(GetWalletResponse):
    """
    Implementation of GetWalletResponse use case.

    Handles retrieval of wallet response for a completed transaction.
    """

    def __init__(self, repository: PresentationRepository):
        self.repository = repository

    async def execute(
        self, request: GetWalletResponseRequest
    ) -> Result[GetWalletResponseResponse, GetWalletResponseError]:
        """
        Execute the get wallet response use case.

        Flow:
        1. Retrieve presentation by transaction_id
        2. Optionally verify response_code (for polling-based retrieval)
        3. Check presentation state
        4. Return presentation and wallet response if available
        """
        try:
            # Retrieve presentation
            get_result = await self.repository.get_by_transaction_id(request.transaction_id)
            if isinstance(get_result, Failure):
                error = get_result.failure()
                if isinstance(error, PresentationNotFound):
                    return Failure(
                        GetWalletResponseError(f"Presentation not found: {request.transaction_id}")
                    )
                return Failure(GetWalletResponseError(f"Failed to retrieve presentation: {error}"))

            presentation = get_result.unwrap()

            # Validate response_code if provided
            # Note: In a full implementation, response_code would be stored in the presentation
            # and validated here. For now, we just validate it's properly formatted.
            if request.response_code is not None:
                # TODO: Validate response_code matches stored value
                # For redirect-based flows, the response_code is generated and given to the wallet
                # The wallet redirects back with this code, and we verify it matches
                if not request.response_code.value or not request.response_code.value.strip():
                    return Failure(InvalidResponseCode(response_code=request.response_code))

            # Check if presentation is completed
            completed = is_completed(presentation)
            successful = is_successful(presentation)

            # Extract wallet_response if in Submitted state
            wallet_response: Optional[Dict[str, Any]] = None
            if isinstance(presentation, PresentationSubmitted):
                wallet_response = presentation.wallet_response

            # Return response
            return Success(
                GetWalletResponseResponse(
                    transaction_id=request.transaction_id,
                    presentation=presentation,
                    wallet_response=wallet_response,
                    is_completed=completed,
                    is_successful=successful,
                )
            )

        except Exception as e:
            return Failure(GetWalletResponseError(f"Unexpected error: {e}"))
