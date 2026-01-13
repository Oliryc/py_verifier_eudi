"""GetRequestObject use case implementation"""

from returns.result import Failure, Result, Success

from eudi_verifier.domain import (
    Clock,
    PresentationRequested,
    is_expired,
    mark_as_retrieved,
)
from eudi_verifier.port.input import (
    GetRequestObject,
    GetRequestObjectRequest,
    GetRequestObjectResponse,
    GetRequestObjectError,
    RequestObjectExpired,
)
from eudi_verifier.port.output import (
    PresentationRepository,
    PresentationNotFound,
)


class GetRequestObjectImpl(GetRequestObject):
    """
    Implementation of GetRequestObject use case.

    Handles wallet's retrieval of JAR (JWT-Secured Authorization Request).
    """

    def __init__(self, repository: PresentationRepository, clock: Clock):
        self.repository = repository
        self.clock = clock

    async def execute(self, request: GetRequestObjectRequest) -> Result[GetRequestObjectResponse, GetRequestObjectError]:
        """
        Execute the get request object use case.

        Flow:
        1. Retrieve presentation by request_id
        2. Check presentation is in Requested state
        3. Check presentation is not expired
        4. Transition to RequestObjectRetrieved state
        5. Save updated presentation
        6. Return JAR
        """
        try:
            # Retrieve presentation
            get_result = await self.repository.get_by_request_id(request.request_id)
            if isinstance(get_result, Failure):
                error = get_result.failure()
                if isinstance(error, PresentationNotFound):
                    return Failure(GetRequestObjectError(f"Presentation not found: {request.request_id}"))
                return Failure(GetRequestObjectError(f"Failed to retrieve presentation: {error}"))

            presentation = get_result.unwrap()

            # Check if expired
            if is_expired(presentation, self.clock):
                return Failure(RequestObjectExpired(request_id=request.request_id))

            # Check state - must be in Requested state
            if not isinstance(presentation, PresentationRequested):
                return Failure(
                    GetRequestObjectError(
                        f"Presentation in invalid state: {type(presentation).__name__}. "
                        f"Expected PresentationRequested"
                    )
                )

            # Get JAR
            jar = presentation.jar

            # Transition to RequestObjectRetrieved state
            transition_result = mark_as_retrieved(presentation, self.clock)
            if isinstance(transition_result, Failure):
                error = transition_result.failure()
                return Failure(GetRequestObjectError(f"Failed to transition state: {error.message}"))

            retrieved_presentation = transition_result.unwrap()

            # Save updated presentation
            save_result = await self.repository.save(retrieved_presentation)
            if isinstance(save_result, Failure):
                return Failure(GetRequestObjectError(f"Failed to save presentation: {save_result.failure()}"))

            # Return JAR
            return Success(
                GetRequestObjectResponse(
                    request_id=request.request_id,
                    jar=jar,
                    content_type="application/oauth-authz-req+jwt",
                )
            )

        except Exception as e:
            return Failure(GetRequestObjectError(f"Unexpected error: {e}"))
