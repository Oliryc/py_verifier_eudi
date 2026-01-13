"""Wallet API endpoints"""

from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from returns.result import Failure

from eudi_verifier.api.dependencies import (
    get_get_request_object_use_case,
    get_post_wallet_response_use_case,
)
from eudi_verifier.api.models import ErrorResponseModel, PostWalletResponseResponseModel
from eudi_verifier.domain import RequestId
from eudi_verifier.port.input import (
    GetRequestObject,
    GetRequestObjectRequest,
    PostWalletResponse,
    PostWalletResponseRequest,
)

router = APIRouter(prefix="/wallet", tags=["Wallet"])


@router.get(
    "/request.jwt/{request_id}",
    summary="Get request object (JAR)",
    description="Retrieve JWT-Secured Authorization Request by request_id",
    responses={
        200: {"content": {"application/oauth-authz-req+jwt": {}}, "description": "JWT-Secured Authorization Request"},
        404: {"model": ErrorResponseModel},
    },
)
async def get_request_object(
    request_id: str,
    get_request_object_uc: GetRequestObject = Depends(get_get_request_object_use_case),
) -> PlainTextResponse:
    """
    Get request object (JAR) by request_id.

    This endpoint is called by the wallet when it resolves the request_uri
    parameter from the authorization request.

    Returns the signed JWT (JAR) with content-type: application/oauth-authz-req+jwt
    """
    try:
        # Create use case request
        rid = RequestId(value=request_id)
        uc_request = GetRequestObjectRequest(request_id=rid)

        # Execute use case
        result = await get_request_object_uc.execute(uc_request)

        if isinstance(result, Failure):
            error = result.failure()
            raise HTTPException(
                status_code=404,
                detail=ErrorResponseModel(
                    error="request_not_found",
                    error_description=str(error),
                ).model_dump(),
            )

        response = result.unwrap()

        # Return JAR with proper content type
        return PlainTextResponse(
            content=response.jar,
            media_type="application/oauth-authz-req+jwt",
        )

    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=ErrorResponseModel(
                error="invalid_request", error_description=f"Invalid request: {e}"
            ).model_dump(),
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=ErrorResponseModel(
                error="internal_error", error_description=f"Internal error: {e}"
            ).model_dump(),
        )


@router.post(
    "/direct_post",
    summary="Submit wallet response",
    description="Wallet submits credentials (direct_post response mode)",
    responses={
        200: {"model": PostWalletResponseResponseModel},
        400: {"model": ErrorResponseModel},
    },
)
async def post_wallet_response(
    state: str = Form(..., description="State parameter (request_id)"),
    vp_token: Optional[str] = Form(None, description="VP token (if successful)"),
    presentation_submission: Optional[str] = Form(None, description="Presentation submission descriptor (JSON)"),
    error: Optional[str] = Form(None, description="Error code (if error)"),
    error_description: Optional[str] = Form(None, description="Error description"),
    post_wallet_response_uc: PostWalletResponse = Depends(get_post_wallet_response_use_case),
) -> JSONResponse:
    """
    Process wallet response (credential submission).

    This endpoint is called by the wallet to submit credentials or report errors.
    Uses application/x-www-form-urlencoded as per OpenID4VP spec.
    """
    try:
        # Create use case request
        rid = RequestId(value=state)

        # Parse presentation_submission if provided
        import json

        ps_dict = None
        if presentation_submission:
            ps_dict = json.loads(presentation_submission)

        uc_request = PostWalletResponseRequest(
            request_id=rid,
            vp_token=vp_token,
            presentation_submission=ps_dict,
            error=error,
            error_description=error_description,
        )

        # Execute use case
        result = await post_wallet_response_uc.execute(uc_request)

        if isinstance(result, Failure):
            error_obj = result.failure()
            raise HTTPException(
                status_code=400,
                detail=ErrorResponseModel(
                    error="invalid_response",
                    error_description=str(error_obj),
                ).model_dump(),
            )

        response = result.unwrap()

        # Return success response
        # In a real implementation, this might include a redirect_uri
        return JSONResponse(
            status_code=200,
            content={
                "status": "accepted",
                "message": "Wallet response processed successfully",
            },
        )

    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=ErrorResponseModel(
                error="invalid_request", error_description=f"Invalid request: {e}"
            ).model_dump(),
        )
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=400,
            detail=ErrorResponseModel(
                error="invalid_presentation_submission",
                error_description=f"Invalid JSON in presentation_submission: {e}",
            ).model_dump(),
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=ErrorResponseModel(
                error="internal_error", error_description=f"Internal error: {e}"
            ).model_dump(),
        )
