"""UI/Verifier API endpoints"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from returns.result import Failure

from eudi_verifier.api.dependencies import (
    get_init_transaction_use_case,
    get_get_wallet_response_use_case,
    get_qrcode_service,
)
from eudi_verifier.api.models import (
    ErrorResponseModel,
    GetWalletResponseResponseModel,
    InitTransactionRequestModel,
    InitTransactionResponseModel,
)
from eudi_verifier.domain import DCQL, Nonce, ResponseCode, TransactionId
from eudi_verifier.port.input import (
    GetWalletResponse,
    GetWalletResponseRequest,
    InitTransaction,
    InitTransactionRequest,
)
from eudi_verifier.port.output import QrCodeFormat, QrCodeService

router = APIRouter(prefix="/ui", tags=["UI/Verifier"])


@router.post(
    "/presentations",
    response_model=InitTransactionResponseModel,
    status_code=201,
    summary="Initiate presentation transaction",
    description="Create a new presentation transaction and return authorization request URI",
)
async def init_transaction(
    request: InitTransactionRequestModel,
    init_transaction_uc: InitTransaction = Depends(get_init_transaction_use_case),
) -> InitTransactionResponseModel:
    """
    Initiate a new presentation transaction.

    This endpoint is called by the verifier UI to create a new transaction.
    Returns an authorization request URI that can be encoded in a QR code.
    """
    try:
        # Parse DCQL from JSON
        dcql = DCQL.model_validate(request.dcql_query)

        # Generate or use provided nonce
        nonce = Nonce(value=request.nonce) if request.nonce else Nonce.generate()

        # Parse transaction data if provided
        # TODO: Parse transaction_data based on type (QesAuthorization, QCertCreationAcceptance)
        transaction_data = None

        # Create use case request
        uc_request = InitTransactionRequest(
            dcql_query=dcql,
            nonce=nonce,
            response_mode=request.response_mode,
            transaction_data=transaction_data,
        )

        # Execute use case
        result = await init_transaction_uc.execute(uc_request)

        if isinstance(result, Failure):
            error = result.failure()
            raise HTTPException(
                status_code=500,
                detail=ErrorResponseModel(
                    error="init_transaction_failed",
                    error_description=str(error),
                ).model_dump(),
            )

        response = result.unwrap()

        # Build QR code URL
        qr_code_url = f"/ui/presentations/{response.transaction_id.value}/qrcode"

        return InitTransactionResponseModel(
            transaction_id=response.transaction_id.value,
            request_id=response.request_id.value,
            authorization_request_uri=response.authorization_request or "",
            qr_code_url=qr_code_url,
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


@router.get(
    "/presentations/{transaction_id}",
    response_model=GetWalletResponseResponseModel,
    summary="Get wallet response",
    description="Retrieve wallet response for a completed transaction",
)
async def get_wallet_response(
    transaction_id: str,
    response_code: Optional[str] = Query(None, description="Response code for polling"),
    get_wallet_response_uc: GetWalletResponse = Depends(get_get_wallet_response_use_case),
) -> GetWalletResponseResponseModel:
    """
    Get wallet response for a transaction.

    This endpoint is called by the verifier UI to check the status
    and retrieve validated credentials.
    """
    try:
        # Create use case request
        tid = TransactionId(value=transaction_id)
        rc = ResponseCode(value=response_code) if response_code else None

        uc_request = GetWalletResponseRequest(transaction_id=tid, response_code=rc)

        # Execute use case
        result = await get_wallet_response_uc.execute(uc_request)

        if isinstance(result, Failure):
            error = result.failure()
            raise HTTPException(
                status_code=404,
                detail=ErrorResponseModel(
                    error="presentation_not_found",
                    error_description=str(error),
                ).model_dump(),
            )

        response = result.unwrap()

        # Determine presentation state
        presentation = response.presentation
        state_name = type(presentation).__name__

        return GetWalletResponseResponseModel(
            transaction_id=response.transaction_id.value,
            is_completed=response.is_completed,
            is_successful=response.is_successful,
            wallet_response=response.wallet_response,
            presentation_state=state_name,
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


@router.get(
    "/presentations/{transaction_id}/qrcode",
    summary="Get QR code",
    description="Generate QR code image for authorization request",
    responses={
        200: {
            "content": {"image/png": {}, "image/svg+xml": {}, "image/jpeg": {}},
            "description": "QR code image",
        }
    },
)
async def get_qrcode(
    transaction_id: str,
    format: str = Query("png", description="Image format: png, svg, jpeg"),
    get_wallet_response_uc: GetWalletResponse = Depends(get_get_wallet_response_use_case),
    qrcode_service: QrCodeService = Depends(get_qrcode_service),
) -> Response:
    """
    Generate QR code for authorization request.

    This endpoint is called by the verifier UI to display a QR code
    that wallets can scan.
    """
    try:
        # Get transaction to retrieve authorization request URI
        tid = TransactionId(value=transaction_id)
        uc_request = GetWalletResponseRequest(transaction_id=tid)

        result = await get_wallet_response_uc.execute(uc_request)

        if isinstance(result, Failure):
            raise HTTPException(status_code=404, detail="Transaction not found")

        response = result.unwrap()
        presentation = response.presentation

        # Get JAR from presentation (all states have this initially)
        # For simplicity, we'll use the request_id to construct the URI
        # In a real implementation, we'd store the full authorization_request_uri
        request_id = presentation.request_id.value
        authorization_request_uri = f"eudi-openid4vp://?request_uri=https://example.com/wallet/request.jwt/{request_id}"

        # Parse format
        qr_format = QrCodeFormat(format.lower())

        # Generate QR code
        qr_result = await qrcode_service.generate_authorization_request_qr(
            authorization_request=authorization_request_uri, format=qr_format
        )

        if isinstance(qr_result, Failure):
            raise HTTPException(status_code=500, detail="Failed to generate QR code")

        qr_bytes = qr_result.unwrap()

        # Determine content type
        content_type_map = {
            QrCodeFormat.PNG: "image/png",
            QrCodeFormat.SVG: "image/svg+xml",
            QrCodeFormat.JPEG: "image/jpeg",
        }

        return Response(content=qr_bytes, media_type=content_type_map[qr_format])

    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid format: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {e}")
