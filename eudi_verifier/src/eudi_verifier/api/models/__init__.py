"""API models - Request and response DTOs"""

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class InitTransactionRequestModel(BaseModel):
    """Request to initiate a presentation transaction"""

    dcql_query: Dict[str, Any] = Field(..., description="DCQL query as JSON")
    nonce: Optional[str] = Field(None, description="Optional nonce (generated if not provided)")
    response_mode: Optional[str] = Field("direct_post", description="Response mode: direct_post or direct_post.jwt")
    transaction_data: Optional[Dict[str, Any]] = Field(None, description="Optional transaction data (RQES)")


class InitTransactionResponseModel(BaseModel):
    """Response from transaction initiation"""

    transaction_id: str = Field(..., description="Transaction identifier")
    request_id: str = Field(..., description="Request identifier (state parameter)")
    authorization_request_uri: str = Field(..., description="Authorization request URI for wallet")
    qr_code_url: Optional[str] = Field(None, description="Optional URL to fetch QR code")


class GetRequestObjectResponseModel(BaseModel):
    """Response from JAR retrieval"""

    request_id: str = Field(..., description="Request identifier")
    jar: str = Field(..., description="JWT-Secured Authorization Request")


class PostWalletResponseRequestModel(BaseModel):
    """Request from wallet submitting credentials"""

    vp_token: Optional[str] = Field(None, description="VP token (if successful)")
    presentation_submission: Optional[Dict[str, Any]] = Field(None, description="Presentation submission descriptor")
    error: Optional[str] = Field(None, description="Error code (if error)")
    error_description: Optional[str] = Field(None, description="Error description")
    state: str = Field(..., description="State parameter (request_id)")


class PostWalletResponseResponseModel(BaseModel):
    """Response to wallet credential submission"""

    redirect_uri: Optional[str] = Field(None, description="Redirect URI for wallet")
    status: str = Field(..., description="Processing status")


class GetWalletResponseResponseModel(BaseModel):
    """Response from wallet response retrieval"""

    transaction_id: str = Field(..., description="Transaction identifier")
    is_completed: bool = Field(..., description="Whether presentation is completed")
    is_successful: bool = Field(..., description="Whether credentials were successfully submitted")
    wallet_response: Optional[Dict[str, Any]] = Field(None, description="Wallet response data")
    presentation_state: str = Field(..., description="Current presentation state")


class ErrorResponseModel(BaseModel):
    """Standard error response"""

    error: str = Field(..., description="Error code")
    error_description: str = Field(..., description="Human-readable error description")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
