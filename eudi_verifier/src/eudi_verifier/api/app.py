"""FastAPI application for EUDI Verifier"""

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from eudi_verifier.api.dependencies import DependencyContainer, set_container
from eudi_verifier.api.routes import ui, wallet


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Application lifespan context manager.

    Handles startup and shutdown events.
    """
    # Startup
    print("Starting EUDI Verifier API...")

    # Initialize dependency container
    # TODO: Load configuration from environment
    container = DependencyContainer()
    set_container(container)

    print("✓ Dependency container initialized")
    print("✓ EUDI Verifier API ready")

    yield

    # Shutdown
    print("Shutting down EUDI Verifier API...")


def create_app() -> FastAPI:
    """
    Create and configure FastAPI application.

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title="EUDI Verifier",
        description="""
        OpenID4VP Verifier Endpoint for EUDI Wallet

        Implements OpenID for Verifiable Presentations (OpenID4VP) 1.0
        with support for:
        - DCQL (Digital Credential Query Language)
        - SD-JWT VC (Selective Disclosure JWT Verifiable Credentials)
        - MSO MDoc (ISO 18013-5 Mobile Driving License)
        - JAR (JWT-Secured Authorization Request) - RFC 9101
        - RQES (Remote Qualified Electronic Signature) transaction data

        ## Architecture

        This implementation follows hexagonal (ports and adapters) architecture:
        - **Domain Layer**: Pure business logic (presentation state machine, DCQL, etc.)
        - **Application Layer**: Use cases orchestrating domain and infrastructure
        - **Port Layer**: Interfaces defining contracts
        - **Adapter Layer**: Infrastructure implementations (repository, JOSE, validation, QR codes)
        - **API Layer**: FastAPI endpoints exposing use cases

        ## Endpoints

        ### UI/Verifier Endpoints
        - `POST /ui/presentations` - Initiate presentation transaction
        - `GET /ui/presentations/{transaction_id}` - Get wallet response
        - `GET /ui/presentations/{transaction_id}/qrcode` - Get QR code

        ### Wallet Endpoints
        - `GET /wallet/request.jwt/{request_id}` - Get JAR (request object)
        - `POST /wallet/direct_post` - Submit credentials
        """,
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # CORS middleware
    # SECURITY WARNING: allow_origins=["*"] is permissive and should be restricted in production
    # Configure based on environment variables or deployment configuration
    # For production: Set specific origins like ["https://verifier-ui.example.com"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # TODO: Configure based on environment (e.g., ALLOWED_ORIGINS env var)
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include routers
    app.include_router(ui.router)
    app.include_router(wallet.router)

    # Health check endpoint
    @app.get("/health", tags=["Health"])
    async def health_check():
        """Health check endpoint"""
        return JSONResponse(content={"status": "healthy", "service": "eudi-verifier"})

    return app


# Create app instance
app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
