"""
Run the EUDI Verifier API server

This script starts the FastAPI server for the EUDI Verifier.
"""

import uvicorn

from eudi_verifier.api import app

if __name__ == "__main__":
    print("=" * 60)
    print("Starting EUDI Verifier API Server")
    print("=" * 60)
    print("\nEndpoints:")
    print("  - Docs: http://localhost:8000/docs")
    print("  - ReDoc: http://localhost:8000/redoc")
    print("  - Health: http://localhost:8000/health")
    print("\nUI/Verifier endpoints:")
    print("  - POST /ui/presentations")
    print("  - GET /ui/presentations/{transaction_id}")
    print("  - GET /ui/presentations/{transaction_id}/qrcode")
    print("\nWallet endpoints:")
    print("  - GET /wallet/request.jwt/{request_id}")
    print("  - POST /wallet/direct_post")
    print("\n" + "=" * 60)

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True,
    )
