# EUDI Verifier - Examples

This directory contains example scripts demonstrating how to use the EUDI Verifier.

## Examples

### 1. Basic Usage (`basic_usage.py`)

Demonstrates the complete OpenID4VP flow using the verifier as a library:

```bash
python examples/basic_usage.py
```

This example shows:
- Creating a verifier configuration
- Initiating a presentation transaction with DCQL
- Retrieving the JAR (JWT-Secured Authorization Request)
- Submitting wallet credentials
- Retrieving and validating the final response

### 2. Run Server (`run_server.py`)

Starts the FastAPI server for the EUDI Verifier:

```bash
python examples/run_server.py
```

The server will be available at:
- API Documentation: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- Health Check: http://localhost:8000/health

## API Endpoints

### UI/Verifier Endpoints

These endpoints are used by the verifier's user interface:

#### 1. Initiate Transaction

```bash
POST /ui/presentations
Content-Type: application/json

{
  "dcql_query": {
    "credentials": [
      {
        "id": "pid_credential",
        "format": "dc+sd-jwt",
        "meta": {
          "vct": "https://example.com/credentials/person_identification_data"
        },
        "claims": [
          {"path": ["given_name"]},
          {"path": ["family_name"]},
          {"path": ["birthdate"]}
        ]
      }
    ]
  },
  "nonce": "optional-nonce",
  "response_mode": "direct_post"
}
```

Response:
```json
{
  "transaction_id": "txn_abc123",
  "request_id": "req_xyz789",
  "authorization_request_uri": "eudi-openid4vp://?request_uri=...",
  "qr_code_url": "/ui/presentations/txn_abc123/qrcode"
}
```

#### 2. Get Wallet Response

```bash
GET /ui/presentations/{transaction_id}
```

Response:
```json
{
  "transaction_id": "txn_abc123",
  "is_completed": true,
  "is_successful": true,
  "wallet_response": {
    "vp_token": "...",
    "presentation_submission": {...}
  },
  "presentation_state": "PresentationSubmitted"
}
```

#### 3. Get QR Code

```bash
GET /ui/presentations/{transaction_id}/qrcode?format=png
```

Returns a QR code image (PNG, SVG, or JPEG).

### Wallet Endpoints

These endpoints are used by the wallet application:

#### 1. Get Request Object (JAR)

```bash
GET /wallet/request.jwt/{request_id}
```

Returns the signed JWT (JAR) with content-type: `application/oauth-authz-req+jwt`

#### 2. Submit Credentials

```bash
POST /wallet/direct_post
Content-Type: application/x-www-form-urlencoded

state=req_xyz789&vp_token=eyJ...&presentation_submission={...}
```

Response:
```json
{
  "status": "accepted",
  "message": "Wallet response processed successfully"
}
```

## Testing with cURL

### 1. Initiate a transaction:

```bash
curl -X POST http://localhost:8000/ui/presentations \
  -H "Content-Type: application/json" \
  -d '{
    "dcql_query": {
      "credentials": [{
        "id": "test_cred",
        "format": "dc+sd-jwt"
      }]
    }
  }'
```

### 2. Get the JAR:

```bash
curl http://localhost:8000/wallet/request.jwt/YOUR_REQUEST_ID
```

### 3. Submit credentials:

```bash
curl -X POST http://localhost:8000/wallet/direct_post \
  -d "state=YOUR_REQUEST_ID&vp_token=fake-token&presentation_submission={}"
```

### 4. Get wallet response:

```bash
curl http://localhost:8000/ui/presentations/YOUR_TRANSACTION_ID
```

### 5. Get QR code:

```bash
curl http://localhost:8000/ui/presentations/YOUR_TRANSACTION_ID/qrcode \
  -o qrcode.png
```

## Configuration

The verifier can be configured via environment variables:

```bash
export VERIFIER_ID="my-verifier-001"
export VERIFIER_SIGNING_KEY="/path/to/signing-key.json"
export VERIFIER_SIGNING_ALGORITHM="ES256"
export VERIFIER_BASE_URL="https://verifier.example.com"
export VERIFIER_CLIENT_ID="my-verifier"

python examples/run_server.py
```

If no configuration is provided, the verifier uses a test configuration suitable for development.

## Integration Testing

Run the integration tests:

```bash
pytest tests/integration/test_api_flow.py -v
```

This tests the complete flow including:
- Happy path (successful credential submission)
- Error flow (wallet reports error)
- QR code generation
- Error handling for invalid IDs
