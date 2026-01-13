# EUDI Verifier Endpoint - Python Implementation

**OpenID4VP Verifier for European Digital Identity Wallet**

Python implementation of the EUDI (European Digital Identity) Verifier Endpoint, supporting OpenID for Verifiable Presentations (OpenID4VP) 1.0 specification.

---

## 🎯 Features

- ✅ **OpenID4VP 1.0** compliant verifier endpoint
- ✅ **Multiple credential formats**: SD-JWT VC and MSO MDoc (ISO 18013-5)
- ✅ **DCQL** (Digital Credential Query Language) support
- ✅ **JWT-Secured Authorization Requests** (JAR - RFC 9101)
- ✅ **Multiple response modes**: `direct_post` and `direct_post.jwt`
- ✅ **Transaction data** support for RQES (Remote Qualified Electronic Signature)
- ✅ **Certificate validation** with trust sources and LOTL
- ✅ **Hexagonal architecture** (Ports & Adapters pattern)

---

## 📋 Prerequisites

- **Python 3.10+** (3.10, 3.11, or 3.12)
- **pip** or **uv** for package management

---

## 🚀 Quick Start

### 1. Clone and Setup

```bash
cd eudi_verifier

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install package in development mode
pip install -e ".[dev]"
```

### 2. Configure

Create `.env` file:

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 3. Run Development Server

```bash
uvicorn eudi_verifier.adapter.input.web.app:app --reload --host 0.0.0.0 --port 8080
```

Visit:
- **API Docs**: http://localhost:8080/docs
- **Health Check**: http://localhost:8080/health

---

## 🏗️ Architecture

### Hexagonal Architecture (Ports & Adapters)

```
┌─────────────────────────────────────┐
│      Input Adapters                 │
│  (FastAPI, Scheduled Tasks)         │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Application Layer               │
│  (Use Cases / Business Logic)        │
│  • InitTransaction                   │
│  • PostWalletResponse                │
│  • ValidateCredentials               │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│        Domain Layer                  │
│  (Pure Business Logic)               │
│  • Presentation State Machine        │
│  • DCQL Query Language               │
│  • Verifier Configuration            │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Output Adapters                 │
│  (Persistence, Crypto, Validation)   │
└──────────────────────────────────────┘
```

### Project Structure

```
src/eudi_verifier/
├── domain/              # Pure business logic
│   ├── presentation.py  # State machine
│   ├── dcql.py          # Query language
│   ├── verifier_config.py
│   ├── transaction_data.py
│   └── clock.py
│
├── port/                # Interfaces
│   ├── input/          # Use cases
│   └── output/         # Output ports
│
├── adapter/             # Implementations
│   ├── input/          # Web API, CLI
│   └── output/         # Persistence, Crypto
│
├── config/              # Configuration
└── utils/               # Shared utilities
```

---

## 🔑 Key Concepts

### Presentation State Machine

Presentations go through 4 states:

1. **Requested** - Initial state after transaction initiated
2. **RequestObjectRetrieved** - Wallet fetched JAR
3. **Submitted** - Wallet posted credentials
4. **TimedOut** - Presentation expired

### Supported Credential Formats

- **SD-JWT VC**: Selective Disclosure JWT Verifiable Credentials
- **MSO MDoc**: ISO/IEC 18013-5 Mobile Driving License format

### Client ID Schemes

- **pre-registered**: Traditional OAuth client_id
- **x509_san_dns**: DNS name from certificate SAN
- **x509_hash**: SHA-256 hash of certificate

---

## 🧪 Testing

### Run All Tests

```bash
pytest
```

### With Coverage

```bash
pytest --cov=eudi_verifier --cov-report=html
```

### Type Checking

```bash
mypy src/
```

### Linting

```bash
# Check
ruff check src/
black --check src/

# Fix
ruff check --fix src/
black src/
```

---

## 📚 API Documentation

### Verifier API (UI/Backend)

#### Initialize Transaction

```http
POST /ui/presentations
Content-Type: application/json

{
  "dcql_query": { ... },
  "nonce": "random-nonce",
  "response_mode": "direct_post"
}
```

**Response**: JSON with `transaction_id`, `client_id`, and `request`/`request_uri`

Or request QR code:

```http
POST /ui/presentations
Accept: image/png
```

**Response**: PNG image of QR code

#### Get Wallet Response

```http
GET /ui/presentations/{transactionId}?response_code={code}
```

### Wallet API

#### Retrieve Request Object

```http
GET /wallet/request.jwt/{requestId}
Accept: application/oauth-authz-req+jwt
```

**Response**: JWT (JAR)

#### Submit Wallet Response

```http
POST /wallet/direct_post/{requestId}
Content-Type: application/x-www-form-urlencoded

state={requestId}&vp_token={credentials}
```

---

## ⚙️ Configuration

Configuration via environment variables or `.env` file:

```bash
# Server
HOST=0.0.0.0
PORT=8080

# Verifier
VERIFIER_CLIENT_ID=https://verifier.example.com
VERIFIER_PUBLIC_URL=https://verifier.example.com

# JAR Signing
JAR_SIGNING_KEY_PATH=/path/to/keystore.jks
JAR_SIGNING_KEY_PASSWORD=secret
JAR_SIGNING_ALGORITHM=RS256

# Trust Sources
TRUST_KEYSTORE_PATH=/path/to/trusted-issuers.jks
LOTL_URL=https://ec.europa.eu/tools/lotl/eu-lotl.xml

# Response Mode
DEFAULT_RESPONSE_MODE=direct_post
MAX_AGE_SECONDS=6400
```

---

## 🔐 Security

- All JWTs are signed and optionally encrypted
- Certificate chains validated against trust sources
- Nonce-based replay protection
- Configurable CORS policies
- Status list checking for revocation

---

## 📖 Documentation

- [Architecture](docs/architecture.md)
- [API Reference](docs/api.md)
- [Design Documents](../design_docs/)
- [Deployment Guide](docs/deployment.md)

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

## 📄 License

Apache License 2.0 - see [LICENSE](LICENSE) file

---

## 🙏 Acknowledgments

- Based on the Kotlin implementation by the EUDI team
- Implements OpenID4VP 1.0 specification
- Supports IETF SD-JWT VC and ISO 18013-5 standards

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-python/issues)
- **Discussions**: [GitHub Discussions](https://github.com/eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-python/discussions)

---

**Status**: 🚧 Under Active Development - Phase 1 Complete

**Version**: 0.1.0
