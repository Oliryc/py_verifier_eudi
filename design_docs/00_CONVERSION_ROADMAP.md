# EUDI Verifier Endpoint - Kotlin to Python Conversion Roadmap

**Document Version**: 1.0
**Last Updated**: 2025-01-03
**Status**: Ready for Implementation

---

## EXECUTIVE SUMMARY

This document provides the complete roadmap for converting the EUDI Verifier Endpoint from Kotlin/Spring Boot to Python/FastAPI. The conversion maintains API compatibility, hexagonal architecture, and all security features while adapting to Python idioms and libraries.

**Total Estimated Effort**: 10-12 weeks (1 full-time developer)

---

## TABLE OF CONTENTS

1. [Architecture Overview](#1-architecture-overview)
2. [Design Documents Index](#2-design-documents-index)
3. [Technology Stack](#3-technology-stack)
4. [Implementation Phases](#4-implementation-phases)
5. [Dependencies](#5-dependencies)
6. [Project Structure](#6-project-structure)
7. [Success Criteria](#7-success-criteria)
8. [Risk Mitigation](#8-risk-mitigation)

---

## 1. ARCHITECTURE OVERVIEW

### 1.1 Hexagonal Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     ADAPTERS (Input)                     │
│  ┌──────────┐  ┌────────┐  ┌───────────┐              │
│  │FastAPI   │  │Scheduled│  │CLI Utils  │              │
│  │Web API   │  │Tasks    │  │           │              │
│  └────┬─────┘  └────┬───┘  └─────┬─────┘              │
├───────┼─────────────┼─────────────┼──────────────────────┤
│       │             │             │                      │
│  ┌────▼─────────────▼─────────────▼────┐                │
│  │         APPLICATION LAYER            │                │
│  │                                      │                │
│  │  ┌────────────────────────────┐    │                │
│  │  │ Use Cases (Input Ports)    │    │                │
│  │  ├────────────────────────────┤    │                │
│  │  │ • InitTransaction          │    │                │
│  │  │ • PostWalletResponse       │    │                │
│  │  │ • GetWalletResponse        │    │                │
│  │  │ • RetrieveRequestObject    │    │                │
│  │  │ • ValidateSdJwtVc         │    │                │
│  │  │ • ValidateMsoMdoc         │    │                │
│  │  └────────────────────────────┘    │                │
│  │                                      │                │
│  │  ┌────────────────────────────┐    │                │
│  │  │ Output Ports (Interfaces)  │    │                │
│  │  ├────────────────────────────┤    │                │
│  │  │ • StorePresentation        │    │                │
│  │  │ • CreateJar                │    │                │
│  │  │ • ValidateVerifiablePresentation│                │
│  │  │ • FetchLOTLCertificates    │    │                │
│  │  └────────────────────────────┘    │                │
│  └───────────────────────────────────┘                │
├─────────────────────────────────────────────────────────┤
│                    DOMAIN LAYER                          │
│  ┌───────────────────────────────────────────────┐     │
│  │ Pure Business Logic (No Dependencies)         │     │
│  ├───────────────────────────────────────────────┤     │
│  │ • Presentation (State Machine)                │     │
│  │ • DCQL (Query Language)                       │     │
│  │ • VerifierConfig                              │     │
│  │ • TransactionData                             │     │
│  │ • WalletResponse, VerifiablePresentation     │     │
│  └───────────────────────────────────────────────┘     │
├─────────────────────────────────────────────────────────┤
│                  ADAPTERS (Output)                       │
│  ┌──────────┐  ┌─────────┐  ┌────────┐  ┌──────────┐ │
│  │ In-Memory│  │ JAR     │  │ SD-JWT │  │ MSO MDoc │ │
│  │ Repo     │  │ Creator │  │ Validator│  │Validator│ │
│  │          │  │         │  │        │  │          │ │
│  └──────────┘  └─────────┘  └────────┘  └──────────┘ │
│  ┌──────────┐  ┌─────────┐  ┌────────┐               │
│  │ Trust    │  │ LOTL    │  │ QR Code│               │
│  │ Sources  │  │ Fetcher │  │Generator│               │
│  └──────────┘  └─────────┘  └────────┘               │
└─────────────────────────────────────────────────────────┘
```

### 1.2 Key Design Patterns

- **Sealed Classes** → Python Union types + pattern matching (3.10+) or isinstance
- **Arrow Either** → `returns` library Result types
- **Kotlin Coroutines** → Python async/await
- **Spring WebFlux** → FastAPI with async handlers
- **Kotlinx Serialization** → Pydantic models
- **Value Classes** → Frozen dataclasses

---

## 2. DESIGN DOCUMENTS INDEX

Detailed technical specifications for each subsystem:

| # | Document | Purpose | Complexity |
|---|----------|---------|------------|
| 01 | [SD-JWT VC Validation](01_SD_JWT_VC_VALIDATION.md) | Validates Selective Disclosure JWT VCs | High |
| 02 | [MSO MDoc Validation](02_MSO_MDOC_VALIDATION.md) | Validates ISO 18013-5 mobile documents | Very High |
| 03 | [DCQL Validation](03_DCQL_VALIDATION.md) | Digital Credential Query Language | Medium |
| 04 | [JAR Creation](04_JAR_CREATION_AND_ENCRYPTION.md) | JWT-Secured Authorization Requests | Medium |
| 05 | [State Machine](05_PRESENTATION_STATE_MACHINE.md) | Presentation lifecycle management | Medium |
| 06 | [Trust Sources](06_TRUST_SOURCES_AND_CERTIFICATE_VALIDATION.md) | Certificate validation & LOTL | High |

---

## 3. TECHNOLOGY STACK

### 3.1 Core Framework

```python
# requirements.txt
fastapi[all]==0.109.0
uvicorn[standard]==0.27.0
pydantic==2.5.3
pydantic-settings==2.1.0
python-multipart==0.0.6
```

### 3.2 Functional Programming

```python
returns==0.22.0  # Result types, Maybe, IO
attrs==23.2.0    # Alternative to dataclasses with more features
```

### 3.3 Cryptography & JWT

```python
# Option 1: python-jose (more common)
python-jose[cryptography]==3.3.0

# Option 2: joserfc (more modern, better maintained)
joserfc==0.9.0

jwcrypto==1.5.1
cryptography==42.0.0
```

### 3.4 Credential Validation

```python
# SD-JWT VC
sd-jwt==0.10.0
jsonschema==4.21.1

# MSO MDoc
cbor2==5.6.0
pycose==1.1.0
asn1crypto==1.5.1
```

### 3.5 Certificate & Trust

```python
pyOpenSSL==24.0.0
pyjks==20.0.0  # JKS keystore support
```

### 3.6 HTTP & Scheduling

```python
httpx==0.26.0  # Async HTTP client
apscheduler==3.10.4
```

### 3.7 Utilities

```python
qrcode[pil]==7.4.2
structlog==24.1.0  # Structured logging
cachetools==5.3.2
```

### 3.8 Development & Testing

```python
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
black==23.12.1
ruff==0.1.9
mypy==1.8.0
```

---

## 4. IMPLEMENTATION PHASES

### PHASE 1: Foundation (Week 1-2) - 2 weeks

**Goal**: Core domain models and infrastructure

#### Week 1: Domain Models
- [ ] Project structure and configuration
- [ ] Value objects: TransactionId, RequestId, Nonce, Format, etc.
- [ ] Presentation state machine (all 4 states + transitions)
- [ ] Clock abstraction
- [ ] Result/Either pattern setup with returns

#### Week 2: DCQL & Configuration
- [ ] DCQL models (ClaimsQuery → CredentialQuery → DCQL)
- [ ] Pydantic validation for DCQL
- [ ] VerifierConfig with all nested structures
- [ ] TransactionData models (base + QesAuthorization + QCertCreationAcceptance)
- [ ] Error types and ValidationError hierarchy

**Deliverables**:
- [ ] All domain models with unit tests
- [ ] 100% test coverage for domain layer
- [ ] Validation logic working

---

### PHASE 2: Cryptography (Week 2-4) - 2 weeks

**Goal**: JAR creation, encryption, certificate handling

#### Week 3: JAR & JWT
- [ ] SigningConfig with validation
- [ ] JAR creation (CreateJarImpl)
- [ ] JWT signing with x5c and kid headers
- [ ] VerifierId implementations (PreRegistered, X509SanDns, X509Hash)
- [ ] X.509 SAN extraction and validation
- [ ] Certificate hash computation

#### Week 4: Encryption & Trust
- [ ] Ephemeral key generation for DirectPostJwt
- [ ] JWE encryption for JAR (wallet encryption)
- [ ] JWE decryption for responses
- [ ] PEM certificate parsing
- [ ] X5CValidator implementation
- [ ] TrustSourcesManager (keystore loading)

**Deliverables**:
- [ ] JAR creation working end-to-end
- [ ] All three client ID schemes validated
- [ ] Certificate chain validation functional
- [ ] Unit tests for all crypto operations

---

### PHASE 3: Credential Validation (Week 4-6) - 2.5 weeks

**Goal**: SD-JWT VC and MSO MDoc validation

#### Week 5: SD-JWT VC
- [ ] SdJwtVc parsing (JWT + disclosures + KB-JWT)
- [ ] Issuer JWT verification
- [ ] Selective disclosure verification
- [ ] Key Binding JWT validation
- [ ] TypeMetadataLookup with caching
- [ ] StatusListTokenValidator
- [ ] JSON Schema validation

#### Week 6: MSO MDoc
- [ ] CBOR DeviceResponse parsing
- [ ] Document structure validation
- [ ] IssuerAuth COSE_Sign1 verification
- [ ] MSO extraction and validation
- [ ] DeviceAuth MAC/signature verification
- [ ] SessionTranscript building
- [ ] Digest verification for disclosed attributes

**Mid-Week 6: Integration**
- [ ] ValidateSdJwtVc use case
- [ ] ValidateMsoMdoc use case
- [ ] Integration with DCQL satisfaction checking

**Deliverables**:
- [ ] SD-JWT VC validation complete
- [ ] MSO MDoc validation complete
- [ ] Test vectors from specs passing
- [ ] Both formats validated in PostWalletResponse flow

---

### PHASE 4: Use Cases (Week 6-7) - 1.5 weeks

**Goal**: All application use cases implemented

#### Week 7: Core Use Cases
- [ ] InitTransaction orchestration
  - [ ] DCQL validation
  - [ ] Response mode selection
  - [ ] JAR creation (by value/reference)
  - [ ] QR code generation
- [ ] RetrieveRequestObject
  - [ ] JAR retrieval by requestId
  - [ ] State transition to RequestObjectRetrieved
- [ ] PostWalletResponse
  - [ ] Response decryption (if DirectPostJwt)
  - [ ] Credential validation orchestration
  - [ ] DCQL satisfaction checking
  - [ ] State transition to Submitted
- [ ] GetWalletResponse (polling)
- [ ] GetPresentationEvents

**Deliverables**:
- [ ] All 10 use cases implemented
- [ ] State transitions working correctly
- [ ] Transaction data validation
- [ ] Event publishing functional

---

### PHASE 5: Adapters & Infrastructure (Week 7-8) - 1.5 weeks

**Goal**: Persistence, LOTL, scheduling, utilities

#### Week 8: Adapters
- [ ] PresentationInMemoryRepo
  - [ ] Thread-safe concurrent access
  - [ ] All persistence operations
  - [ ] Event storage
- [ ] QR code generation adapter
- [ ] ID generators (TransactionId, RequestId, ResponseCode)
- [ ] LOTL fetching
  - [ ] FetchLOTLCertificatesDSS equivalent
  - [ ] XML parsing for ETSI TS 119 612
  - [ ] Service type filtering

#### Late Week 8: Scheduled Tasks
- [ ] APScheduler setup
- [ ] TimeoutPresentations job
- [ ] DeleteOldPresentations job
- [ ] RefreshTrustSources job

**Deliverables**:
- [ ] All output adapters implemented
- [ ] Scheduled tasks running
- [ ] LOTL integration working

---

### PHASE 6: Web API (Week 8-9) - 1 week

**Goal**: FastAPI REST endpoints

#### Week 9: API Implementation
- [ ] FastAPI application setup
- [ ] Dependency injection configuration
- [ ] CORS middleware
- [ ] VerifierApi
  - [ ] POST /ui/presentations
  - [ ] GET /ui/presentations/{transactionId}
  - [ ] GET /ui/presentations/{transactionId}/events
- [ ] WalletApi
  - [ ] GET /wallet/request.jwt/{requestId}
  - [ ] POST /wallet/request.jwt/{requestId}
  - [ ] POST /wallet/direct_post/{requestId}
  - [ ] GET /wallet/public-keys.json
- [ ] UtilityApi
  - [ ] POST /utilities/validate/{format}
- [ ] Error handling middleware
- [ ] OpenAPI schema generation

**Deliverables**:
- [ ] All REST endpoints functional
- [ ] OpenAPI docs available at /docs
- [ ] API compatible with Kotlin version
- [ ] CORS configured

---

### PHASE 7: Testing (Week 9-10) - 1.5 weeks

**Goal**: Comprehensive test suite

#### Week 9-10: Testing
- [ ] Unit tests for all domain models
- [ ] Unit tests for all use cases
- [ ] Unit tests for adapters
- [ ] Integration tests for API endpoints
- [ ] End-to-end OpenID4VP flow tests
- [ ] Test with both SD-JWT VC and MSO MDoc
- [ ] Test all error paths
- [ ] Load testing basic scenarios

**Coverage Goals**:
- [ ] Domain layer: 100%
- [ ] Use cases: 95%+
- [ ] Adapters: 85%+
- [ ] Overall: 90%+

**Deliverables**:
- [ ] >90% test coverage
- [ ] All happy paths tested
- [ ] Error scenarios covered
- [ ] Integration tests passing

---

### PHASE 8: Deployment & Documentation (Week 10) - 0.5 weeks

**Goal**: Production-ready deployment

#### Week 10: Finalization
- [ ] Dockerfile (multi-stage build)
- [ ] docker-compose.yml
- [ ] Environment-based configuration
- [ ] Production logging setup
- [ ] Health check endpoints
- [ ] Metrics/monitoring setup (optional)
- [ ] README.md with setup instructions
- [ ] API documentation
- [ ] Architecture documentation
- [ ] Deployment guide

**Deliverables**:
- [ ] Docker images built
- [ ] docker-compose deployable
- [ ] Complete documentation
- [ ] Production checklist

---

## 5. DEPENDENCIES

### 5.1 Complete requirements.txt

```txt
# Web Framework
fastapi[all]==0.109.0
uvicorn[standard]==0.27.0
pydantic==2.5.3
pydantic-settings==2.1.0
python-multipart==0.0.6

# Functional Programming
returns==0.22.0
attrs==23.2.0

# Cryptography & JWT
joserfc==0.9.0  # or python-jose[cryptography]==3.3.0
jwcrypto==1.5.1
cryptography==42.0.0

# Credential Validation
sd-jwt==0.10.0
jsonschema==4.21.1
cbor2==5.6.0
pycose==1.1.0
asn1crypto==1.5.1

# Certificate Handling
pyOpenSSL==24.0.0
pyjks==20.0.0

# HTTP & Scheduling
httpx==0.26.0
apscheduler==3.10.4

# Utilities
qrcode[pil]==7.4.2
structlog==24.1.0
cachetools==5.3.2

# Development
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
black==23.12.1
ruff==0.1.9
mypy==1.8.0
```

---

## 6. PROJECT STRUCTURE

```
eudi_verifier/
├── pyproject.toml
├── README.md
├── Dockerfile
├── docker-compose.yml
├── .env.example
│
├── src/
│   └── eudi_verifier/
│       ├── __init__.py
│       │
│       ├── domain/                    # Pure business logic
│       │   ├── __init__.py
│       │   ├── presentation.py        # State machine
│       │   ├── dcql.py               # DCQL models
│       │   ├── verifier_config.py    # Configuration
│       │   ├── transaction_data.py   # RQES
│       │   ├── wallet_response.py
│       │   ├── clock.py
│       │   └── errors.py
│       │
│       ├── port/                      # Interfaces
│       │   ├── __init__.py
│       │   ├── input/                # Use cases
│       │   │   ├── __init__.py
│       │   │   ├── init_transaction.py
│       │   │   ├── post_wallet_response.py
│       │   │   ├── get_wallet_response.py
│       │   │   ├── retrieve_request_object.py
│       │   │   ├── validate_sd_jwt_vc.py
│       │   │   └── validate_mso_mdoc.py
│       │   │
│       │   └── output/               # Output port interfaces
│       │       ├── __init__.py
│       │       ├── persistence.py
│       │       ├── jose.py
│       │       ├── validation.py
│       │       ├── trust.py
│       │       └── qrcode.py
│       │
│       ├── adapter/                   # Implementations
│       │   ├── __init__.py
│       │   │
│       │   ├── input/
│       │   │   ├── __init__.py
│       │   │   ├── web/
│       │   │   │   ├── __init__.py
│       │   │   │   ├── app.py        # FastAPI app
│       │   │   │   ├── verifier_api.py
│       │   │   │   ├── wallet_api.py
│       │   │   │   └── utility_api.py
│       │   │   │
│       │   │   └── scheduler/
│       │   │       ├── __init__.py
│       │   │       └── tasks.py
│       │   │
│       │   └── output/
│       │       ├── __init__.py
│       │       ├── jose/
│       │       │   ├── __init__.py
│       │       │   ├── jar_creator.py
│       │       │   └── jwe_handler.py
│       │       │
│       │       ├── validation/
│       │       │   ├── __init__.py
│       │       │   ├── sd_jwt_vc.py
│       │       │   ├── mso_mdoc.py
│       │       │   └── dcql.py
│       │       │
│       │       ├── persistence/
│       │       │   ├── __init__.py
│       │       │   └── in_memory_repo.py
│       │       │
│       │       ├── trust/
│       │       │   ├── __init__.py
│       │       │   ├── trust_sources.py
│       │       │   ├── x5c_validator.py
│       │       │   └── lotl_fetcher.py
│       │       │
│       │       └── qrcode/
│       │           ├── __init__.py
│       │           └── generator.py
│       │
│       ├── config/                    # Configuration
│       │   ├── __init__.py
│       │   ├── settings.py           # Pydantic Settings
│       │   └── dependencies.py       # DI setup
│       │
│       └── utils/                     # Shared utilities
│           ├── __init__.py
│           ├── base64.py
│           ├── hash.py
│           └── cbor.py
│
├── tests/
│   ├── __init__.py
│   ├── unit/
│   │   ├── domain/
│   │   ├── port/
│   │   └── adapter/
│   │
│   ├── integration/
│   │   └── api/
│   │
│   └── e2e/
│       └── test_openid4vp_flow.py
│
├── docs/
│   ├── architecture.md
│   ├── api.md
│   └── deployment.md
│
└── scripts/
    ├── generate_test_certs.py
    └── run_dev.sh
```

---

## 7. SUCCESS CRITERIA

### 7.1 Functional Requirements

- [ ] All REST endpoints return same responses as Kotlin version
- [ ] SD-JWT VC validation matches spec behavior
- [ ] MSO MDoc validation matches spec behavior
- [ ] DCQL satisfaction logic correct
- [ ] All client ID schemes working (pre-registered, x509_san_dns, x509_hash)
- [ ] Both response modes working (direct_post, direct_post.jwt)
- [ ] Transaction data validation functional
- [ ] State machine transitions correct
- [ ] Scheduled tasks executing

### 7.2 Non-Functional Requirements

- [ ] >90% test coverage
- [ ] No critical security vulnerabilities
- [ ] API response time <500ms (p95)
- [ ] Handles 100 concurrent presentations
- [ ] Runs in Docker container
- [ ] Configuration via environment variables
- [ ] Logging structured and comprehensive
- [ ] OpenAPI documentation complete

### 7.3 API Compatibility

Test against Kotlin version:
- [ ] Same request/response formats
- [ ] Same error codes
- [ ] Same HTTP status codes
- [ ] Same header handling
- [ ] Compatible with test wallets

---

## 8. RISK MITIGATION

### 8.1 Technical Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| **No mature MSO MDoc Python library** | High | Build custom using cbor2 + pycose; budget extra time |
| **LOTL XML parsing complexity** | Medium | Start with simple parsing; consider DSS Java lib via Jython if needed |
| **JWE encryption edge cases** | Medium | Extensive testing with test vectors; use jwcrypto |
| **Certificate validation subtleties** | High | Use cryptography library; test with real chains |
| **State machine race conditions** | Medium | Use proper locking; extensive concurrent testing |

### 8.2 Schedule Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| **MSO MDoc takes longer** | High | Front-load this work; consider 2-week buffer |
| **Integration issues** | Medium | Early integration testing; modular development |
| **Testing time underestimated** | Medium | Start testing from Phase 1; continuous testing |

### 8.3 Dependency Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| **Library compatibility issues** | Medium | Lock versions; test on fresh venv regularly |
| **sd-jwt-python incomplete** | Medium | Fork and extend if needed; budget time |
| **pycose limitations** | High | Test early; may need to extend |

---

## 9. VALIDATION CHECKPOINTS

### Checkpoint 1: End of Phase 2 (Week 4)
- [ ] All domain models working
- [ ] JAR creation functional
- [ ] Can create and verify signed JWT
- [ ] Certificate validation basic flow working

**Go/No-Go Decision**: Can we create valid JARs?

### Checkpoint 2: End of Phase 3 (Week 6)
- [ ] SD-JWT VC validation complete
- [ ] MSO MDoc validation complete
- [ ] Both formats work end-to-end in isolation

**Go/No-Go Decision**: Can we validate both credential types?

### Checkpoint 3: End of Phase 5 (Week 8)
- [ ] All use cases implemented
- [ ] Persistence working
- [ ] Scheduled tasks running
- [ ] Integration smoke tests passing

**Go/No-Go Decision**: Is the application feature-complete?

### Checkpoint 4: End of Phase 7 (Week 10)
- [ ] All tests passing
- [ ] Coverage >90%
- [ ] API compatibility verified
- [ ] Production deployment tested

**Go/No-Go Decision**: Ready for production?

---

## 10. MAINTENANCE PLAN

### Post-Conversion

**Week 11-12: Stabilization**
- Fix bugs found in testing
- Performance optimization
- Documentation cleanup
- Knowledge transfer

**Ongoing**:
- Monitor for security updates
- Keep dependencies updated
- Add features as needed
- Maintain test suite

---

## 11. CONTACT & REFERENCES

### Design Documents
- See individual design docs (01-06) for detailed technical specifications

### Specifications
- OpenID4VP 1.0: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- SD-JWT VC: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/
- ISO 18013-5: mDL specification
- RFC 9101: JWT-Secured Authorization Request (JAR)

### Code References
- Kotlin source: `/home/cyril/py_verifier_eudi/eudi-srv-web-verifier-endpoint-23220-4-kt`
- Python target: `/home/cyril/py_verifier_eudi/eudi_verifier` (to be created)

---

## 12. NEXT STEPS

1. **Review this roadmap** with stakeholders
2. **Set up development environment**
3. **Start Phase 1** - Domain models
4. **Schedule weekly check-ins**
5. **Begin implementation**

---

**Document Status**: ✅ Complete and Ready for Implementation

**Prepared by**: Claude Code Analysis System
**Date**: 2025-01-03
