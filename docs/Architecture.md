  All use cases follow the hexagonal architecture pattern:

  Input Port (Interface) → Use Case Implementation → Domain + Output Ports
       ↓                          ↓                         ↓
    Request DTO             Orchestration Logic      Repository/Services
       ↓                          ↓                         ↓
    Response DTO              Result<Success, Error>   External Systems

  Key Patterns Used:
  - Functional error handling with Returns library (Success/Failure)
  - Dependency injection via constructor
  - Async/await for all I/O operations
  - Domain state machine for presentation lifecycle
  - Clear separation between use case logic and domain logic

  A. Unit Tests (Recommended to validate domain logic)
  - Create comprehensive test suite for all domain models
  - Test state transitions, validation rules, edge cases
  - Target 100% coverage for domain layer
  - Estimated: ~600-800 LOC of tests

  B. Port Layer (Input/Output interfaces)
  - Define use case interfaces (InitTransaction, PostWalletResponse)
  - Define repository interfaces (PresentationRepository)
  - Define adapter interfaces (JoseService, ValidationService)
  - Estimated: ~400 LOC of interfaces

  C. Adapter Layer (Implementations)
  - Start with in-memory repository
  - Implement JAR creation with joserfc
  - Build FastAPI web endpoints
  - Estimated: ~1,500 LOC initial adapters

  Architecture Summary

  The adapter layer completes the hexagonal architecture:

  ┌─────────────────────────────────────────────────────────┐
  │                    FastAPI Endpoints                     │
  │                    (Not yet implemented)                 │
  └──────────────────────┬──────────────────────────────────┘
                         │
          ┌──────────────▼──────────────┐
          │  Application Layer (Phase 3) │
          │  - InitTransactionImpl       │
          │  - GetRequestObjectImpl      │
          │  - PostWalletResponseImpl    │
          │  - GetWalletResponseImpl     │
          └──────────────┬──────────────┘
                         │
          ┌──────────────▼──────────────┐
          │   Domain Layer (Phase 1)    │
          │   - Presentation FSM        │
          │   - DCQL                    │
          │   - VerifierConfig          │
          │   - TransactionData         │
          └──────────────┬──────────────┘
                         │
          ┌──────────────▼──────────────┐
          │   Port Layer (Phase 2)      │
          │   - Input Ports (Use Cases) │
          │   - Output Ports (Adapters) │
          └──────────────┬──────────────┘
                         │
          ┌──────────────▼──────────────┐
          │  Adapter Layer (Phase 4) ✓  │
          │  - Repository               │
          │  - JOSE Service             │
          │  - Validation Service       │
          │  - QR Code Service          │
          └─────────────────────────────┘

API Flow Diagram

  ┌─────────────────────────────────────────────────────┐
  │              Verifier UI (Browser/App)              │
  └────────────────────┬────────────────────────────────┘
                       │
          POST /ui/presentations (DCQL)
                       ↓
          ┌────────────────────────────┐
          │   transaction_id           │
          │   request_id               │
          │   authorization_request_uri│
          │   qr_code_url              │
          └────────────┬───────────────┘
                       │
          GET /ui/presentations/{txn_id}/qrcode
                       ↓
          ┌────────────────────────────┐
          │    QR Code (PNG/SVG)       │
          └────────────┬───────────────┘
                       │
                       │ Wallet scans QR
                       ↓
  ┌──────────────────────────────────────────────────────┐
  │              EUDI Wallet (Mobile App)                │
  └────────────────────┬─────────────────────────────────┘
                       │
          GET /wallet/request.jwt/{request_id}
                       ↓
          ┌────────────────────────────┐
          │    JAR (Signed JWT)        │
          └────────────┬───────────────┘
                       │
          POST /wallet/direct_post (vp_token)
                       ↓
          ┌────────────────────────────┐
          │   status: accepted         │
          └────────────────────────────┘
                       │
                       │ Verifier polls
                       ↓
  ┌──────────────────────────────────────────────────────┐
  │              Verifier UI (Browser/App)               │
  └────────────────────┬─────────────────────────────────┘
                       │
          GET /ui/presentations/{transaction_id}
                       ↓
          ┌────────────────────────────┐
          │   wallet_response          │
          │   validated_credentials    │
          │   is_completed: true       │
          │   is_successful: true      │
          └────────────────────────────┘

  Complete Architecture Stack

  ┌─────────────────────────────────────────────────┐
  │              FastAPI Endpoints ✓                 │
  │     /ui/*  |  /wallet/*  |  /health             │
  └──────────────────┬──────────────────────────────┘
                     │
  ┌──────────────────▼──────────────────────────────┐
  │         Dependency Injection ✓                   │
  │    Container manages all layer wiring           │
  └──────────────────┬──────────────────────────────┘
                     │
  ┌──────────────────▼──────────────────────────────┐
  │          Application Layer ✓                     │
  │  InitTransaction | GetRequestObject             │
  │  PostWalletResponse | GetWalletResponse         │
  └──────────────────┬──────────────────────────────┘
                     │
  ┌──────────────────▼──────────────────────────────┐
  │           Domain Layer ✓                         │
  │  Presentation FSM | DCQL | VerifierConfig       │
  └──────────────────┬──────────────────────────────┘
                     │
  ┌──────────────────▼──────────────────────────────┐
  │           Port Layer ✓                           │
  │   Input Ports (Use Cases)                       │
  │   Output Ports (Adapters)                       │
  └──────────────────┬──────────────────────────────┘
                     │
  ┌──────────────────▼──────────────────────────────┐
  │          Adapter Layer ✓                         │
  │  Repository | JOSE | Validation | QR Codes      │
  └──────────────────────────────────────────────────┘

 