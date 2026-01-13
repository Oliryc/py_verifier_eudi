# Presentation State Machine - Detailed Design

**Document Version**: 1.0
**Last Updated**: 2025-01-03
**Status**: Design Phase

---

## 1. STATE MACHINE OVERVIEW

The Presentation entity has 4 states representing the credential presentation lifecycle:

```
┌─────────────┐
│  Requested  │  ← Initial state after InitTransaction
└──────┬──────┘
       │
       │ retrieveRequestObject()
       ▼
┌───────────────────────┐
│RequestObjectRetrieved │  ← Wallet fetched JAR
└──────┬────────────────┘
       │
       │ submit()
       ▼
┌──────────┐
│Submitted │  ← Wallet posted response
└──────────┘

       │ timeout() from any state
       ▼
┌──────────┐
│TimedOut  │  ← Presentation expired
└──────────┘
```

---

## 2. PYTHON IMPLEMENTATION

### 2.1 Base Class and States

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List
from returns.result import Result, Success, Failure

class Presentation(ABC):
    """Base class for all presentation states"""

    @property
    @abstractmethod
    def id(self) -> TransactionId:
        pass

    @property
    @abstractmethod
    def initiated_at(self) -> datetime:
        pass

@dataclass(frozen=True)
class PresentationRequested(Presentation):
    """Initial state - presentation requested but JAR not yet retrieved"""
    id: TransactionId
    initiated_at: datetime
    query: DCQL
    transaction_data: Optional[List[TransactionData]]
    request_id: RequestId
    request_uri_method: RequestUriMethod
    nonce: Nonce
    response_mode: ResponseMode
    get_wallet_response_method: GetWalletResponseMethod
    issuer_chain: Optional[List[X509Certificate]]

@dataclass(frozen=True)
class PresentationRequestObjectRetrieved(Presentation):
    """JAR has been retrieved by wallet"""
    id: TransactionId
    initiated_at: datetime
    query: DCQL
    transaction_data: Optional[List[TransactionData]]
    request_id: RequestId
    request_object_retrieved_at: datetime
    nonce: Nonce
    response_mode: ResponseMode
    get_wallet_response_method: GetWalletResponseMethod
    issuer_chain: Optional[List[X509Certificate]]

    def __post_init__(self):
        # Validate timestamps
        if self.initiated_at > self.request_object_retrieved_at:
            raise ValueError("initiated_at must be <= request_object_retrieved_at")

@dataclass(frozen=True)
class PresentationSubmitted(Presentation):
    """Wallet has submitted response"""
    id: TransactionId
    initiated_at: datetime
    request_id: RequestId
    request_object_retrieved_at: datetime
    submitted_at: datetime
    wallet_response: WalletResponse
    nonce: Nonce
    response_code: Optional[ResponseCode]

    def __post_init__(self):
        if self.initiated_at > self.request_object_retrieved_at:
            raise ValueError("initiated_at must be <= request_object_retrieved_at")
        if self.request_object_retrieved_at > self.submitted_at:
            raise ValueError("request_object_retrieved_at must be <= submitted_at")

@dataclass(frozen=True)
class PresentationTimedOut(Presentation):
    """Presentation has expired"""
    id: TransactionId
    initiated_at: datetime
    request_object_retrieved_at: Optional[datetime]
    submitted_at: Optional[datetime]
    timed_out_at: datetime

    def __post_init__(self):
        if self.initiated_at >= self.timed_out_at:
            raise ValueError("initiated_at must be < timed_out_at")
```

### 2.2 State Transitions

```python
class PresentationTransitions:
    """State transition logic"""

    @staticmethod
    def retrieve_request_object(
        requested: PresentationRequested,
        clock: Clock
    ) -> Result[PresentationRequestObjectRetrieved, Exception]:
        """Transition: Requested → RequestObjectRetrieved"""
        try:
            return Success(PresentationRequestObjectRetrieved(
                id=requested.id,
                initiated_at=requested.initiated_at,
                query=requested.query,
                transaction_data=requested.transaction_data,
                request_id=requested.request_id,
                request_object_retrieved_at=clock.now(),
                nonce=requested.nonce,
                response_mode=requested.response_mode,
                get_wallet_response_method=requested.get_wallet_response_method,
                issuer_chain=requested.issuer_chain
            ))
        except ValueError as e:
            return Failure(e)

    @staticmethod
    def submit(
        retrieved: PresentationRequestObjectRetrieved,
        clock: Clock,
        wallet_response: WalletResponse,
        response_code: Optional[ResponseCode]
    ) -> Result[PresentationSubmitted, Exception]:
        """Transition: RequestObjectRetrieved → Submitted"""
        try:
            return Success(PresentationSubmitted(
                id=retrieved.id,
                initiated_at=retrieved.initiated_at,
                request_id=retrieved.request_id,
                request_object_retrieved_at=retrieved.request_object_retrieved_at,
                submitted_at=clock.now(),
                wallet_response=wallet_response,
                nonce=retrieved.nonce,
                response_code=response_code
            ))
        except ValueError as e:
            return Failure(e)

    @staticmethod
    def timeout_requested(
        requested: PresentationRequested,
        clock: Clock
    ) -> Result[PresentationTimedOut, Exception]:
        """Transition: Requested → TimedOut"""
        try:
            now = clock.now()
            return Success(PresentationTimedOut(
                id=requested.id,
                initiated_at=requested.initiated_at,
                request_object_retrieved_at=None,
                submitted_at=None,
                timed_out_at=now
            ))
        except ValueError as e:
            return Failure(e)

    @staticmethod
    def timeout_retrieved(
        retrieved: PresentationRequestObjectRetrieved,
        clock: Clock
    ) -> Result[PresentationTimedOut, Exception]:
        """Transition: RequestObjectRetrieved → TimedOut"""
        try:
            return Success(PresentationTimedOut(
                id=retrieved.id,
                initiated_at=retrieved.initiated_at,
                request_object_retrieved_at=retrieved.request_object_retrieved_at,
                submitted_at=None,
                timed_out_at=clock.now()
            ))
        except ValueError as e:
            return Failure(e)

    @staticmethod
    def timeout_submitted(
        submitted: PresentationSubmitted,
        clock: Clock
    ) -> Result[PresentationTimedOut, Exception]:
        """Transition: Submitted → TimedOut"""
        try:
            return Success(PresentationTimedOut(
                id=submitted.id,
                initiated_at=submitted.initiated_at,
                request_object_retrieved_at=submitted.request_object_retrieved_at,
                submitted_at=submitted.submitted_at,
                timed_out_at=clock.now()
            ))
        except ValueError as e:
            return Failure(e)
```

### 2.3 Expiration Logic

```python
def is_expired(presentation: Presentation, at: datetime) -> bool:
    """Check if presentation is expired at given time"""
    match presentation:
        case PresentationRequested():
            return presentation.initiated_at <= at
        case PresentationRequestObjectRetrieved():
            return presentation.request_object_retrieved_at <= at
        case PresentationSubmitted():
            return presentation.initiated_at <= at
        case PresentationTimedOut():
            return False  # Already timed out
```

---

## 3. PATTERN MATCHING

Python 3.10+ structural pattern matching provides exhaustive checking:

```python
def handle_presentation(p: Presentation) -> str:
    match p:
        case PresentationRequested():
            return "Waiting for wallet to fetch JAR"
        case PresentationRequestObjectRetrieved():
            return "Waiting for wallet response"
        case PresentationSubmitted():
            return "Presentation submitted"
        case PresentationTimedOut():
            return "Presentation timed out"
        case _:
            raise ValueError(f"Unknown presentation type: {type(p)}")
```

For Python < 3.10, use isinstance:

```python
def handle_presentation(p: Presentation) -> str:
    if isinstance(p, PresentationRequested):
        return "Waiting for wallet to fetch JAR"
    elif isinstance(p, PresentationRequestObjectRetrieved):
        return "Waiting for wallet response"
    elif isinstance(p, PresentationSubmitted):
        return "Presentation submitted"
    elif isinstance(p, PresentationTimedOut):
        return "Presentation timed out"
    else:
        raise ValueError(f"Unknown presentation type: {type(p)}")
```

---

## 4. TESTING

```python
import pytest
from datetime import datetime, timedelta

class TestPresentationStateMachine:

    def test_requested_to_retrieved_transition(self):
        """Test Requested → RequestObjectRetrieved"""
        clock = FixedClock(datetime(2024, 1, 1, 12, 0, 0))

        requested = PresentationRequested(
            id=TransactionId("tx-123"),
            initiated_at=clock.now(),
            query=Mock(),
            transaction_data=None,
            request_id=RequestId("req-456"),
            request_uri_method=RequestUriMethod.GET,
            nonce=Nonce("nonce-789"),
            response_mode=ResponseMode.DirectPost,
            get_wallet_response_method=GetWalletResponseMethod.Poll,
            issuer_chain=None
        )

        # Advance clock
        clock.advance(timedelta(seconds=5))

        # Transition
        result = PresentationTransitions.retrieve_request_object(requested, clock)

        assert isinstance(result, Success)
        retrieved = result.unwrap()
        assert isinstance(retrieved, PresentationRequestObjectRetrieved)
        assert retrieved.request_object_retrieved_at == clock.now()

    def test_invalid_timestamp_rejected(self):
        """Test that invalid timestamps are rejected"""
        with pytest.raises(ValueError, match="initiated_at"):
            PresentationRequestObjectRetrieved(
                id=TransactionId("tx-123"),
                initiated_at=datetime(2024, 1, 1, 12, 0, 0),
                query=Mock(),
                transaction_data=None,
                request_id=RequestId("req-456"),
                request_object_retrieved_at=datetime(2024, 1, 1, 11, 0, 0),  # Before initiated_at!
                nonce=Nonce("nonce-789"),
                response_mode=ResponseMode.DirectPost,
                get_wallet_response_method=GetWalletResponseMethod.Poll,
                issuer_chain=None
            )

    def test_expiration_checking(self):
        """Test expiration logic"""
        now = datetime(2024, 1, 1, 12, 0, 0)
        requested = PresentationRequested(
            id=TransactionId("tx-123"),
            initiated_at=now,
            # ... other fields
        )

        # Not expired at same time
        assert not is_expired(requested, now)

        # Expired one second later
        assert is_expired(requested, now + timedelta(seconds=1))
```

---

## 5. KEY DESIGN DECISIONS

### 5.1 Immutability
All presentation states are frozen dataclasses - transitions create new instances

### 5.2 Timestamp Validation
Timestamps are validated at construction time via `__post_init__`

### 5.3 Type Safety
Using sealed hierarchy (ABC + pattern matching/isinstance) ensures exhaustive handling

### 5.4 Transition Functions
Separate transition functions return Result types for error handling

---

**End of State Machine Design Document**
