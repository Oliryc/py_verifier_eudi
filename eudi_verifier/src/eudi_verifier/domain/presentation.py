"""Presentation state machine for OpenID4VP verification flow

This module implements the core state machine for managing verifiable presentation
transactions. A presentation progresses through 4 distinct states:

1. Requested - Initial state after transaction initiated
2. RequestObjectRetrieved - Wallet has fetched the JAR
3. Submitted - Wallet has posted credentials
4. TimedOut - Presentation expired before completion

All states are immutable (frozen dataclasses) and transitions are explicit.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from returns.result import Failure, Result, Success

from eudi_verifier.domain.clock import Clock
from eudi_verifier.domain.value_objects import Nonce, RequestId, TransactionId


# ======================
# State Classes
# ======================


@dataclass(frozen=True)
class PresentationRequested:
    """
    Initial state of a presentation transaction.

    Created when a verifier initiates a new transaction. Contains the
    JWT-Secured Authorization Request (JAR) and configuration needed
    for the wallet to present credentials.

    Attributes:
        transaction_id: Unique identifier for this transaction
        request_id: State parameter communicated to wallet
        jar: JWT-Secured Authorization Request (signed, optionally encrypted)
        nonce: Cryptographic nonce for replay protection
        response_mode: How wallet should respond (direct_post or direct_post.jwt)
        presentation_definition: Optional JSON presentation definition
        initiated_at: When this presentation was created
        expires_at: When this presentation expires
    """

    transaction_id: TransactionId
    request_id: RequestId
    jar: str
    nonce: Nonce
    response_mode: str
    presentation_definition: dict[str, Any] | None
    initiated_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        """Validate timestamps"""
        if self.expires_at <= self.initiated_at:
            raise ValueError(
                f"expires_at ({self.expires_at}) must be after initiated_at ({self.initiated_at})"
            )


@dataclass(frozen=True)
class PresentationRequestObjectRetrieved:
    """
    State after wallet has retrieved the request object (JAR).

    Indicates that the wallet has successfully fetched the JAR via
    the request_uri endpoint. The wallet can now prepare credentials
    and submit a response.

    Attributes:
        transaction_id: Unique identifier for this transaction
        request_id: State parameter communicated to wallet
        jar: JWT-Secured Authorization Request
        nonce: Cryptographic nonce for replay protection
        response_mode: How wallet should respond
        presentation_definition: Optional JSON presentation definition
        initiated_at: When presentation was created
        retrieved_at: When wallet fetched the JAR
        expires_at: When this presentation expires
    """

    transaction_id: TransactionId
    request_id: RequestId
    jar: str
    nonce: Nonce
    response_mode: str
    presentation_definition: dict[str, Any] | None
    initiated_at: datetime
    retrieved_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        """Validate timestamps"""
        if self.retrieved_at < self.initiated_at:
            raise ValueError(
                f"retrieved_at ({self.retrieved_at}) cannot be before initiated_at ({self.initiated_at})"
            )
        if self.expires_at <= self.initiated_at:
            raise ValueError(
                f"expires_at ({self.expires_at}) must be after initiated_at ({self.initiated_at})"
            )


@dataclass(frozen=True)
class PresentationSubmitted:
    """
    State after wallet has submitted credentials.

    The final successful state. Contains the wallet's response with
    verifiable credentials that can be validated and extracted.

    Attributes:
        transaction_id: Unique identifier for this transaction
        request_id: State parameter communicated to wallet
        initiated_at: When presentation was created
        retrieved_at: When wallet fetched the JAR
        submitted_at: When wallet posted credentials
        wallet_response: The vp_token and related data from wallet
    """

    transaction_id: TransactionId
    request_id: RequestId
    initiated_at: datetime
    retrieved_at: datetime
    submitted_at: datetime
    wallet_response: dict[str, Any]  # Will be typed more specifically in later phases

    def __post_init__(self) -> None:
        """Validate timestamps"""
        if self.retrieved_at < self.initiated_at:
            raise ValueError(
                f"retrieved_at ({self.retrieved_at}) cannot be before initiated_at ({self.initiated_at})"
            )
        if self.submitted_at < self.retrieved_at:
            raise ValueError(
                f"submitted_at ({self.submitted_at}) cannot be before retrieved_at ({self.retrieved_at})"
            )
        if not self.wallet_response:
            raise ValueError("wallet_response cannot be empty")


@dataclass(frozen=True)
class PresentationTimedOut:
    """
    State when presentation expires before completion.

    Terminal state indicating the transaction was not completed within
    the allowed time window. No credentials were received.

    Attributes:
        transaction_id: Unique identifier for this transaction
        request_id: State parameter communicated to wallet
        initiated_at: When presentation was created
        timed_out_at: When timeout was detected
        last_state: The state when timeout occurred
    """

    transaction_id: TransactionId
    request_id: RequestId
    initiated_at: datetime
    timed_out_at: datetime
    last_state: str  # "Requested" or "RequestObjectRetrieved"

    def __post_init__(self) -> None:
        """Validate timestamps and state"""
        if self.timed_out_at < self.initiated_at:
            raise ValueError(
                f"timed_out_at ({self.timed_out_at}) cannot be before initiated_at ({self.initiated_at})"
            )
        if self.last_state not in ("Requested", "RequestObjectRetrieved"):
            raise ValueError(f"Invalid last_state: {self.last_state}. Must be 'Requested' or 'RequestObjectRetrieved'")


# ======================
# Union Type (Sealed Interface)
# ======================

Presentation = (
    PresentationRequested
    | PresentationRequestObjectRetrieved
    | PresentationSubmitted
    | PresentationTimedOut
)


# ======================
# Error Types
# ======================


@dataclass(frozen=True)
class PresentationError:
    """Base error type for presentation operations"""

    message: str = ""


@dataclass(frozen=True)
class InvalidStateTransition(PresentationError):
    """Error when attempting invalid state transition"""

    current_state: str = ""
    attempted_transition: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "message",
            f"Cannot transition from {self.current_state} via {self.attempted_transition}",
        )


@dataclass(frozen=True)
class PresentationExpired(PresentationError):
    """Error when presentation has expired"""

    transaction_id: TransactionId | None = None
    expired_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.transaction_id and self.expired_at:
            object.__setattr__(
                self,
                "message",
                f"Presentation {self.transaction_id} expired at {self.expired_at}",
            )
        else:
            object.__setattr__(self, "message", "Presentation expired")


@dataclass(frozen=True)
class PresentationAlreadyCompleted(PresentationError):
    """Error when attempting to modify completed presentation"""

    transaction_id: TransactionId | None = None

    def __post_init__(self) -> None:
        if self.transaction_id:
            object.__setattr__(
                self,
                "message",
                f"Presentation {self.transaction_id} is already completed",
            )
        else:
            object.__setattr__(self, "message", "Presentation already completed")


# ======================
# State Transition Functions
# ======================


def mark_as_retrieved(
    presentation: Presentation,
    clock: Clock,
) -> Result[PresentationRequestObjectRetrieved, PresentationError]:
    """
    Transition from Requested to RequestObjectRetrieved.

    Called when wallet successfully retrieves the JAR via GET/POST to request_uri.

    Args:
        presentation: Current presentation state
        clock: Clock for timestamp generation

    Returns:
        Success with new state, or Failure with error
    """
    now = clock.now()

    # Only valid from Requested state
    if not isinstance(presentation, PresentationRequested):
        return Failure(
            InvalidStateTransition(
                current_state=type(presentation).__name__,
                attempted_transition="mark_as_retrieved",
            )
        )

    # Check not expired
    if now >= presentation.expires_at:
        return Failure(
            PresentationExpired(
                transaction_id=presentation.transaction_id,
                expired_at=presentation.expires_at,
            )
        )

    return Success(
        PresentationRequestObjectRetrieved(
            transaction_id=presentation.transaction_id,
            request_id=presentation.request_id,
            jar=presentation.jar,
            nonce=presentation.nonce,
            response_mode=presentation.response_mode,
            presentation_definition=presentation.presentation_definition,
            initiated_at=presentation.initiated_at,
            retrieved_at=now,
            expires_at=presentation.expires_at,
        )
    )


def mark_as_submitted(
    presentation: Presentation,
    wallet_response: dict[str, Any],
    clock: Clock,
) -> Result[PresentationSubmitted, PresentationError]:
    """
    Transition from RequestObjectRetrieved to Submitted.

    Called when wallet posts credentials via direct_post endpoint.

    Args:
        presentation: Current presentation state
        wallet_response: The vp_token and related data from wallet
        clock: Clock for timestamp generation

    Returns:
        Success with new state, or Failure with error
    """
    now = clock.now()

    # Only valid from RequestObjectRetrieved state
    if not isinstance(presentation, PresentationRequestObjectRetrieved):
        return Failure(
            InvalidStateTransition(
                current_state=type(presentation).__name__,
                attempted_transition="mark_as_submitted",
            )
        )

    # Check not expired
    if now >= presentation.expires_at:
        return Failure(
            PresentationExpired(
                transaction_id=presentation.transaction_id,
                expired_at=presentation.expires_at,
            )
        )

    # Validate response not empty
    if not wallet_response:
        return Failure(PresentationError(message="wallet_response cannot be empty"))

    return Success(
        PresentationSubmitted(
            transaction_id=presentation.transaction_id,
            request_id=presentation.request_id,
            initiated_at=presentation.initiated_at,
            retrieved_at=presentation.retrieved_at,
            submitted_at=now,
            wallet_response=wallet_response,
        )
    )


def mark_as_timed_out(
    presentation: Presentation,
    clock: Clock,
) -> Result[PresentationTimedOut, PresentationError]:
    """
    Transition from Requested or RequestObjectRetrieved to TimedOut.

    Called by scheduled task that checks for expired presentations.
    Cannot timeout already completed presentations.

    Args:
        presentation: Current presentation state
        clock: Clock for timestamp generation

    Returns:
        Success with new state, or Failure with error
    """
    now = clock.now()

    # Cannot timeout completed presentations
    if isinstance(presentation, (PresentationSubmitted, PresentationTimedOut)):
        return Failure(
            PresentationAlreadyCompleted(transaction_id=presentation.transaction_id)
        )

    # Determine last state
    if isinstance(presentation, PresentationRequested):
        last_state = "Requested"
    elif isinstance(presentation, PresentationRequestObjectRetrieved):
        last_state = "RequestObjectRetrieved"
    else:
        return Failure(
            InvalidStateTransition(
                current_state=type(presentation).__name__,
                attempted_transition="mark_as_timed_out",
            )
        )

    return Success(
        PresentationTimedOut(
            transaction_id=presentation.transaction_id,
            request_id=presentation.request_id,
            initiated_at=presentation.initiated_at,
            timed_out_at=now,
            last_state=last_state,
        )
    )


# ======================
# Query Functions
# ======================


def is_expired(presentation: Presentation, clock: Clock) -> bool:
    """
    Check if presentation has expired.

    Completed (Submitted) and already TimedOut presentations are not considered expired.

    Args:
        presentation: Presentation to check
        clock: Clock for current time

    Returns:
        True if presentation is expired, False otherwise
    """
    # Completed presentations are not expired
    if isinstance(presentation, (PresentationSubmitted, PresentationTimedOut)):
        return False

    # Check expires_at
    if isinstance(presentation, PresentationRequested):
        return clock.now() >= presentation.expires_at
    elif isinstance(presentation, PresentationRequestObjectRetrieved):
        return clock.now() >= presentation.expires_at

    return False


def get_transaction_id(presentation: Presentation) -> TransactionId:
    """Get transaction ID from any presentation state"""
    return presentation.transaction_id


def get_request_id(presentation: Presentation) -> RequestId:
    """Get request ID from any presentation state"""
    return presentation.request_id


def is_completed(presentation: Presentation) -> bool:
    """Check if presentation is in terminal state (Submitted or TimedOut)"""
    return isinstance(presentation, (PresentationSubmitted, PresentationTimedOut))


def is_successful(presentation: Presentation) -> bool:
    """Check if presentation completed successfully with credentials"""
    return isinstance(presentation, PresentationSubmitted)


# ======================
# Factory Functions
# ======================


def create_presentation_requested(
    transaction_id: TransactionId,
    request_id: RequestId,
    jar: str,
    nonce: Nonce,
    response_mode: str,
    presentation_definition: dict[str, Any] | None,
    max_age: timedelta,
    clock: Clock,
) -> PresentationRequested:
    """
    Create initial Requested presentation.

    Args:
        transaction_id: Unique transaction identifier
        request_id: State parameter for wallet correlation
        jar: JWT-Secured Authorization Request
        nonce: Cryptographic nonce
        response_mode: direct_post or direct_post.jwt
        presentation_definition: Optional PD for wallet
        max_age: How long presentation is valid
        clock: Clock for timestamp generation

    Returns:
        New PresentationRequested instance
    """
    now = clock.now()
    return PresentationRequested(
        transaction_id=transaction_id,
        request_id=request_id,
        jar=jar,
        nonce=nonce,
        response_mode=response_mode,
        presentation_definition=presentation_definition,
        initiated_at=now,
        expires_at=now + max_age,
    )
