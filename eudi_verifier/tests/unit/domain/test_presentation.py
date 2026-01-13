"""Tests for Presentation state machine"""

from datetime import datetime, timedelta, timezone

import pytest
from returns.result import Failure, Success

from eudi_verifier.domain import (
    FixedClock,
    TransactionId,
    RequestId,
    Nonce,
    PresentationRequested,
    PresentationRequestObjectRetrieved,
    PresentationSubmitted,
    PresentationTimedOut,
    PresentationError,
    InvalidStateTransition,
    PresentationExpired,
    PresentationAlreadyCompleted,
    mark_as_retrieved,
    mark_as_submitted,
    mark_as_timed_out,
    is_expired,
    is_completed,
    is_successful,
    get_transaction_id,
    get_request_id,
    create_presentation_requested,
)


class TestPresentationRequested:
    """Tests for PresentationRequested state"""

    def test_create_valid_presentation(
        self, transaction_id: TransactionId, request_id: RequestId, nonce: Nonce, fixed_clock: FixedClock
    ):
        """Can create valid PresentationRequested"""
        initiated = fixed_clock.now()
        expires = initiated + timedelta(hours=1)

        presentation = PresentationRequested(
            transaction_id=transaction_id,
            request_id=request_id,
            jar="eyJhbGciOiJSUzI1NiJ9...",
            nonce=nonce,
            response_mode="direct_post",
            presentation_definition=None,
            initiated_at=initiated,
            expires_at=expires,
        )

        assert presentation.transaction_id == transaction_id
        assert presentation.request_id == request_id
        assert presentation.nonce == nonce
        assert presentation.initiated_at == initiated
        assert presentation.expires_at == expires

    def test_immutable(
        self, transaction_id: TransactionId, request_id: RequestId, nonce: Nonce, fixed_clock: FixedClock
    ):
        """PresentationRequested is immutable"""
        initiated = fixed_clock.now()
        presentation = PresentationRequested(
            transaction_id=transaction_id,
            request_id=request_id,
            jar="test",
            nonce=nonce,
            response_mode="direct_post",
            presentation_definition=None,
            initiated_at=initiated,
            expires_at=initiated + timedelta(hours=1),
        )

        with pytest.raises(Exception):
            presentation.jar = "modified"

    def test_expires_before_initiated_raises_error(
        self, transaction_id: TransactionId, request_id: RequestId, nonce: Nonce, fixed_clock: FixedClock
    ):
        """expires_at before initiated_at raises ValueError"""
        initiated = fixed_clock.now()
        expires = initiated - timedelta(seconds=1)

        with pytest.raises(ValueError, match="expires_at.*must be after initiated_at"):
            PresentationRequested(
                transaction_id=transaction_id,
                request_id=request_id,
                jar="test",
                nonce=nonce,
                response_mode="direct_post",
                presentation_definition=None,
                initiated_at=initiated,
                expires_at=expires,
            )


class TestPresentationRequestObjectRetrieved:
    """Tests for PresentationRequestObjectRetrieved state"""

    def test_create_valid_presentation(
        self, transaction_id: TransactionId, request_id: RequestId, nonce: Nonce, fixed_clock: FixedClock
    ):
        """Can create valid PresentationRequestObjectRetrieved"""
        initiated = fixed_clock.now()
        retrieved = initiated + timedelta(seconds=5)
        expires = initiated + timedelta(hours=1)

        presentation = PresentationRequestObjectRetrieved(
            transaction_id=transaction_id,
            request_id=request_id,
            jar="test",
            nonce=nonce,
            response_mode="direct_post",
            presentation_definition=None,
            initiated_at=initiated,
            retrieved_at=retrieved,
            expires_at=expires,
        )

        assert presentation.retrieved_at == retrieved

    def test_retrieved_before_initiated_raises_error(
        self, transaction_id: TransactionId, request_id: RequestId, nonce: Nonce, fixed_clock: FixedClock
    ):
        """retrieved_at before initiated_at raises ValueError"""
        initiated = fixed_clock.now()
        retrieved = initiated - timedelta(seconds=1)

        with pytest.raises(ValueError, match="retrieved_at.*cannot be before initiated_at"):
            PresentationRequestObjectRetrieved(
                transaction_id=transaction_id,
                request_id=request_id,
                jar="test",
                nonce=nonce,
                response_mode="direct_post",
                presentation_definition=None,
                initiated_at=initiated,
                retrieved_at=retrieved,
                expires_at=initiated + timedelta(hours=1),
            )


class TestPresentationSubmitted:
    """Tests for PresentationSubmitted state"""

    def test_create_valid_presentation(
        self, transaction_id: TransactionId, request_id: RequestId, fixed_clock: FixedClock
    ):
        """Can create valid PresentationSubmitted"""
        initiated = fixed_clock.now()
        retrieved = initiated + timedelta(seconds=5)
        submitted = retrieved + timedelta(seconds=10)

        presentation = PresentationSubmitted(
            transaction_id=transaction_id,
            request_id=request_id,
            initiated_at=initiated,
            retrieved_at=retrieved,
            submitted_at=submitted,
            wallet_response={"vp_token": "eyJ..."},
        )

        assert presentation.submitted_at == submitted
        assert presentation.wallet_response == {"vp_token": "eyJ..."}

    def test_empty_wallet_response_raises_error(
        self, transaction_id: TransactionId, request_id: RequestId, fixed_clock: FixedClock
    ):
        """Empty wallet_response raises ValueError"""
        initiated = fixed_clock.now()

        with pytest.raises(ValueError, match="wallet_response cannot be empty"):
            PresentationSubmitted(
                transaction_id=transaction_id,
                request_id=request_id,
                initiated_at=initiated,
                retrieved_at=initiated + timedelta(seconds=5),
                submitted_at=initiated + timedelta(seconds=15),
                wallet_response={},
            )


class TestPresentationTimedOut:
    """Tests for PresentationTimedOut state"""

    def test_create_valid_timeout(
        self, transaction_id: TransactionId, request_id: RequestId, fixed_clock: FixedClock
    ):
        """Can create valid PresentationTimedOut"""
        initiated = fixed_clock.now()
        timed_out = initiated + timedelta(hours=2)

        presentation = PresentationTimedOut(
            transaction_id=transaction_id,
            request_id=request_id,
            initiated_at=initiated,
            timed_out_at=timed_out,
            last_state="Requested",
        )

        assert presentation.timed_out_at == timed_out
        assert presentation.last_state == "Requested"

    def test_invalid_last_state_raises_error(
        self, transaction_id: TransactionId, request_id: RequestId, fixed_clock: FixedClock
    ):
        """Invalid last_state raises ValueError"""
        initiated = fixed_clock.now()

        with pytest.raises(ValueError, match="Invalid last_state"):
            PresentationTimedOut(
                transaction_id=transaction_id,
                request_id=request_id,
                initiated_at=initiated,
                timed_out_at=initiated + timedelta(hours=1),
                last_state="InvalidState",
            )


class TestStateTransitions:
    """Tests for state transition functions"""

    def test_mark_as_retrieved_from_requested_success(
        self, transaction_id: TransactionId, request_id: RequestId, nonce: Nonce, fixed_clock: FixedClock
    ):
        """Can transition from Requested to RequestObjectRetrieved"""
        initiated = fixed_clock.now()
        presentation = PresentationRequested(
            transaction_id=transaction_id,
            request_id=request_id,
            jar="test",
            nonce=nonce,
            response_mode="direct_post",
            presentation_definition=None,
            initiated_at=initiated,
            expires_at=initiated + timedelta(hours=1),
        )

        fixed_clock.advance(timedelta(seconds=5))
        result = mark_as_retrieved(presentation, fixed_clock)

        assert isinstance(result, Success)
        retrieved = result.unwrap()
        assert isinstance(retrieved, PresentationRequestObjectRetrieved)
        assert retrieved.retrieved_at == fixed_clock.now()

    def test_mark_as_retrieved_from_wrong_state_fails(
        self, transaction_id: TransactionId, request_id: RequestId, fixed_clock: FixedClock
    ):
        """Cannot transition to RequestObjectRetrieved from wrong state"""
        initiated = fixed_clock.now()
        presentation = PresentationSubmitted(
            transaction_id=transaction_id,
            request_id=request_id,
            initiated_at=initiated,
            retrieved_at=initiated + timedelta(seconds=5),
            submitted_at=initiated + timedelta(seconds=15),
            wallet_response={"vp_token": "test"},
        )

        result = mark_as_retrieved(presentation, fixed_clock)

        assert isinstance(result, Failure)
        error = result.failure()
        assert isinstance(error, InvalidStateTransition)

    def test_mark_as_retrieved_when_expired_fails(
        self, transaction_id: TransactionId, request_id: RequestId, nonce: Nonce, fixed_clock: FixedClock
    ):
        """Cannot retrieve when presentation is expired"""
        initiated = fixed_clock.now()
        presentation = PresentationRequested(
            transaction_id=transaction_id,
            request_id=request_id,
            jar="test",
            nonce=nonce,
            response_mode="direct_post",
            presentation_definition=None,
            initiated_at=initiated,
            expires_at=initiated + timedelta(hours=1),
        )

        # Advance past expiration
        fixed_clock.advance(timedelta(hours=2))
        result = mark_as_retrieved(presentation, fixed_clock)

        assert isinstance(result, Failure)
        error = result.failure()
        assert isinstance(error, PresentationExpired)

    def test_mark_as_submitted_from_retrieved_success(
        self, transaction_id: TransactionId, request_id: RequestId, nonce: Nonce, fixed_clock: FixedClock
    ):
        """Can transition from RequestObjectRetrieved to Submitted"""
        initiated = fixed_clock.now()
        retrieved = initiated + timedelta(seconds=5)
        presentation = PresentationRequestObjectRetrieved(
            transaction_id=transaction_id,
            request_id=request_id,
            jar="test",
            nonce=nonce,
            response_mode="direct_post",
            presentation_definition=None,
            initiated_at=initiated,
            retrieved_at=retrieved,
            expires_at=initiated + timedelta(hours=1),
        )

        fixed_clock.advance(timedelta(seconds=10))
        wallet_response = {"vp_token": "eyJ..."}
        result = mark_as_submitted(presentation, wallet_response, fixed_clock)

        assert isinstance(result, Success)
        submitted = result.unwrap()
        assert isinstance(submitted, PresentationSubmitted)
        assert submitted.wallet_response == wallet_response

    def test_mark_as_submitted_with_empty_response_fails(
        self, transaction_id: TransactionId, request_id: RequestId, nonce: Nonce, fixed_clock: FixedClock
    ):
        """Cannot submit with empty wallet response"""
        initiated = fixed_clock.now()
        presentation = PresentationRequestObjectRetrieved(
            transaction_id=transaction_id,
            request_id=request_id,
            jar="test",
            nonce=nonce,
            response_mode="direct_post",
            presentation_definition=None,
            initiated_at=initiated,
            retrieved_at=initiated + timedelta(seconds=5),
            expires_at=initiated + timedelta(hours=1),
        )

        result = mark_as_submitted(presentation, {}, fixed_clock)

        assert isinstance(result, Failure)
        error = result.failure()
        assert isinstance(error, PresentationError)

    def test_mark_as_timed_out_from_requested_success(
        self, transaction_id: TransactionId, request_id: RequestId, nonce: Nonce, fixed_clock: FixedClock
    ):
        """Can timeout from Requested state"""
        initiated = fixed_clock.now()
        presentation = PresentationRequested(
            transaction_id=transaction_id,
            request_id=request_id,
            jar="test",
            nonce=nonce,
            response_mode="direct_post",
            presentation_definition=None,
            initiated_at=initiated,
            expires_at=initiated + timedelta(hours=1),
        )

        fixed_clock.advance(timedelta(hours=2))
        result = mark_as_timed_out(presentation, fixed_clock)

        assert isinstance(result, Success)
        timed_out = result.unwrap()
        assert isinstance(timed_out, PresentationTimedOut)
        assert timed_out.last_state == "Requested"

    def test_mark_as_timed_out_from_completed_fails(
        self, transaction_id: TransactionId, request_id: RequestId, fixed_clock: FixedClock
    ):
        """Cannot timeout already completed presentation"""
        initiated = fixed_clock.now()
        presentation = PresentationSubmitted(
            transaction_id=transaction_id,
            request_id=request_id,
            initiated_at=initiated,
            retrieved_at=initiated + timedelta(seconds=5),
            submitted_at=initiated + timedelta(seconds=15),
            wallet_response={"vp_token": "test"},
        )

        result = mark_as_timed_out(presentation, fixed_clock)

        assert isinstance(result, Failure)
        error = result.failure()
        assert isinstance(error, PresentationAlreadyCompleted)


class TestQueryFunctions:
    """Tests for query/helper functions"""

    def test_is_expired_requested_not_expired(
        self, transaction_id: TransactionId, request_id: RequestId, nonce: Nonce, fixed_clock: FixedClock
    ):
        """is_expired returns False when not expired"""
        initiated = fixed_clock.now()
        presentation = PresentationRequested(
            transaction_id=transaction_id,
            request_id=request_id,
            jar="test",
            nonce=nonce,
            response_mode="direct_post",
            presentation_definition=None,
            initiated_at=initiated,
            expires_at=initiated + timedelta(hours=1),
        )

        assert not is_expired(presentation, fixed_clock)

    def test_is_expired_requested_expired(
        self, transaction_id: TransactionId, request_id: RequestId, nonce: Nonce, fixed_clock: FixedClock
    ):
        """is_expired returns True when expired"""
        initiated = fixed_clock.now()
        presentation = PresentationRequested(
            transaction_id=transaction_id,
            request_id=request_id,
            jar="test",
            nonce=nonce,
            response_mode="direct_post",
            presentation_definition=None,
            initiated_at=initiated,
            expires_at=initiated + timedelta(hours=1),
        )

        fixed_clock.advance(timedelta(hours=2))
        assert is_expired(presentation, fixed_clock)

    def test_is_expired_completed_never_expired(
        self, transaction_id: TransactionId, request_id: RequestId, fixed_clock: FixedClock
    ):
        """is_expired returns False for completed presentations"""
        initiated = fixed_clock.now()
        presentation = PresentationSubmitted(
            transaction_id=transaction_id,
            request_id=request_id,
            initiated_at=initiated,
            retrieved_at=initiated + timedelta(seconds=5),
            submitted_at=initiated + timedelta(seconds=15),
            wallet_response={"vp_token": "test"},
        )

        fixed_clock.advance(timedelta(days=365))
        assert not is_expired(presentation, fixed_clock)

    def test_is_completed(
        self, transaction_id: TransactionId, request_id: RequestId, nonce: Nonce, fixed_clock: FixedClock
    ):
        """is_completed returns correct value for each state"""
        initiated = fixed_clock.now()

        requested = PresentationRequested(
            transaction_id=transaction_id,
            request_id=request_id,
            jar="test",
            nonce=nonce,
            response_mode="direct_post",
            presentation_definition=None,
            initiated_at=initiated,
            expires_at=initiated + timedelta(hours=1),
        )
        assert not is_completed(requested)

        submitted = PresentationSubmitted(
            transaction_id=transaction_id,
            request_id=request_id,
            initiated_at=initiated,
            retrieved_at=initiated + timedelta(seconds=5),
            submitted_at=initiated + timedelta(seconds=15),
            wallet_response={"vp_token": "test"},
        )
        assert is_completed(submitted)

        timed_out = PresentationTimedOut(
            transaction_id=transaction_id,
            request_id=request_id,
            initiated_at=initiated,
            timed_out_at=initiated + timedelta(hours=2),
            last_state="Requested",
        )
        assert is_completed(timed_out)

    def test_is_successful(
        self, transaction_id: TransactionId, request_id: RequestId, fixed_clock: FixedClock
    ):
        """is_successful returns True only for Submitted state"""
        initiated = fixed_clock.now()

        submitted = PresentationSubmitted(
            transaction_id=transaction_id,
            request_id=request_id,
            initiated_at=initiated,
            retrieved_at=initiated + timedelta(seconds=5),
            submitted_at=initiated + timedelta(seconds=15),
            wallet_response={"vp_token": "test"},
        )
        assert is_successful(submitted)

        timed_out = PresentationTimedOut(
            transaction_id=transaction_id,
            request_id=request_id,
            initiated_at=initiated,
            timed_out_at=initiated + timedelta(hours=2),
            last_state="Requested",
        )
        assert not is_successful(timed_out)

    def test_get_transaction_id(
        self, transaction_id: TransactionId, request_id: RequestId, nonce: Nonce, fixed_clock: FixedClock
    ):
        """get_transaction_id returns transaction_id from any state"""
        initiated = fixed_clock.now()
        presentation = PresentationRequested(
            transaction_id=transaction_id,
            request_id=request_id,
            jar="test",
            nonce=nonce,
            response_mode="direct_post",
            presentation_definition=None,
            initiated_at=initiated,
            expires_at=initiated + timedelta(hours=1),
        )

        assert get_transaction_id(presentation) == transaction_id

    def test_get_request_id(
        self, transaction_id: TransactionId, request_id: RequestId, nonce: Nonce, fixed_clock: FixedClock
    ):
        """get_request_id returns request_id from any state"""
        initiated = fixed_clock.now()
        presentation = PresentationRequested(
            transaction_id=transaction_id,
            request_id=request_id,
            jar="test",
            nonce=nonce,
            response_mode="direct_post",
            presentation_definition=None,
            initiated_at=initiated,
            expires_at=initiated + timedelta(hours=1),
        )

        assert get_request_id(presentation) == request_id


class TestFactoryFunctions:
    """Tests for factory functions"""

    def test_create_presentation_requested(
        self, transaction_id: TransactionId, request_id: RequestId, nonce: Nonce, fixed_clock: FixedClock
    ):
        """create_presentation_requested creates valid presentation"""
        presentation = create_presentation_requested(
            transaction_id=transaction_id,
            request_id=request_id,
            jar="test_jar",
            nonce=nonce,
            response_mode="direct_post",
            presentation_definition={"id": "test"},
            max_age=timedelta(hours=1),
            clock=fixed_clock,
        )

        assert isinstance(presentation, PresentationRequested)
        assert presentation.transaction_id == transaction_id
        assert presentation.initiated_at == fixed_clock.now()
        assert presentation.expires_at == fixed_clock.now() + timedelta(hours=1)
