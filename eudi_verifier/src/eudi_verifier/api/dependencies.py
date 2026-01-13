"""Dependency injection container for FastAPI"""

from typing import Optional

from eudi_verifier.adapter import (
    InMemoryPresentationRepository,
    JoseServiceImpl,
    QrCodeServiceImpl,
    ValidationServiceImpl,
)
from eudi_verifier.application import (
    GetRequestObjectImpl,
    GetWalletResponseImpl,
    InitTransactionImpl,
    PostWalletResponseImpl,
)
from eudi_verifier.config import load_or_create_config
from eudi_verifier.domain import Clock, SystemClock, VerifierConfig
from eudi_verifier.port.input import (
    GetRequestObject,
    GetWalletResponse,
    InitTransaction,
    PostWalletResponse,
)
from eudi_verifier.port.output import (
    JoseService,
    PresentationRepository,
    QrCodeService,
    ValidationService,
)


class DependencyContainer:
    """
    Dependency injection container for the EUDI Verifier application.

    Manages singleton instances of services and use cases.
    """

    def __init__(self, config: Optional[VerifierConfig] = None):
        """
        Initialize container with optional configuration.

        Args:
            config: Verifier configuration (if None, uses default)
        """
        self._config = config
        self._clock: Optional[Clock] = None
        self._repository: Optional[PresentationRepository] = None
        self._jose_service: Optional[JoseService] = None
        self._validation_service: Optional[ValidationService] = None
        self._qrcode_service: Optional[QrCodeService] = None
        self._init_transaction: Optional[InitTransaction] = None
        self._get_request_object: Optional[GetRequestObject] = None
        self._post_wallet_response: Optional[PostWalletResponse] = None
        self._get_wallet_response: Optional[GetWalletResponse] = None

    def get_config(self) -> VerifierConfig:
        """Get verifier configuration"""
        if self._config is None:
            # Load from environment or create test config
            self._config = load_or_create_config()
        return self._config

    def get_clock(self) -> Clock:
        """Get clock instance (singleton)"""
        if self._clock is None:
            self._clock = SystemClock()
        return self._clock

    def get_repository(self) -> PresentationRepository:
        """Get presentation repository (singleton)"""
        if self._repository is None:
            self._repository = InMemoryPresentationRepository(clock=self.get_clock())
        return self._repository

    def get_jose_service(self) -> JoseService:
        """Get JOSE service (singleton)"""
        if self._jose_service is None:
            self._jose_service = JoseServiceImpl()
        return self._jose_service

    def get_validation_service(self) -> ValidationService:
        """Get validation service (singleton)"""
        if self._validation_service is None:
            self._validation_service = ValidationServiceImpl()
        return self._validation_service

    def get_qrcode_service(self) -> QrCodeService:
        """Get QR code service (singleton)"""
        if self._qrcode_service is None:
            self._qrcode_service = QrCodeServiceImpl()
        return self._qrcode_service

    def get_init_transaction(self) -> InitTransaction:
        """Get InitTransaction use case (singleton)"""
        if self._init_transaction is None:
            self._init_transaction = InitTransactionImpl(
                repository=self.get_repository(),
                jose_service=self.get_jose_service(),
                qrcode_service=self.get_qrcode_service(),
                clock=self.get_clock(),
                config=self.get_config(),
            )
        return self._init_transaction

    def get_get_request_object(self) -> GetRequestObject:
        """Get GetRequestObject use case (singleton)"""
        if self._get_request_object is None:
            self._get_request_object = GetRequestObjectImpl(
                repository=self.get_repository(), clock=self.get_clock()
            )
        return self._get_request_object

    def get_post_wallet_response(self) -> PostWalletResponse:
        """Get PostWalletResponse use case (singleton)"""
        if self._post_wallet_response is None:
            self._post_wallet_response = PostWalletResponseImpl(
                repository=self.get_repository(),
                jose_service=self.get_jose_service(),
                validation_service=self.get_validation_service(),
                clock=self.get_clock(),
            )
        return self._post_wallet_response

    def get_get_wallet_response(self) -> GetWalletResponse:
        """Get GetWalletResponse use case (singleton)"""
        if self._get_wallet_response is None:
            self._get_wallet_response = GetWalletResponseImpl(repository=self.get_repository())
        return self._get_wallet_response


# Global container instance
_container: Optional[DependencyContainer] = None


def get_container() -> DependencyContainer:
    """Get or create global dependency container"""
    global _container
    if _container is None:
        _container = DependencyContainer()
    return _container


def set_container(container: DependencyContainer) -> None:
    """Set global dependency container (useful for testing)"""
    global _container
    _container = container


# FastAPI dependency functions
def get_init_transaction_use_case() -> InitTransaction:
    """FastAPI dependency for InitTransaction use case"""
    return get_container().get_init_transaction()


def get_get_request_object_use_case() -> GetRequestObject:
    """FastAPI dependency for GetRequestObject use case"""
    return get_container().get_get_request_object()


def get_post_wallet_response_use_case() -> PostWalletResponse:
    """FastAPI dependency for PostWalletResponse use case"""
    return get_container().get_post_wallet_response()


def get_get_wallet_response_use_case() -> GetWalletResponse:
    """FastAPI dependency for GetWalletResponse use case"""
    return get_container().get_get_wallet_response()


def get_qrcode_service() -> QrCodeService:
    """FastAPI dependency for QrCodeService"""
    return get_container().get_qrcode_service()


def get_verifier_config() -> VerifierConfig:
    """FastAPI dependency for VerifierConfig"""
    return get_container().get_config()
