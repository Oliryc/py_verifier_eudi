# Trust Sources and Certificate Validation - Detailed Design

**Document Version**: 1.0
**Last Updated**: 2025-01-03
**Status**: Design Phase

---

## 1. OVERVIEW

Trust sources define which issuers the verifier trusts to issue credentials. The system supports:
- **Keystores**: Static trust anchors (JKS/PKCS12)
- **LOTL**: Dynamic trust lists (List of Trusted Lists - ETSI TS 119 612)

Certificate validation ensures credential issuer certificates chain to trusted roots.

---

## 2. TRUST SOURCE TYPES

```python
from dataclasses import dataclass
from typing import Optional, Union, List
from enum import Enum

class ProviderKind(Enum):
    """ETSI trust service provider types"""
    PID_PROVIDER = "http://uri.etsi.org/Svc/Svctype/Provider/PID"
    QEEA_PROVIDER = "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q"
    PUB_EAA_PROVIDER = "http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA"

@dataclass(frozen=True)
class KeyStoreConfig:
    """Static keystore trust source"""
    keystore_path: str
    keystore_type: str = "JKS"  # JKS, PKCS12, etc.
    keystore_password: Optional[str] = None

@dataclass(frozen=True)
class TrustedListConfig:
    """Dynamic LOTL trust source"""
    location: str  # URL to LOTL
    service_type_filter: Optional[ProviderKind]
    refresh_interval: str = "0 0 * * * *"  # Cron expression
    keystore_config: Optional[KeyStoreConfig] = None  # For LOTL signature verification

@dataclass(frozen=True)
class TrustSourceConfig:
    """Combined trust source (keystore and/or LOTL)"""
    trusted_list: Optional[TrustedListConfig]
    keystore: Optional[KeyStoreConfig]

    def __post_init__(self):
        if not self.trusted_list and not self.keystore:
            raise ValueError("At least one trust source must be provided")
```

---

## 3. CERTIFICATE VALIDATION

### 3.1 X5C Validator

```python
from cryptography import x509
from cryptography.x509 import Certificate
from cryptography.hazmat.backends import default_backend
from returns.result import Result, Success, Failure
from typing import List

class X5CValidator:
    """Validates X.509 certificate chains (x5c header)"""

    def __init__(self, trust_sources: TrustSourcesManager):
        self.trust_sources = trust_sources

    async def validate(
        self,
        cert_chain: List[Certificate],
        issuer_trust_chain: Optional[List[Certificate]]
    ) -> Result[None, ValidationError]:
        """
        Validate certificate chain

        Steps:
        1. Parse certificates from x5c
        2. Build chain from leaf to root
        3. Verify each signature in chain
        4. Check certificate validity periods
        5. Verify chain terminates at trusted root
        6. Check revocation status (if configured)
        """

        if not cert_chain:
            return Failure(ValidationError.EmptyCertificateChain)

        leaf_cert = cert_chain[0]

        # Step 1: Validate leaf certificate
        leaf_result = self._validate_certificate(leaf_cert)
        if isinstance(leaf_result, Failure):
            return leaf_result

        # Step 2: Verify chain signatures
        for i in range(len(cert_chain) - 1):
            child = cert_chain[i]
            parent = cert_chain[i + 1]

            verify_result = self._verify_signature(child, parent)
            if isinstance(verify_result, Failure):
                return verify_result

        # Step 3: Check trust anchor
        root_cert = cert_chain[-1]
        trust_result = await self.trust_sources.is_trusted(
            root_cert,
            issuer_trust_chain
        )
        if isinstance(trust_result, Failure):
            return trust_result

        return Success(None)

    def _validate_certificate(
        self,
        cert: Certificate
    ) -> Result[None, ValidationError]:
        """Validate single certificate"""
        from datetime import datetime

        # Check validity period
        now = datetime.utcnow()
        if now < cert.not_valid_before:
            return Failure(ValidationError.CertificateNotYetValid)
        if now > cert.not_valid_after:
            return Failure(ValidationError.CertificateExpired)

        # Additional checks (basic constraints, key usage, etc.)
        # ...

        return Success(None)

    def _verify_signature(
        self,
        child: Certificate,
        parent: Certificate
    ) -> Result[None, ValidationError]:
        """Verify child certificate is signed by parent"""
        try:
            parent_public_key = parent.public_key()
            child.verify_directly_issued_by(parent, parent_public_key)
            return Success(None)
        except Exception as e:
            return Failure(ValidationError.InvalidCertificateSignature(str(e)))
```

### 3.2 Trust Sources Manager

```python
from threading import Lock
from datetime import datetime, timedelta

class TrustSourcesManager:
    """Manages trust anchors from keystores and LOTL"""

    def __init__(self, config: Dict[str, TrustSourceConfig]):
        self.config = config
        self.keystore_certs: Dict[str, List[Certificate]] = {}
        self.lotl_certs: Dict[str, List[Certificate]] = {}
        self.lock = Lock()
        self._initialize()

    def _initialize(self):
        """Load trust anchors from keystores"""
        for issuer_pattern, trust_config in self.config.items():
            if trust_config.keystore:
                certs = self._load_keystore(trust_config.keystore)
                self.keystore_certs[issuer_pattern] = certs

    def _load_keystore(
        self,
        keystore_config: KeyStoreConfig
    ) -> List[Certificate]:
        """Load certificates from JKS/PKCS12 keystore"""
        import jks
        from pathlib import Path

        keystore_path = Path(keystore_config.keystore_path)
        password = (keystore_config.keystore_password or "").encode('utf-8')

        if keystore_config.keystore_type == "JKS":
            keystore = jks.KeyStore.load(
                str(keystore_path),
                password
            )

            certs = []
            for alias, cert_entry in keystore.certs.items():
                if isinstance(cert_entry, jks.TrustedCertEntry):
                    cert_bytes = cert_entry.cert
                    cert = x509.load_der_x509_certificate(
                        cert_bytes,
                        default_backend()
                    )
                    certs.append(cert)

            return certs

        elif keystore_config.keystore_type == "PKCS12":
            from cryptography.hazmat.primitives.serialization import pkcs12

            with open(keystore_path, 'rb') as f:
                private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                    f.read(),
                    password,
                    default_backend()
                )

            certs = [cert] if cert else []
            if additional_certs:
                certs.extend(additional_certs)

            return certs

        else:
            raise ValueError(f"Unsupported keystore type: {keystore_config.keystore_type}")

    async def is_trusted(
        self,
        cert: Certificate,
        issuer_trust_chain: Optional[List[Certificate]]
    ) -> Result[bool, ValidationError]:
        """Check if certificate chains to a trusted root"""

        # Check keystore certs
        with self.lock:
            for pattern, trusted_certs in self.keystore_certs.items():
                if self._cert_matches_pattern(cert, pattern):
                    if cert in trusted_certs:
                        return Success(True)

            # Check LOTL certs
            for pattern, trusted_certs in self.lotl_certs.items():
                if self._cert_matches_pattern(cert, pattern):
                    if cert in trusted_certs:
                        return Success(True)

        # Check provided issuer trust chain
        if issuer_trust_chain and cert in issuer_trust_chain:
            return Success(True)

        return Failure(ValidationError.UntrustedIssuer)

    def _cert_matches_pattern(self, cert: Certificate, pattern: str) -> bool:
        """Check if certificate matches issuer pattern (regex)"""
        import re
        subject = cert.subject.rfc4514_string()
        return bool(re.match(pattern, subject))

    async def refresh_lotl(self, issuer_pattern: str):
        """Refresh LOTL certificates for issuer"""
        trust_config = self.config.get(issuer_pattern)
        if not trust_config or not trust_config.trusted_list:
            return

        lotl_config = trust_config.trusted_list

        # Fetch LOTL
        lotl_result = await self._fetch_lotl(lotl_config)
        if isinstance(lotl_result, Failure):
            # Log error
            return

        lotl_certs = lotl_result.unwrap()

        # Update cache
        with self.lock:
            self.lotl_certs[issuer_pattern] = lotl_certs

    async def _fetch_lotl(
        self,
        config: TrustedListConfig
    ) -> Result[List[Certificate], Exception]:
        """Fetch and parse LOTL"""
        import httpx

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(config.location)
                response.raise_for_status()
                lotl_xml = response.content

            # Parse LOTL XML (ETSI TS 119 612)
            certs = self._parse_lotl_xml(
                lotl_xml,
                config.service_type_filter
            )

            return Success(certs)

        except Exception as e:
            return Failure(e)

    def _parse_lotl_xml(
        self,
        xml_data: bytes,
        service_filter: Optional[ProviderKind]
    ) -> List[Certificate]:
        """Parse ETSI Trust List XML"""
        import xml.etree.ElementTree as ET

        # Parse XML
        root = ET.fromstring(xml_data)

        # Extract certificates from trust service providers
        # This is a simplified implementation
        # Real implementation needs to handle ETSI TS 119 612 properly

        certs = []
        # ... XML parsing logic ...

        return certs
```

---

## 4. SCHEDULED LOTL REFRESH

```python
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

class LOTLRefreshScheduler:
    """Schedules periodic LOTL refreshes"""

    def __init__(
        self,
        trust_sources: TrustSourcesManager,
        scheduler: AsyncIOScheduler
    ):
        self.trust_sources = trust_sources
        self.scheduler = scheduler

    def schedule_refreshes(self):
        """Schedule LOTL refreshes for all configured sources"""
        for issuer_pattern, trust_config in self.trust_sources.config.items():
            if trust_config.trusted_list:
                self._schedule_refresh(
                    issuer_pattern,
                    trust_config.trusted_list.refresh_interval
                )

    def _schedule_refresh(self, issuer_pattern: str, cron_expression: str):
        """Schedule single LOTL refresh"""
        trigger = CronTrigger.from_crontab(cron_expression)

        self.scheduler.add_job(
            func=self._refresh_job,
            trigger=trigger,
            args=[issuer_pattern],
            id=f"lotl_refresh_{issuer_pattern}",
            replace_existing=True
        )

    async def _refresh_job(self, issuer_pattern: str):
        """Execute LOTL refresh"""
        try:
            await self.trust_sources.refresh_lotl(issuer_pattern)
        except Exception as e:
            # Log error
            pass
```

---

## 5. TESTING

```python
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from datetime import datetime, timedelta

class TestCertificateValidation:

    def test_valid_chain(self):
        """Test validation of valid certificate chain"""
        # Create test chain
        root_key, root_cert = create_self_signed_cert("CN=Root CA")
        intermediate_key, intermediate_cert = create_signed_cert(
            "CN=Intermediate CA",
            root_key,
            root_cert
        )
        leaf_key, leaf_cert = create_signed_cert(
            "CN=Leaf",
            intermediate_key,
            intermediate_cert
        )

        # Create trust sources with root
        trust_sources = TrustSourcesManager({
            ".*": TrustSourceConfig(
                keystore=None,
                trusted_list=None
            )
        })
        trust_sources.keystore_certs[".*"] = [root_cert]

        # Validate
        validator = X5CValidator(trust_sources)
        result = await validator.validate(
            [leaf_cert, intermediate_cert, root_cert],
            None
        )

        assert isinstance(result, Success)

    def test_expired_certificate_rejected(self):
        """Test expired certificate is rejected"""
        # Create expired certificate
        expired_cert = create_expired_cert()

        validator = X5CValidator(Mock())
        result = validator._validate_certificate(expired_cert)

        assert isinstance(result, Failure)
        assert result.failure().type == ValidationErrorType.CERTIFICATE_EXPIRED

    def test_untrusted_root_rejected(self):
        """Test certificate with untrusted root is rejected"""
        # Create chain with unknown root
        root_key, root_cert = create_self_signed_cert("CN=Unknown Root")
        leaf_key, leaf_cert = create_signed_cert("CN=Leaf", root_key, root_cert)

        # Trust sources with different root
        other_root_key, other_root_cert = create_self_signed_cert("CN=Other Root")
        trust_sources = TrustSourcesManager(...)
        trust_sources.keystore_certs[".*"] = [other_root_cert]

        validator = X5CValidator(trust_sources)
        result = await validator.validate([leaf_cert, root_cert], None)

        assert isinstance(result, Failure)
        assert result.failure().type == ValidationErrorType.UNTRUSTED_ISSUER
```

---

## 6. DEPENDENCIES

```
cryptography==42.0.0
pyjks==20.0.0  # For JKS keystore support
apscheduler==3.10.4
httpx==0.26.0
returns==0.22.0
```

---

## 7. KEY IMPLEMENTATION NOTES

1. **LOTL Parsing**: ETSI TS 119 612 XML is complex - consider using existing library or DSS
2. **Caching**: Cache LOTL certificates to avoid repeated fetches
3. **Refresh Strategy**: Use APScheduler for periodic LOTL refreshes
4. **Keystore Format**: Support both JKS and PKCS12
5. **Revocation**: Consider implementing OCSP/CRL checking
6. **Thread Safety**: Use locks when accessing shared cert caches

---

**End of Trust Sources Design Document**
