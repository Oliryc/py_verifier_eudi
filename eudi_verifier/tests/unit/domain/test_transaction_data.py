"""Tests for TransactionData models"""

import base64
import hashlib
import json

import pytest
from pydantic import ValidationError

from eudi_verifier.domain import (
    HashAlgorithm,
    CredentialInfo,
    DocumentToSign,
    QesAuthorization,
    CertificatePolicy,
    SubjectAttributes,
    QCertCreationAcceptance,
    create_qes_authorization,
    create_qcert_creation_acceptance,
)


class TestHashAlgorithm:
    """Tests for HashAlgorithm enum"""

    def test_hash_algorithm_values(self):
        """HashAlgorithm has correct string values"""
        assert HashAlgorithm.SHA256 == "sha-256"
        assert HashAlgorithm.SHA384 == "sha-384"
        assert HashAlgorithm.SHA512 == "sha-512"

    def test_compute_hash_sha256(self):
        """compute_hash works for SHA-256"""
        data = b"test data"
        result = HashAlgorithm.SHA256.compute_hash(data)
        expected = hashlib.sha256(data).digest()
        assert result == expected

    def test_compute_hash_sha384(self):
        """compute_hash works for SHA-384"""
        data = b"test data"
        result = HashAlgorithm.SHA384.compute_hash(data)
        expected = hashlib.sha384(data).digest()
        assert result == expected

    def test_compute_hash_sha512(self):
        """compute_hash works for SHA-512"""
        data = b"test data"
        result = HashAlgorithm.SHA512.compute_hash(data)
        expected = hashlib.sha512(data).digest()
        assert result == expected


class TestCredentialInfo:
    """Tests for CredentialInfo"""

    def test_create_minimal_credential_info(self):
        """Can create CredentialInfo with minimal fields"""
        info = CredentialInfo(credential_id="cred_123")
        assert info.credential_id == "cred_123"
        assert info.description is None

    def test_create_with_description(self):
        """Can create CredentialInfo with description"""
        info = CredentialInfo(credential_id="cred_123", description="Test credential")
        assert info.description == "Test credential"

    def test_create_with_certificates(self, sample_certificate: str):
        """Can create CredentialInfo with certificates"""
        info = CredentialInfo(credential_id="cred_123", certificates=[sample_certificate])
        assert len(info.certificates) == 1

    def test_blank_credential_id_raises_error(self):
        """Blank credential_id raises ValidationError"""
        with pytest.raises(ValidationError):
            CredentialInfo(credential_id="")


class TestDocumentToSign:
    """Tests for DocumentToSign"""

    def test_create_document_to_sign(self):
        """Can create DocumentToSign"""
        doc = DocumentToSign(
            label="Contract.pdf", hash="xyz123_base64url", hash_algorithm=HashAlgorithm.SHA256, description="Contract"
        )
        assert doc.label == "Contract.pdf"
        assert doc.hash == "xyz123_base64url"
        assert doc.hash_algorithm == HashAlgorithm.SHA256

    def test_blank_label_raises_error(self):
        """Blank label raises ValidationError"""
        with pytest.raises(ValidationError):
            DocumentToSign(label="", hash="xyz123")

    def test_blank_hash_raises_error(self):
        """Blank hash raises ValidationError"""
        with pytest.raises(ValidationError):
            DocumentToSign(label="Document", hash="")


class TestQesAuthorization:
    """Tests for QesAuthorization"""

    def test_create_qes_authorization(self):
        """Can create QesAuthorization"""
        info = CredentialInfo(credential_id="cred_123")
        doc = DocumentToSign(label="Contract.pdf", hash="xyz123")
        qes = QesAuthorization(credential_info=info, documents_to_sign=[doc])

        assert qes.credential_info == info
        assert len(qes.documents_to_sign) == 1
        assert qes.num_signatures == 1

    def test_empty_documents_raises_error(self):
        """Empty documents_to_sign raises ValueError"""
        info = CredentialInfo(credential_id="cred_123")
        with pytest.raises(ValueError, match="cannot be empty"):
            QesAuthorization(credential_info=info, documents_to_sign=[])

    def test_num_signatures_validation(self):
        """num_signatures must be valid"""
        info = CredentialInfo(credential_id="cred_123")
        doc = DocumentToSign(label="Doc", hash="xyz")

        # num_signatures < 1 raises error
        with pytest.raises(ValueError, match="must be >= 1"):
            QesAuthorization(credential_info=info, documents_to_sign=[doc], num_signatures=0)

        # num_signatures > documents raises error
        with pytest.raises(ValueError, match="cannot exceed"):
            QesAuthorization(credential_info=info, documents_to_sign=[doc], num_signatures=2)

    def test_to_dict(self):
        """to_dict converts to dictionary"""
        info = CredentialInfo(credential_id="cred_123", description="Test")
        doc = DocumentToSign(label="Doc", hash="xyz")
        qes = QesAuthorization(credential_info=info, documents_to_sign=[doc])

        result = qes.to_dict()
        assert result["type"] == "qes_authorization"
        assert result["credential_info"]["credential_id"] == "cred_123"
        assert len(result["documents_to_sign"]) == 1

    def test_to_json(self):
        """to_json converts to compact JSON"""
        info = CredentialInfo(credential_id="cred_123")
        doc = DocumentToSign(label="Doc", hash="xyz")
        qes = QesAuthorization(credential_info=info, documents_to_sign=[doc])

        json_str = qes.to_json()
        assert isinstance(json_str, str)
        # Verify it's valid JSON
        parsed = json.loads(json_str)
        assert parsed["type"] == "qes_authorization"

    def test_to_base64url(self):
        """to_base64url encodes as Base64URL"""
        info = CredentialInfo(credential_id="cred_123")
        doc = DocumentToSign(label="Doc", hash="xyz")
        qes = QesAuthorization(credential_info=info, documents_to_sign=[doc])

        b64 = qes.to_base64url()
        assert isinstance(b64, str)
        # Should not contain padding
        assert "=" not in b64
        # Should be Base64URL alphabet
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in b64)

    def test_compute_hash(self):
        """compute_hash computes correct hash"""
        info = CredentialInfo(credential_id="cred_123")
        doc = DocumentToSign(label="Doc", hash="xyz")
        qes = QesAuthorization(credential_info=info, documents_to_sign=[doc])

        hash_result = qes.compute_hash(HashAlgorithm.SHA256)
        assert isinstance(hash_result, str)
        # Should be Base64URL without padding
        assert "=" not in hash_result

        # Verify hash is correct
        json_bytes = qes.to_json().encode("utf-8")
        expected_hash = hashlib.sha256(json_bytes).digest()
        expected_b64 = base64.urlsafe_b64encode(expected_hash).decode("ascii").rstrip("=")
        assert hash_result == expected_b64


class TestCertificatePolicy:
    """Tests for CertificatePolicy"""

    def test_create_certificate_policy(self):
        """Can create CertificatePolicy"""
        policy = CertificatePolicy(policy_oid="1.2.3.4.5", policy_name="Test Policy")
        assert policy.policy_oid == "1.2.3.4.5"
        assert policy.policy_name == "Test Policy"

    def test_policy_oid_pattern_validation(self):
        """policy_oid must match OID pattern"""
        # Valid OIDs
        valid_oids = ["1.2.3", "1.2.3.4.5.6", "2.5.29.37"]
        for oid in valid_oids:
            policy = CertificatePolicy(policy_oid=oid, policy_name="Test")
            assert policy.policy_oid == oid

        # Invalid OID
        with pytest.raises(ValidationError):
            CertificatePolicy(policy_oid="not-an-oid", policy_name="Test")

    def test_blank_policy_name_raises_error(self):
        """Blank policy_name raises ValidationError"""
        with pytest.raises(ValidationError):
            CertificatePolicy(policy_oid="1.2.3", policy_name="")


class TestSubjectAttributes:
    """Tests for SubjectAttributes"""

    def test_create_minimal_subject(self):
        """Can create SubjectAttributes with minimal fields"""
        subject = SubjectAttributes(common_name="John Doe")
        assert subject.common_name == "John Doe"
        assert subject.organization is None

    def test_create_full_subject(self):
        """Can create SubjectAttributes with all fields"""
        subject = SubjectAttributes(
            common_name="John Doe",
            organization="Example Corp",
            organizational_unit="IT",
            country="US",
            email="john@example.com",
        )
        assert subject.organization == "Example Corp"
        assert subject.country == "US"

    def test_blank_common_name_raises_error(self):
        """Blank common_name raises ValidationError"""
        with pytest.raises(ValidationError):
            SubjectAttributes(common_name="")

    def test_country_code_validation(self):
        """country must be 2-letter ISO code"""
        # Valid
        subject = SubjectAttributes(common_name="Test", country="US")
        assert subject.country == "US"

        # Uppercase conversion
        subject2 = SubjectAttributes(common_name="Test", country="us")
        assert subject2.country == "US"

        # Invalid length (Pydantic enforces max_length)
        with pytest.raises(ValidationError):
            SubjectAttributes(common_name="Test", country="USA")

        # Invalid characters
        with pytest.raises(ValidationError):
            SubjectAttributes(common_name="Test", country="U1")


class TestQCertCreationAcceptance:
    """Tests for QCertCreationAcceptance"""

    def test_create_qcert_acceptance(self):
        """Can create QCertCreationAcceptance"""
        policy = CertificatePolicy(policy_oid="1.2.3", policy_name="Test Policy")
        subject = SubjectAttributes(common_name="John Doe", organization="Example", country="US")
        qcert = QCertCreationAcceptance(
            certificate_policy=policy,
            subject_attributes=subject,
            validity_days=365,
            key_usages=["digitalSignature", "nonRepudiation"],
        )

        assert qcert.validity_days == 365
        assert len(qcert.key_usages) == 2

    def test_validity_days_validation(self):
        """validity_days must be valid range"""
        policy = CertificatePolicy(policy_oid="1.2.3", policy_name="Test")
        subject = SubjectAttributes(common_name="Test", country="US")

        # Too small
        with pytest.raises(ValueError, match="must be >= 1"):
            QCertCreationAcceptance(
                certificate_policy=policy, subject_attributes=subject, validity_days=0, key_usages=["digitalSignature"]
            )

        # Too large
        with pytest.raises(ValueError, match="cannot exceed 3650"):
            QCertCreationAcceptance(
                certificate_policy=policy,
                subject_attributes=subject,
                validity_days=4000,
                key_usages=["digitalSignature"],
            )

    def test_empty_key_usages_raises_error(self):
        """Empty key_usages raises ValueError"""
        policy = CertificatePolicy(policy_oid="1.2.3", policy_name="Test")
        subject = SubjectAttributes(common_name="Test", country="US")

        with pytest.raises(ValueError, match="cannot be empty"):
            QCertCreationAcceptance(
                certificate_policy=policy, subject_attributes=subject, validity_days=365, key_usages=[]
            )

    def test_invalid_key_usage_raises_error(self):
        """Invalid key usage raises ValueError"""
        policy = CertificatePolicy(policy_oid="1.2.3", policy_name="Test")
        subject = SubjectAttributes(common_name="Test", country="US")

        with pytest.raises(ValueError, match="Invalid key usage"):
            QCertCreationAcceptance(
                certificate_policy=policy, subject_attributes=subject, validity_days=365, key_usages=["invalidUsage"]
            )

    def test_valid_key_usages(self):
        """All valid key usages are accepted"""
        policy = CertificatePolicy(policy_oid="1.2.3", policy_name="Test")
        subject = SubjectAttributes(common_name="Test", country="US")
        valid_usages = [
            "digitalSignature",
            "nonRepudiation",
            "keyEncipherment",
            "dataEncipherment",
            "keyAgreement",
            "keyCertSign",
            "cRLSign",
        ]

        qcert = QCertCreationAcceptance(
            certificate_policy=policy, subject_attributes=subject, validity_days=365, key_usages=valid_usages
        )
        assert qcert.key_usages == valid_usages

    def test_to_dict(self):
        """to_dict converts to dictionary"""
        policy = CertificatePolicy(policy_oid="1.2.3", policy_name="Test")
        subject = SubjectAttributes(common_name="Test", country="US")
        qcert = QCertCreationAcceptance(
            certificate_policy=policy, subject_attributes=subject, validity_days=365, key_usages=["digitalSignature"]
        )

        result = qcert.to_dict()
        assert result["type"] == "qcert_creation_acceptance"
        assert result["validity_days"] == 365
        assert "certificate_policy" in result


class TestFactoryFunctions:
    """Tests for transaction data factory functions"""

    def test_create_qes_authorization(self):
        """create_qes_authorization creates valid QesAuthorization"""
        qes = create_qes_authorization(
            credential_id="cred_123",
            credential_description="Signing key",
            document_label="Contract.pdf",
            document_hash="abc123",
            hash_algorithm=HashAlgorithm.SHA256,
        )

        assert isinstance(qes, QesAuthorization)
        assert qes.credential_info.credential_id == "cred_123"
        assert len(qes.documents_to_sign) == 1
        assert qes.documents_to_sign[0].label == "Contract.pdf"

    def test_create_qcert_creation_acceptance(self):
        """create_qcert_creation_acceptance creates valid QCertCreationAcceptance"""
        qcert = create_qcert_creation_acceptance(
            policy_oid="1.2.3.4",
            policy_name="Test Policy",
            common_name="John Doe",
            organization="Example Corp",
            country="US",
            validity_days=730,
            key_usages=["digitalSignature"],
        )

        assert isinstance(qcert, QCertCreationAcceptance)
        assert qcert.certificate_policy.policy_oid == "1.2.3.4"
        assert qcert.subject_attributes.common_name == "John Doe"
        assert qcert.validity_days == 730
        assert "digitalSignature" in qcert.key_usages

    def test_create_qcert_with_default_key_usages(self):
        """create_qcert_creation_acceptance uses default key usages"""
        qcert = create_qcert_creation_acceptance(
            policy_oid="1.2.3",
            policy_name="Test",
            common_name="Test",
            organization="Test",
            country="US",
        )

        assert "digitalSignature" in qcert.key_usages
        assert "nonRepudiation" in qcert.key_usages
