"""Vérification d'un credential authentique."""
from credential_engine import VerificationStatus


def test_authentic_credential_is_valid(engine, subject):
    vc = engine.issue_credential(subject)
    result = engine.verify_credential(vc)
    assert result.status == VerificationStatus.VALID
    assert result.is_valid
    assert result.checks["signature"] is True
    assert result.checks["issuer_trusted"] is True


def test_result_serializes_to_dict(engine, subject):
    vc = engine.issue_credential(subject)
    d = engine.verify_credential(vc).to_dict()
    assert d["result"] == "Valid" and d["valid"] is True


def test_missing_fields_is_invalid(engine):
    result = engine.verify_credential({"id": "x"})
    assert result.status == VerificationStatus.INVALID
    assert result.checks["structure"] is False


def test_expired_credential(engine, subject):
    vc = engine.issue_credential(subject, expires_at="2000-01-01T00:00:00Z")
    assert engine.verify_credential(vc).status == VerificationStatus.EXPIRED
