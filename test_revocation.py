"""Révocation : preuve valide mais résultat global = Revoked (§7.4, §14)."""
from credential_engine import VerificationStatus


def test_revoked_credential_reports_revoked(engine, subject):
    vc = engine.issue_credential(subject)
    assert engine.verify_credential(vc).status == VerificationStatus.VALID
    engine.revoke_credential(vc["id"], "Diplôme annulé")
    assert engine.verify_credential(vc).status == VerificationStatus.REVOKED


def test_revocation_keeps_signature_valid(engine, subject):
    vc = engine.issue_credential(subject)
    engine.revoke_credential(vc["id"], "raison")
    result = engine.verify_credential(vc)
    # La signature reste mathématiquement valide ; seul le statut change.
    assert result.checks["signature"] is True
    assert result.status == VerificationStatus.REVOKED
