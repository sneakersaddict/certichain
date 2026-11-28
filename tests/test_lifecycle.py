"""Tests Phase 3 : registre de confiance + cycle de vie (implémentation en mémoire)."""

import pytest

from credential_engine import (
    CredentialEngine,
    CredentialSubject,
    InMemoryTrustLedger,
    Issuer,
    LifecycleError,
    LocalECDSASigner,
    NotFoundError,
)
from credential_engine.engine import VerificationStatus
from credential_engine.status_store import CredentialStatus


@pytest.fixture
def setup():
    signer = LocalECDSASigner.generate()
    ledger = InMemoryTrustLedger()
    ledger.register_from_signer("uir", "Université Internationale de Rabat", "uir.ac.ma", signer)
    engine = CredentialEngine(signer, ledger, "uir", ledger)
    subject = CredentialSubject(holder_id="s-001", full_name="Mona Test",
                                credential_name="Master Cloud", credential_type_label="Master")
    return engine, ledger, subject


def test_issuance_is_recorded_with_hash_and_event(setup):
    engine, ledger, subject = setup
    vc = engine.issue_credential(subject)
    record = ledger.get_record(vc["id"])
    assert record["status"] == "active"
    assert record["issuer_id"] == "uir"
    assert len(record["credential_hash"]) == 64
    assert "Mona Test" not in str(record)          # minimisation : pas de nom en clair
    events = ledger.history(vc["id"])
    assert [e["event_type"] for e in events] == ["ISSUED"]


def test_revocation_changes_verification_and_is_logged(setup):
    engine, ledger, subject = setup
    vc = engine.issue_credential(subject)
    assert engine.verify_credential(vc).status == VerificationStatus.VALID
    ledger.change_status(vc["id"], CredentialStatus.REVOKED, "Fraude constatée")
    assert engine.verify_credential(vc).status == VerificationStatus.REVOKED
    events = ledger.history(vc["id"])
    assert events[-1]["event_type"] == "REVOKED"
    assert events[-1]["reason"] == "Fraude constatée"


def test_revocation_is_final(setup):
    engine, ledger, subject = setup
    vc = engine.issue_credential(subject)
    ledger.change_status(vc["id"], CredentialStatus.REVOKED, "erreur")
    with pytest.raises(LifecycleError) as exc:
        ledger.change_status(vc["id"], CredentialStatus.ACTIVE, "retour")
    assert exc.value.code == "forbidden_transition"


def test_revocation_requires_reason(setup):
    engine, ledger, subject = setup
    vc = engine.issue_credential(subject)
    with pytest.raises(LifecycleError) as exc:
        ledger.change_status(vc["id"], CredentialStatus.REVOKED, None)
    assert exc.value.code == "reason_required"


def test_suspend_then_reactivate(setup):
    engine, ledger, subject = setup
    vc = engine.issue_credential(subject)
    ledger.change_status(vc["id"], CredentialStatus.SUSPENDED, "enquête")
    assert engine.verify_credential(vc).status == VerificationStatus.REVOKED
    ledger.change_status(vc["id"], CredentialStatus.ACTIVE, "enquête close")
    assert engine.verify_credential(vc).status == VerificationStatus.VALID
    assert [e["event_type"] for e in ledger.history(vc["id"])] == [
        "ISSUED", "SUSPENDED", "REACTIVATED"]


def test_same_status_is_refused(setup):
    engine, ledger, subject = setup
    vc = engine.issue_credential(subject)
    with pytest.raises(LifecycleError) as exc:
        ledger.change_status(vc["id"], CredentialStatus.ACTIVE)
    assert exc.value.code == "no_change"


def test_unknown_credential(setup):
    _, ledger, _ = setup
    with pytest.raises(NotFoundError):
        ledger.change_status("urn:uuid:inconnu", CredentialStatus.REVOKED, "x")


def test_uuid_without_prefix_is_accepted(setup):
    engine, ledger, subject = setup
    vc = engine.issue_credential(subject)
    short_id = vc["id"].split(":")[-1]
    assert ledger.get_record(short_id)["credential_id"] == vc["id"]


def test_suspended_issuer_makes_credentials_untrusted(setup):
    engine, ledger, subject = setup
    vc = engine.issue_credential(subject)
    ledger.set_issuer_status("uir", "suspended", "audit", actor="admin")
    assert engine.verify_credential(vc).status == VerificationStatus.ISSUER_NOT_TRUSTED
    ledger.set_issuer_status("uir", "trusted", "audit OK")
    assert engine.verify_credential(vc).status == VerificationStatus.VALID
    types = [e["event_type"] for e in ledger.history("uir")]
    assert types == ["ISSUER_REGISTERED", "ISSUER_SUSPENDED", "ISSUER_REACTIVATED"]


def test_register_new_issuer_and_duplicate(setup):
    _, ledger, _ = setup
    other = LocalECDSASigner.generate()
    ledger.register_issuer(Issuer("emi", "École Mohammadia", "emi.ac.ma",
                                  other.key_id, other.public_jwk()))
    assert {i.issuer_id for i in ledger.list_issuers()} == {"uir", "emi"}
    with pytest.raises(LifecycleError) as exc:
        ledger.register_issuer(Issuer("emi", "x", "x", other.key_id, other.public_jwk()))
    assert exc.value.code == "already_exists"


def test_bad_issuer_status(setup):
    _, ledger, _ = setup
    with pytest.raises(LifecycleError):
        ledger.set_issuer_status("uir", "banni")
