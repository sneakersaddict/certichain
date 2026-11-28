"""Tests de finalisation : format standard vc+jwt, rotation de clé, autorisations."""

import pytest

from credential_engine import (
    AuthorizationError,
    CredentialEngine,
    CredentialSubject,
    InMemoryTrustLedger,
    LocalECDSASigner,
)
from credential_engine.engine import VerificationStatus
from credential_engine.status_store import CredentialStatus


@pytest.fixture
def env():
    signer = LocalECDSASigner.generate()
    ledger = InMemoryTrustLedger()
    ledger.register_from_signer("uir", "UIR", "uir.ac.ma", signer)
    ledger.add_user("admin@uir.ac.ma", "ADMINISTRATOR")
    ledger.add_user("scolarite@uir.ac.ma", "UNIVERSITY_STAFF")
    ledger.add_user("etudiant@uir.ac.ma", "STUDENT")
    ledger.allow_types("uir", "Master", "Bachelor")
    engine = CredentialEngine(signer, ledger, "uir", ledger)
    subject = CredentialSubject("s-1", "Test", "Master Cloud", "Master")
    return engine, ledger, subject


# ---------------------------------------------------------------- vc+jwt (VC-JOSE)
def test_jwt_valid(env):
    engine, _, subject = env
    vc = engine.issue_credential(subject)
    token = engine.issue_jwt(vc)
    assert token.count(".") == 2
    res = engine.verify_jwt(token)
    assert res.status == VerificationStatus.VALID
    assert res.checks["format"] == "vc+jwt"


def test_jwt_tampered_payload(env):
    import base64, json
    engine, _, subject = env
    token = engine.issue_jwt(engine.issue_credential(subject))
    h, p, s = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    payload["credentialSubject"]["name"] = "Pirate"
    p2 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    assert engine.verify_jwt(f"{h}.{p2}.{s}").status == VerificationStatus.INVALID


def test_jwt_revoked(env):
    engine, ledger, subject = env
    vc = engine.issue_credential(subject)
    token = engine.issue_jwt(vc)
    ledger.change_status(vc["id"], CredentialStatus.REVOKED, "erreur")
    assert engine.verify_jwt(token).status == VerificationStatus.REVOKED


def test_jwt_garbage(env):
    engine, _, _ = env
    assert engine.verify_jwt("pas-un-jwt").status == VerificationStatus.INVALID


# ---------------------------------------------------------------- rotation de clé
def test_old_credentials_still_valid_after_rotation(env):
    engine, ledger, subject = env
    old_vc = engine.issue_credential(subject)
    old_jwt = engine.issue_jwt(old_vc)
    new_signer = LocalECDSASigner.generate("certichain-local-key-2")
    ledger.rotate_key("uir", new_signer.key_id, new_signer.public_jwk())
    engine.signer = new_signer
    new_vc = engine.issue_credential(subject)
    assert engine.verify_credential(old_vc).status == VerificationStatus.VALID
    assert engine.verify_jwt(old_jwt).status == VerificationStatus.VALID
    assert engine.verify_credential(new_vc).status == VerificationStatus.VALID
    keys = {k["status"] for k in ledger.get_issuer("uir").public_info()["keys"]}
    assert keys == {"active", "retired"}


def test_compromised_key_is_rejected(env):
    engine, ledger, subject = env
    old_vc = engine.issue_credential(subject)
    new_signer = LocalECDSASigner.generate("certichain-local-key-2")
    old_kid = ledger.get_issuer("uir").public_key_id
    ledger.rotate_key("uir", new_signer.key_id, new_signer.public_jwk())
    ledger.get_issuer("uir").keys[old_kid]["status"] = "compromised"
    assert engine.verify_credential(old_vc).status == VerificationStatus.ISSUER_NOT_TRUSTED


def test_signature_with_retired_key_after_retirement_is_rejected(env):
    engine, ledger, subject = env
    old_signer = engine.signer
    new_signer = LocalECDSASigner.generate("certichain-local-key-2")
    ledger.rotate_key("uir", new_signer.key_id, new_signer.public_jwk())
    ledger.get_issuer("uir").keys[old_signer.key_id]["retired_at"] = "2000-01-01T00:00:00Z"
    late_vc = engine.issue_credential(subject)  # toujours signé avec l'ANCIENNE clé
    assert engine.verify_credential(late_vc).status == VerificationStatus.ISSUER_NOT_TRUSTED


# ---------------------------------------------------------------- autorisations
def test_staff_can_issue_allowed_type(env):
    _, ledger, _ = env
    assert "UNIVERSITY_STAFF" in ledger.authorize("scolarite@uir.ac.ma", "issue", "uir", "Master")


def test_type_not_allowed_is_refused_and_logged(env):
    _, ledger, _ = env
    with pytest.raises(AuthorizationError) as exc:
        ledger.authorize("scolarite@uir.ac.ma", "issue", "uir", "Doctorate")
    assert exc.value.http_status == 403
    assert ledger.security_events()[0]["event_type"] == "CREDENTIAL_TYPE_NOT_ALLOWED"


def test_student_cannot_issue(env):
    _, ledger, _ = env
    with pytest.raises(AuthorizationError):
        ledger.authorize("etudiant@uir.ac.ma", "issue", "uir", "Master")
    assert ledger.security_events()[0]["event_type"] == "UNAUTHORIZED_ISSUE"


def test_unknown_user_and_missing_actor(env):
    _, ledger, _ = env
    with pytest.raises(AuthorizationError):
        ledger.authorize("inconnu@x.com", "issue", "uir", "Master")
    with pytest.raises(AuthorizationError):
        ledger.authorize(None, "revoke")
    types = [e["event_type"] for e in ledger.security_events()]
    assert types == ["UNAUTHENTICATED_ACTION", "UNKNOWN_OR_INACTIVE_USER"]


def test_only_admin_can_revoke(env):
    _, ledger, _ = env
    with pytest.raises(AuthorizationError):
        ledger.authorize("scolarite@uir.ac.ma", "revoke")
    assert ledger.authorize("admin@uir.ac.ma", "revoke") == {"ADMINISTRATOR"}
