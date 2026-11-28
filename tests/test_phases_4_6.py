"""Phases 4 à 6 : stockage des documents, partage, pannes partielles et réconciliation."""

import hashlib

import pytest

from credential_engine import CredentialSubject, build_local_engine
from credential_engine.issuance import IssuanceError, IssuanceService
from credential_engine.models import holder_did
from credential_engine.storage import (
    CREDENTIALS_CONTAINER,
    InMemoryDocumentStore,
    StorageError,
    validate_pdf,
)

PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"


@pytest.fixture
def env():
    engine = build_local_engine()
    store = InMemoryDocumentStore()
    svc = IssuanceService(engine, store, allow_fault_injection=True)
    uid = engine.registry.user_id_for("etudiant@uir.ac.ma", role="STUDENT")
    return engine, store, svc, uid


def subject(uid):
    return CredentialSubject(holder_id=uid, full_name="Etudiant Test",
                             credential_name="Master Cloud", credential_type_label="Master")


# ---------------- Phase 4 : documents ----------------
def test_pdf_validation():
    validate_pdf(PDF)
    with pytest.raises(StorageError):
        validate_pdf(b"MZ\x90\x00 pas un pdf")
    with pytest.raises(StorageError):
        validate_pdf(PDF, "image/png")
    with pytest.raises(StorageError):
        validate_pdf(b"%PDF-" + b"0" * (6 * 1024 * 1024))


def test_upload_link_and_hash_in_credential(env):
    engine, store, svc, uid = env
    meta = store.put_document(PDF, "../../diplome.pdf", "application/pdf", "scolarite@uir.ac.ma")
    assert meta["content_hash"] == hashlib.sha256(PDF).hexdigest()
    assert meta["original_name"] == "diplome.pdf"            # chemin nettoyé
    engine.registry.record_document(meta, "scolarite@uir.ac.ma")
    out = svc.issue(subject(uid), "scolarite@uir.ac.ma", document_id=meta["document_id"])
    schema = out["credential"]["credentialSchema"]
    assert schema["documentHash"] == meta["content_hash"]    # PDF <-> credential lié par empreinte
    assert engine.registry.get_document(meta["document_id"])["status"] == "LINKED"
    assert engine.verify_jwt(out["jwt"]).status.value == "Valid"
    # le même PDF ne peut pas être rattaché à un 2e credential
    with pytest.raises(IssuanceError) as e:
        svc.issue(subject(uid), "scolarite@uir.ac.ma", document_id=meta["document_id"])
    assert e.value.code == "document_already_linked"


def test_worm_no_overwrite(env):
    _, store, _, _ = env
    store.put("documents", "x.pdf", PDF, "application/pdf", {})
    with pytest.raises(StorageError):
        store.put("documents", "x.pdf", b"%PDF-autre", "application/pdf", {})


# ---------------- Phase 5 : portefeuille & partage ----------------
def test_wallet_and_share(env):
    engine, store, svc, uid = env
    out = svc.issue(subject(uid), "scolarite@uir.ac.ma")
    recs = engine.registry.credentials_for_holder(holder_did(uid))
    assert [r["credential_id"] for r in recs] == [out["credential"]["id"]]
    assert store.load_credential(out["credential"]["id"])["jwt"] == out["jwt"]
    token_hash = hashlib.sha256(b"jeton").hexdigest()
    sh = engine.registry.create_share(out["credential"]["id"], token_hash, "2099-01-01T00:00:00Z", "etudiant")
    assert "token_hash" not in sh                              # le jeton n'est jamais renvoyé
    assert engine.registry.resolve_share(token_hash)["credential_id"] == out["credential"]["id"]
    engine.registry.revoke_share(sh["share_id"], "etudiant")
    assert engine.registry.resolve_share(token_hash)["revoked"] is True
    assert engine.registry.resolve_share(hashlib.sha256(b"autre").hexdigest()) is None


# ---------------- Phase 6 : pannes partielles ----------------
def test_blob_failure_nothing_issued(env):
    engine, store, svc, uid = env
    with pytest.raises(IssuanceError) as e:
        svc.issue(subject(uid), "scolarite@uir.ac.ma", simulate="blob")
    assert e.value.state == "NOT_ISSUED"
    assert engine.registry.get_record(e.value.credential_id) is None
    assert store.list_names(CREDENTIALS_CONTAINER) == []


def test_sql_failure_pending_then_reconciled(env):
    engine, store, svc, uid = env
    with pytest.raises(IssuanceError) as e:
        svc.issue(subject(uid), "scolarite@uir.ac.ma", simulate="sql")
    assert e.value.state == "PENDING_RECONCILIATION"
    cid = e.value.credential_id
    saved = store.load_credential(cid)
    # signature valide MAIS absent du registre => jamais « Valid »
    r = engine.verify_jwt(saved["jwt"])
    assert r.status.value == "Invalid" and r.checks["registered"] is False
    rep = svc.reconcile("admin@uir.ac.ma")
    assert rep["recovered"] == [cid]
    assert engine.verify_jwt(saved["jwt"]).status.value == "Valid"
    assert svc.reconcile("admin@uir.ac.ma")["recovered"] == []   # idempotent
    assert engine.registry.history(cid)[0]["actor"].startswith("system:reconciliation")


def test_fault_injection_disabled_by_default(env):
    engine, store, _, uid = env
    svc = IssuanceService(engine, store)     # injection désactivée (production)
    assert svc.issue(subject(uid), "scolarite@uir.ac.ma", simulate="sql")["state"] == "ISSUED"


def test_new_actions_rbac(env):
    engine, *_ = env
    from credential_engine import AuthorizationError
    with pytest.raises(AuthorizationError):
        engine.registry.authorize("etudiant@uir.ac.ma", "upload_document")
    with pytest.raises(AuthorizationError):
        engine.registry.authorize("scolarite@uir.ac.ma", "reconcile")
    assert "STUDENT" in engine.registry.authorize("etudiant@uir.ac.ma", "share")


def test_stale_instance_resyncs_key_before_signing(env):
    """Panne observée en ligne : une instance signait encore avec la clé retirée."""
    engine, store, svc, uid = env
    from credential_engine.signing import LocalECDSASigner

    old = engine.signer
    new = LocalECDSASigner.generate("certichain-local-key-2")

    class FakeKV:
        def __init__(self):
            self.current = old
        key_id = property(lambda s: s.current.key_id)
        def sign_digest(self, d): return self.current.sign_digest(d)
        def public_key(self): return self.current.public_key()
        def public_jwk(self): return self.current.public_jwk()
        def refresh(self, force=False):
            changed = self.current is not new
            self.current = new
            return changed

    engine.signer = FakeKV()
    engine.registry.rotate_key("uir", new.key_id, new.public_jwk())   # autre instance a tourné
    out = svc.issue(subject(uid), "scolarite@uir.ac.ma")
    assert out["credential"]["proof"]["verificationMethod"].endswith(new.key_id)
    assert engine.verify_jwt(out["jwt"]).status.value == "Valid"
