"""Émission : structure du credential, modèle W3C, preuve attachée."""
from credential_engine import models


def test_issue_produces_valid_structure(engine, subject):
    vc = engine.issue_credential(subject)
    for field in models.REQUIRED_TOP_LEVEL_FIELDS:
        assert field in vc
    assert vc["type"][0] == "VerifiableCredential"
    assert vc["issuer"] == "did:certichain:issuer:uir"
    assert vc["credentialSubject"]["id"] == "did:certichain:holder:stu-001"


def test_issue_attaches_proof(engine, subject):
    vc = engine.issue_credential(subject)
    proof = vc["proof"]
    assert proof["type"] == models.PROOF_TYPE
    assert proof["signatureAlg"] == "ES256"
    assert proof["verificationMethod"] == "did:certichain:issuer:uir#test-key-1"
    assert len(proof["proofValue"]) > 0


def test_issue_sets_unique_ids(engine, subject):
    a = engine.issue_credential(subject)
    b = engine.issue_credential(subject)
    assert a["id"] != b["id"]


def test_issue_with_expiration(engine, subject):
    vc = engine.issue_credential(subject, expires_at="2031-01-01T00:00:00Z")
    assert vc["expirationDate"] == "2031-01-01T00:00:00Z"


def test_issue_with_document_reference(engine, subject):
    vc = engine.issue_credential(
        subject, document_reference="blob://docs/dipl.pdf", document_hash="abcd"
    )
    assert vc["credentialSchema"]["documentReference"] == "blob://docs/dipl.pdf"
    assert vc["credentialSchema"]["hashAlg"] == "SHA-256"
