"""Altération : toute modification des données protégées casse la preuve (§14)."""
import copy
from credential_engine import VerificationStatus


def test_tampering_subject_name_fails(engine, subject):
    vc = engine.issue_credential(subject)
    t = copy.deepcopy(vc)
    t["credentialSubject"]["name"] = "Imposteur"
    assert engine.verify_credential(t).status == VerificationStatus.INVALID


def test_tampering_credential_name_fails(engine, subject):
    vc = engine.issue_credential(subject)
    t = copy.deepcopy(vc)
    t["credentialSubject"]["achievement"]["name"] = "Doctorat"
    assert engine.verify_credential(t).status == VerificationStatus.INVALID


def test_tampering_issuer_fails(engine, subject):
    vc = engine.issue_credential(subject)
    t = copy.deepcopy(vc)
    t["issuanceDate"] = "1999-01-01T00:00:00Z"
    assert engine.verify_credential(t).status == VerificationStatus.INVALID


def test_swapped_proof_value_fails(engine, subject):
    vc1 = engine.issue_credential(subject)
    vc2 = engine.issue_credential(subject)
    forged = copy.deepcopy(vc1)
    forged["proof"]["proofValue"] = vc2["proof"]["proofValue"]
    assert engine.verify_credential(forged).status == VerificationStatus.INVALID
