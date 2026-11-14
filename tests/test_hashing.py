"""Hachage : déterminisme, sensibilité à l'altération, exclusion de la preuve."""
import copy
from credential_engine.hashing import sha256_hex, credential_digest
from credential_engine.canonical import canonical_bytes


def test_sha256_known_value():
    # Empreinte SHA-256 connue de la chaîne vide (vecteur de test standard).
    assert sha256_hex(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_digest_is_deterministic():
    cred = {"b": 2, "a": 1, "credentialSubject": {"y": 1, "x": 2}}
    assert credential_digest(cred) == credential_digest(copy.deepcopy(cred))


def test_key_order_does_not_change_digest():
    c1 = {"a": 1, "b": 2}
    c2 = {"b": 2, "a": 1}
    assert credential_digest(c1) == credential_digest(c2)


def test_single_byte_change_changes_digest():
    c1 = {"name": "Mona"}
    c2 = {"name": "Mons"}
    assert credential_digest(c1) != credential_digest(c2)


def test_proof_is_excluded_from_digest():
    base = {"id": "x", "credentialSubject": {"n": 1}}
    with_proof = {**base, "proof": {"proofValue": "AAAA"}}
    assert credential_digest(base) == credential_digest(with_proof)
    assert b"proof" not in canonical_bytes(with_proof)
