"""Signature ECDSA P-256 / ES256 : signer, vérifier, formats, conversions, JWK."""
import pytest
from credential_engine.signing import (
    LocalECDSASigner, verify_digest, der_to_raw, raw_to_der,
    public_key_to_jwk, jwk_to_public_key, b64url_encode, b64url_decode,
)
from credential_engine.errors import SigningError


def test_sign_returns_64_bytes(signer):
    sig = signer.sign_digest(b"0" * 32)
    assert len(sig) == 64


def test_sign_and_verify_roundtrip(signer):
    digest = b"A" * 32
    sig = signer.sign_digest(digest)
    assert verify_digest(signer.public_key(), digest, sig) is True


def test_verify_fails_on_wrong_digest(signer):
    sig = signer.sign_digest(b"A" * 32)
    assert verify_digest(signer.public_key(), b"B" * 32, sig) is False


def test_verify_fails_with_other_key(signer):
    other = LocalECDSASigner.generate("other")
    digest = b"A" * 32
    sig = signer.sign_digest(digest)
    assert verify_digest(other.public_key(), digest, sig) is False


def test_sign_rejects_non_32_byte_digest(signer):
    with pytest.raises(SigningError):
        signer.sign_digest(b"short")


def test_der_raw_roundtrip(signer):
    sig = signer.sign_digest(b"Z" * 32)
    assert der_to_raw(raw_to_der(sig)) == sig


def test_raw_to_der_rejects_bad_length():
    with pytest.raises(SigningError):
        raw_to_der(b"\x00" * 10)


def test_jwk_roundtrip(signer):
    jwk = public_key_to_jwk(signer.public_key(), "k1")
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256"
    pk = jwk_to_public_key(jwk)
    # La clé reconstruite vérifie bien les signatures de la clé d'origine.
    digest = b"Q" * 32
    assert verify_digest(pk, digest, signer.sign_digest(digest))


def test_b64url_roundtrip():
    data = b"\x00\x01\x02hello-\xff\xfe"
    assert b64url_decode(b64url_encode(data)) == data


def test_pem_persistence_roundtrip(tmp_path, signer):
    path = tmp_path / "k.pem"
    signer.save_pem_file(str(path))
    loaded = LocalECDSASigner.from_pem_file(str(path), "test-key-1")
    digest = b"P" * 32
    assert verify_digest(loaded.public_key(), digest, signer.sign_digest(digest))
