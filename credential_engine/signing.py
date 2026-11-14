"""
Signature et vérification ECDSA P-256 (algorithme ES256 : ECDSA sur la courbe
P-256 avec SHA-256).

Architecture clé du projet (concept §5, §8) :
- La clé PRIVÉE ne doit jamais être exportée ni manipulée par le code applicatif.
  En production, elle vit dans Azure Key Vault et c'est Key Vault qui signe.
- On définit donc une interface `Signer` abstraite, avec deux implémentations :
    * LocalECDSASigner  -> logiciel, pour les tests unitaires et la démo hors-ligne.
    * AzureKeyVaultSigner -> la vraie clé non exportable (fichier keyvault_signer.py).
- La VÉRIFICATION n'a besoin que de la clé PUBLIQUE (jamais de la privée).

Format de signature : « raw » r||s de 64 octets (convention JWS/ES256),
encodé en base64url pour le proofValue.
"""

from __future__ import annotations

import abc
import base64
from typing import Any, Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    EllipticCurvePrivateKey,
    SECP256R1,
)
from cryptography.exceptions import InvalidSignature

from .errors import SigningError

CURVE = SECP256R1()
COORD_BYTES = 32  # P-256 : coordonnées sur 32 octets


# ---------------------------------------------------------------------------
# Encodage base64url (sans padding) — convention des JWK/JWS
# ---------------------------------------------------------------------------
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


# ---------------------------------------------------------------------------
# Conversion signature : DER (format de `cryptography`) <-> raw r||s (format JWS)
# ---------------------------------------------------------------------------
def der_to_raw(der_sig: bytes) -> bytes:
    r, s = utils.decode_dss_signature(der_sig)
    return r.to_bytes(COORD_BYTES, "big") + s.to_bytes(COORD_BYTES, "big")


def raw_to_der(raw_sig: bytes) -> bytes:
    if len(raw_sig) != 2 * COORD_BYTES:
        raise SigningError(
            f"Signature brute invalide : {len(raw_sig)} octets, 64 attendus."
        )
    r = int.from_bytes(raw_sig[:COORD_BYTES], "big")
    s = int.from_bytes(raw_sig[COORD_BYTES:], "big")
    return utils.encode_dss_signature(r, s)


# ---------------------------------------------------------------------------
# Clé publique <-> JWK (format d'échange ; ce que Key Vault et le registre exposent)
# ---------------------------------------------------------------------------
def public_key_to_jwk(public_key: EllipticCurvePublicKey, key_id: str) -> Dict[str, Any]:
    numbers = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(numbers.x.to_bytes(COORD_BYTES, "big")),
        "y": b64url_encode(numbers.y.to_bytes(COORD_BYTES, "big")),
        "kid": key_id,
        "use": "sig",
        "alg": "ES256",
    }


def jwk_to_public_key(jwk: Dict[str, Any]) -> EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise SigningError("JWK non supporté : EC/P-256 attendu.")
    x = int.from_bytes(b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(b64url_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, CURVE).public_key()


# ---------------------------------------------------------------------------
# Interface Signer
# ---------------------------------------------------------------------------
class Signer(abc.ABC):
    """Interface commune : signe une empreinte SHA-256 de 32 octets -> 64 octets r||s."""

    @property
    @abc.abstractmethod
    def key_id(self) -> str:
        """Identifiant de la clé (sert de `verificationMethod`)."""

    @abc.abstractmethod
    def sign_digest(self, digest32: bytes) -> bytes:
        """Signe une empreinte SHA-256 (32 octets) et retourne 64 octets (r||s)."""

    @abc.abstractmethod
    def public_key(self) -> EllipticCurvePublicKey:
        """Clé publique correspondante (pour la vérification)."""

    def public_jwk(self) -> Dict[str, Any]:
        return public_key_to_jwk(self.public_key(), self.key_id)


# ---------------------------------------------------------------------------
# Implémentation logicielle (tests / démo). NE PAS utiliser en production.
# ---------------------------------------------------------------------------
class LocalECDSASigner(Signer):
    """Signataire ECDSA P-256 logiciel. La clé privée reste en mémoire/fichier local."""

    def __init__(self, private_key: EllipticCurvePrivateKey, key_id: str):
        self._private_key = private_key
        self._key_id = key_id

    @classmethod
    def generate(cls, key_id: str = "certichain-local-key-1") -> "LocalECDSASigner":
        return cls(ec.generate_private_key(CURVE), key_id)

    @classmethod
    def from_pem_file(cls, path: str, key_id: str = "certichain-local-key-1") -> "LocalECDSASigner":
        from cryptography.hazmat.primitives import serialization
        with open(path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
        return cls(key, key_id)

    def save_pem_file(self, path: str) -> None:
        from cryptography.hazmat.primitives import serialization
        pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(path, "wb") as fh:
            fh.write(pem)

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign_digest(self, digest32: bytes) -> bytes:
        if len(digest32) != 32:
            raise SigningError("L'empreinte à signer doit faire 32 octets (SHA-256).")
        der = self._private_key.sign(
            digest32, ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
        return der_to_raw(der)

    def public_key(self) -> EllipticCurvePublicKey:
        return self._private_key.public_key()


# ---------------------------------------------------------------------------
# Vérification (n'utilise QUE la clé publique)
# ---------------------------------------------------------------------------
def verify_digest(
    public_key: EllipticCurvePublicKey, digest32: bytes, raw_signature: bytes
) -> bool:
    """Vérifie une signature r||s (64 octets) sur une empreinte SHA-256 (32 octets)."""
    try:
        der = raw_to_der(raw_signature)
        public_key.verify(der, digest32, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except (InvalidSignature, SigningError, ValueError):
        return False
