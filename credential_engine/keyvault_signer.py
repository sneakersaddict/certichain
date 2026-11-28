"""
Signataire Azure Key Vault (production).

Principe (concept §5.3, §8) :
- La clé privée ECDSA P-256 est générée DANS Key Vault et marquée non exportable.
- Le backend ne reçoit JAMAIS la clé privée : il demande à Key Vault de signer une
  empreinte, et Key Vault renvoie la signature.
- L'authentification se fait via Managed Identity (en production sur Azure) ou
  via DefaultAzureCredential (ex. `az login` en local) — aucun secret dans le code.

Dépendances (uniquement nécessaires pour CE fichier, pas pour les tests) :
    pip install azure-identity azure-keyvault-keys

Les imports Azure sont « paresseux » pour que le reste du moteur et les tests
unitaires fonctionnent sans les bibliothèques Azure installées.
"""

from __future__ import annotations

from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from .errors import SigningError
from .signing import Signer, jwk_to_public_key


class AzureKeyVaultSigner(Signer):
    """
    Signe via Azure Key Vault avec l'algorithme ES256.
    La clé Key Vault doit être de type EC / courbe P-256.
    """

    def __init__(self, vault_url: str, key_name: str, credential: Optional[object] = None):
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys import KeyClient
            from azure.keyvault.keys.crypto import CryptographyClient
        except ImportError as exc:  # pragma: no cover - dépend de l'environnement
            raise SigningError(
                "Bibliothèques Azure manquantes. Installez : "
                "pip install azure-identity azure-keyvault-keys"
            ) from exc

        self._crypto_algorithms = __import__(
            "azure.keyvault.keys.crypto", fromlist=["SignatureAlgorithm"]
        ).SignatureAlgorithm

        cred = credential or DefaultAzureCredential()
        self._cred = cred
        self._key_name = key_name
        self._key_client = KeyClient(vault_url=vault_url, credential=cred)
        self._load()

    def _load(self) -> None:
        """Charge la DERNIÈRE version de la clé (après une rotation, c'est la nouvelle)."""
        import time
        from azure.keyvault.keys.crypto import CryptographyClient

        kv_key = self._key_client.get_key(self._key_name)
        crv = getattr(kv_key.key, "crv", None)
        # Le SDK renvoie un enum (KeyCurveName.p_256) : on compare sa valeur "P-256".
        crv_value = str(getattr(crv, "value", crv) or "")
        if crv_value.replace("_", "-").upper() not in ("P-256", "P256"):
            raise SigningError(
                f"La clé Key Vault doit être EC P-256 (courbe trouvée : {crv_value})."
            )
        self._kv_key = kv_key
        self._crypto = CryptographyClient(kv_key, credential=self._cred)
        self._key_id = kv_key.id  # URL versionnée de la clé
        self._public_key = self._build_public_key()
        self._loaded_at = time.monotonic()

    def refresh(self, force: bool = False, max_age_seconds: int = 60) -> bool:
        """
        Rotation de clé (concept §9) : chaque instance relit périodiquement la version
        courante de la clé dans Key Vault. Retourne True si la version a changé.
        Évite qu'une instance « ancienne » continue à signer avec une clé retirée.
        """
        import time
        if not force and time.monotonic() - self._loaded_at < max_age_seconds:
            return False
        old = self._key_id
        self._load()
        return self._key_id != old

    def _build_public_key(self) -> EllipticCurvePublicKey:
        k = self._kv_key.key  # JsonWebKey : contient x, y en octets bruts
        from .signing import b64url_encode
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url_encode(k.x),
            "y": b64url_encode(k.y),
            "kid": self._kv_key.id,
        }
        return jwk_to_public_key(jwk)

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign_digest(self, digest32: bytes) -> bytes:
        if len(digest32) != 32:
            raise SigningError("L'empreinte à signer doit faire 32 octets (SHA-256).")
        # Key Vault renvoie déjà la signature au format brut r||s (64 octets) pour ES256.
        result = self._crypto.sign(self._crypto_algorithms.es256, digest32)
        return result.signature

    def public_key(self) -> EllipticCurvePublicKey:
        return self._public_key


def create_keyvault_ec_key_cli_hint(vault_name: str, key_name: str = "certichain-issuer-key") -> str:
    """
    Retourne la commande Azure CLI pour créer la clé EC P-256 non exportable.
    (Aide-mémoire pour l'étape d'intégration ; voir README.)
    """
    return (
        f"az keyvault key create --vault-name {vault_name} --name {key_name} "
        f"--kty EC --curve P-256 --ops sign verify --exportable false"
    )
