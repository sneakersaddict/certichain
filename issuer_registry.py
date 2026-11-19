"""
Registre de confiance des émetteurs (issuer trust).

Concept clé du projet (§2.1, §8) : une signature valide ne suffit PAS. Le
vérificateur doit aussi établir que l'émetteur est RECONNU et AUTORISÉ, et que la
clé qui a signé appartient bien à cet émetteur. Sinon, n'importe qui pourrait
générer une signature « mathématiquement valide » avec sa propre clé.

Le registre associe : issuer_id -> (métadonnées de l'émetteur + clé(s) publique(s)).
Il ne contient JAMAIS de clé privée.

Deux implémentations :
- InMemoryIssuerRegistry : pour les tests et la démo.
- SqlIssuerRegistry      : lit les métadonnées émetteur/clé depuis Azure SQL
                           (concept : « Azure SQL pour les métadonnées issuer/clé »).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from .models import ISSUER_DID_PREFIX
from .signing import jwk_to_public_key

TRUSTED = "trusted"
SUSPENDED = "suspended"


@dataclass
class Issuer:
    """Un émetteur reconnu (ex. l'université) et son identité de signature."""

    issuer_id: str
    name: str
    identifier: str                      # ex. identifiant officiel / domaine
    public_key_id: str                   # kid de la clé publique active
    public_jwk: Dict[str, Any]           # clé publique (JWK EC P-256)
    status: str = TRUSTED                # trusted | suspended
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    # Historique des clés (rotation) : key_id -> {"jwk", "status", "activated_at", "retired_at"}
    # status : active | retired (ancienne clé, reste vérifiable) | compromised (rejetée)
    keys: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def is_trusted(self) -> bool:
        return self.status == TRUSTED

    def public_key(self) -> EllipticCurvePublicKey:
        return jwk_to_public_key(self.public_jwk)

    def public_info(self) -> Dict[str, Any]:
        """Infos publiques (pour GET /api/issuers/{id}) — aucune donnée sensible."""
        return {
            "issuer_id": self.issuer_id,
            "name": self.name,
            "identifier": self.identifier,
            "status": self.status,
            "trusted": self.is_trusted(),
            "public_key_id": self.public_key_id,
            "publicKeyJwk": self.public_jwk,
            "created_at": self.created_at,
            "keys": [
                {"key_id": kid, "status": k.get("status"), "activated_at": k.get("activated_at"),
                 "retired_at": k.get("retired_at"), "publicKeyJwk": k.get("jwk")}
                for kid, k in self.keys.items()
            ],
        }


def parse_verification_method(verification_method: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Décompose un verificationMethod « did:certichain:issuer:<id>#<key_id> »
    en (issuer_id, key_id).
    """
    if "#" not in verification_method:
        return None, None
    did, key_id = verification_method.split("#", 1)
    if not did.startswith(ISSUER_DID_PREFIX):
        return None, key_id
    return did[len(ISSUER_DID_PREFIX):], key_id


class IssuerRegistry(abc.ABC):
    """Interface du registre de confiance."""

    @abc.abstractmethod
    def get_issuer(self, issuer_id: str) -> Optional[Issuer]:
        ...

    def resolve_verification_method(
        self, verification_method: str, issued_at: Optional[str] = None
    ) -> Optional[Tuple[Issuer, EllipticCurvePublicKey]]:
        """
        À partir du verificationMethod d'une preuve, retourne (émetteur, clé publique)
        si l'émetteur existe ET que la clé référencée est bien la sienne. Sinon None.

        Rotation de clé (concept §9) : une ANCIENNE clé (« retired ») reste acceptée
        pour les credentials émis AVANT son retrait ; une clé « compromised » est
        toujours refusée.
        """
        issuer_id, key_id = parse_verification_method(verification_method)
        if not issuer_id:
            return None
        issuer = self.get_issuer(issuer_id)
        if issuer is None:
            return None
        if key_id is None or key_id == issuer.public_key_id:
            return issuer, issuer.public_key()
        old = issuer.keys.get(key_id)
        if not old or old.get("status") != "retired":
            return None  # clé inconnue ou compromise
        retired_at = old.get("retired_at")
        if retired_at and issued_at and issued_at[:19] > retired_at[:19]:
            return None  # signé avec une clé déjà retirée : suspect
        return issuer, jwk_to_public_key(old["jwk"])


class InMemoryIssuerRegistry(IssuerRegistry):
    """Registre en mémoire (tests / démo / bootstrap local)."""

    def __init__(self) -> None:
        self._issuers: Dict[str, Issuer] = {}

    def add_issuer(self, issuer: Issuer) -> None:
        self._issuers[issuer.issuer_id] = issuer

    def rotate_key(self, issuer_id: str, new_key_id: str, new_jwk: Dict[str, Any]) -> Issuer:
        """Rotation : l'ancienne clé passe « retired » (reste vérifiable), la nouvelle devient active."""
        issuer = self._issuers[issuer_id]
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        issuer.keys.setdefault(issuer.public_key_id, {"jwk": issuer.public_jwk, "status": "active"})
        issuer.keys[issuer.public_key_id].update(status="retired", retired_at=now)
        issuer.keys[new_key_id] = {"jwk": new_jwk, "status": "active", "activated_at": now}
        issuer.public_key_id, issuer.public_jwk = new_key_id, new_jwk
        return issuer

    def register_from_signer(
        self, issuer_id: str, name: str, identifier: str, signer, status: str = TRUSTED
    ) -> Issuer:
        """Crée et enregistre un émetteur à partir d'un Signer (sa clé publique)."""
        issuer = Issuer(
            issuer_id=issuer_id,
            name=name,
            identifier=identifier,
            public_key_id=signer.key_id,
            public_jwk=signer.public_jwk(),
            status=status,
        )
        self.add_issuer(issuer)
        return issuer

    def get_issuer(self, issuer_id: str) -> Optional[Issuer]:
        return self._issuers.get(issuer_id)


class SqlIssuerRegistry(IssuerRegistry):
    """
    Registre adossé à Azure SQL (métadonnées issuer/clé). Lecture seule ici ; la
    gestion du cycle de vie des émetteurs relève de la Phase 3 (trust registry).

    Nécessite `pip install pyodbc` et le pilote ODBC SQL Server. La connexion via
    Managed Identity est recommandée (voir README). Import paresseux.
    """

    def __init__(self, connection_string: str):
        try:
            import pyodbc  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "pyodbc manquant. Installez : pip install pyodbc "
                "(+ pilote ODBC Driver 18 for SQL Server)."
            ) from exc
        self._conn_str = connection_string

    def get_issuer(self, issuer_id: str) -> Optional[Issuer]:  # pragma: no cover
        import json
        import pyodbc
        query = (
            "SELECT issuer_id, name, identifier, status, public_key_id, public_jwk "
            "FROM dbo.Issuer WHERE issuer_id = ?"
        )
        with pyodbc.connect(self._conn_str) as conn:
            row = conn.cursor().execute(query, issuer_id).fetchone()
        if row is None:
            return None
        return Issuer(
            issuer_id=row.issuer_id,
            name=row.name,
            identifier=row.identifier,
            status=row.status,
            public_key_id=row.public_key_id,
            public_jwk=json.loads(row.public_jwk),
        )
