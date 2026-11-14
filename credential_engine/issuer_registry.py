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
        self, verification_method: str
    ) -> Optional[Tuple[Issuer, EllipticCurvePublicKey]]:
        """
        À partir du verificationMethod d'une preuve, retourne (émetteur, clé publique)
        si l'émetteur existe ET que la clé référencée est bien la sienne. Sinon None.
        """
        issuer_id, key_id = parse_verification_method(verification_method)
        if not issuer_id:
            return None
        issuer = self.get_issuer(issuer_id)
        if issuer is None:
            return None
        if key_id is not None and key_id != issuer.public_key_id:
            # La clé référencée n'est pas la clé active connue pour cet émetteur.
            return None
        return issuer, issuer.public_key()


class InMemoryIssuerRegistry(IssuerRegistry):
    """Registre en mémoire (tests / démo / bootstrap local)."""

    def __init__(self) -> None:
        self._issuers: Dict[str, Issuer] = {}

    def add_issuer(self, issuer: Issuer) -> None:
        self._issuers[issuer.issuer_id] = issuer

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
