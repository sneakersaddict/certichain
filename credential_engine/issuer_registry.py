
from __future__ import annotations

import abc
import json
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
    """A recognized issuer and its public signing identity."""

    issuer_id: str
    name: str
    identifier: str
    public_key_id: str
    public_jwk: Dict[str, Any]
    status: str = TRUSTED
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    )

    def is_trusted(self) -> bool:
        return self.status == TRUSTED

    def public_key(self) -> EllipticCurvePublicKey:
        return jwk_to_public_key(self.public_jwk)

    def public_info(self) -> Dict[str, Any]:
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


def parse_verification_method(
    verification_method: str,
) -> Tuple[Optional[str], Optional[str]]:
    if not isinstance(verification_method, str) or "#" not in verification_method:
        return None, None

    did, key_id = verification_method.split("#", 1)

    if not did.startswith(ISSUER_DID_PREFIX) or not key_id:
        return None, None

    return did[len(ISSUER_DID_PREFIX):], key_id


class IssuerRegistry(abc.ABC):

    @abc.abstractmethod
    def get_issuer(self, issuer_id: str) -> Optional[Issuer]:
        ...

    def resolve_verification_method(
        self, verification_method: str
    ) -> Optional[Tuple[Issuer, EllipticCurvePublicKey]]:

        issuer_id, key_id = parse_verification_method(verification_method)

        if not issuer_id or not key_id:
            return None

        issuer = self.get_issuer(issuer_id)

        if issuer is None:
            return None

        if key_id != issuer.public_key_id:
            return None

        return issuer, issuer.public_key()


class InMemoryIssuerRegistry(IssuerRegistry):
    """Registry used for local tests and demonstrations."""

    def __init__(self) -> None:
        self._issuers: Dict[str, Issuer] = {}

    def add_issuer(self, issuer: Issuer) -> None:
        self._issuers[issuer.issuer_id] = issuer

    def register_from_signer(
        self,
        issuer_id: str,
        name: str,
        identifier: str,
        signer,
        status: str = TRUSTED,
    ) -> Issuer:

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
    Reads issuer metadata and public JWK from the existing
    dbo.Issuers table.

    Expected columns:
      issuer_id
      issuer_name
      issuer_identifier
      status
      engine_issuer_id
      public_key_id
      public_jwk
      created_at
    """

    def __init__(self, connection_string: str):
        try:
            import pyodbc
        except ImportError as exc:
            raise RuntimeError(
                "pyodbc is missing. Install pyodbc and "
                "Microsoft ODBC Driver 18 for SQL Server."
            ) from exc

        self._conn_str = connection_string

    def get_issuer(self, issuer_id: str) -> Optional[Issuer]:
        import pyodbc

        query = """
            SELECT TOP 1
                engine_issuer_id,
                issuer_name,
                issuer_identifier,
                status,
                public_key_id,
                public_jwk,
                created_at
            FROM dbo.Issuers
            WHERE engine_issuer_id = ?
        """

        with pyodbc.connect(self._conn_str) as conn:
            row = conn.cursor().execute(query, issuer_id).fetchone()

        if row is None:
            return None

        engine_id = row[0]
        name = row[1]
        identifier = row[2]
        db_status = row[3]
        public_key_id = row[4]
        public_jwk_json = row[5]
        created_at = row[6]

        if not public_jwk_json:
            raise RuntimeError(
                f"Issuer '{issuer_id}' has no public JWK in dbo.Issuers."
            )

        public_jwk = json.loads(public_jwk_json)

        # Validate that the stored public key is usable.
        jwk_to_public_key(public_jwk)

        # Only ACTIVE issuers are trusted.
        mapped_status = TRUSTED if db_status == "ACTIVE" else SUSPENDED

        if isinstance(created_at, datetime):
            created_at = created_at.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        elif created_at is None:
            created_at = ""

        return Issuer(
            issuer_id=engine_id,
            name=name,
            identifier=identifier,
            public_key_id=public_key_id,
            public_jwk=public_jwk,
            status=mapped_status,
            created_at=created_at,
        )
