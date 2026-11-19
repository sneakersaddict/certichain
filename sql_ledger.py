"""
Registre de confiance + cycle de vie sur Azure SQL Database (tables LEDGER).

Ce module branche l'API sur le SCHÉMA DE LA PHASE 3 (conçu par Rihab) déjà présent
dans `certichain-db` :

    dbo.Issuers           émetteurs (PENDING | ACTIVE | SUSPENDED | DEACTIVATED)
    dbo.IssuerEvents      journal des émetteurs (ISSUER_REGISTERED, ISSUER_ACTIVATED...)
    dbo.Credentials       registre des credentials (ISSUED | SUSPENDED | REVOKED | EXPIRED)
    dbo.CredentialEvents  journal des credentials (CREDENTIAL_ISSUED, CREDENTIAL_REVOKED...)
    (+ dbo.Users, dbo.Roles, dbo.UserRoles pour les rôles applicatifs)

Toutes ces tables sont des tables LEDGER : chaque transaction est chaînée par
hachage et l'historique des lignes est conservé ; une modification « en douce »
est détectable (sys.sp_verify_database_ledger).

Correspondance moteur (Phase 2) <-> registre (Phase 3) :
    statut credential : active <-> ISSUED, suspended <-> SUSPENDED,
                        revoked <-> REVOKED, expired <-> EXPIRED
    statut émetteur   : trusted <-> ACTIVE, suspended <-> SUSPENDED,
                        pending <-> PENDING, deactivated <-> DEACTIVATED
    émetteur          : Issuers.engine_issuer_id = issuer_id du moteur (ex. « uir »)
    credential        : Credentials.credential_reference = id du VC (urn:uuid:...)

Authentification : AUCUN mot de passe. La Function App obtient un jeton Entra ID
via son identité managée (DefaultAzureCredential) et le passe au pilote ODBC.
"""

from __future__ import annotations

import json
import re
import struct
import time
from typing import Any, Dict, List, Optional

from .issuer_registry import SUSPENDED, TRUSTED, Issuer
from .lifecycle import (
    LifecycleError,
    TrustLedger,
    build_credential_record,
    normalize_credential_id,
)
from .status_store import CredentialStatus

_SQL_COPT_SS_ACCESS_TOKEN = 1256
_TOKEN_SCOPE = "https://database.windows.net/.default"
_TRANSIENT = ("40613", "40197", "40501", "49918", "4060", "HYT00", "08S01", "08001")
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

CRED_TO_DB = {"active": "ISSUED", "suspended": "SUSPENDED", "revoked": "REVOKED", "expired": "EXPIRED"}
CRED_FROM_DB = {v: k for k, v in CRED_TO_DB.items()}
ISSUER_TO_DB = {TRUSTED: "ACTIVE", SUSPENDED: "SUSPENDED", "pending": "PENDING",
                "deactivated": "DEACTIVATED"}
ISSUER_FROM_DB = {v: k for k, v in ISSUER_TO_DB.items()}

_CRED_EVENT = {"ISSUED": "CREDENTIAL_ISSUED", "SUSPENDED": "CREDENTIAL_SUSPENDED",
               "REACTIVATED": "CREDENTIAL_REACTIVATED", "REVOKED": "CREDENTIAL_REVOKED"}


def _upper(status: Optional[str], table: Dict[str, str]) -> Optional[str]:
    return table.get(status, status.upper()) if status else None


class SqlTrustLedger(TrustLedger):
    def __init__(self, server: str, database: str, credential: Optional[object] = None,
                 retries: int = 5):
        import pyodbc  # noqa: F401

        self._server = server if server.endswith(".database.windows.net") else f"{server}.database.windows.net"
        self._database = database
        self._credential = credential
        self._retries = retries

    # ------------------------------------------------------------ connexion
    def _driver(self) -> str:
        import pyodbc
        drivers = [d for d in pyodbc.drivers() if "SQL Server" in d]
        for wanted in ("ODBC Driver 18 for SQL Server", "ODBC Driver 17 for SQL Server"):
            if wanted in drivers:
                return wanted
        if drivers:
            return drivers[-1]
        raise RuntimeError("Aucun pilote ODBC SQL Server trouvé.")

    def _token_struct(self) -> bytes:
        if self._credential is None:
            from azure.identity import DefaultAzureCredential
            self._credential = DefaultAzureCredential()
        token = self._credential.get_token(_TOKEN_SCOPE).token.encode("utf-16-le")
        return struct.pack(f"<I{len(token)}s", len(token), token)

    def _connect(self):
        import pyodbc
        conn_str = (
            f"Driver={{{self._driver()}}};Server=tcp:{self._server},1433;"
            f"Database={self._database};Encrypt=yes;TrustServerCertificate=no;"
            "Connection Timeout=60;"
        )
        last = None
        for attempt in range(self._retries):
            try:
                return pyodbc.connect(conn_str, attrs_before={_SQL_COPT_SS_ACCESS_TOKEN: self._token_struct()})
            except pyodbc.Error as exc:  # pragma: no cover - réseau
                last = exc
                if not any(code in str(exc) for code in _TRANSIENT):
                    raise
                time.sleep(6 * (attempt + 1))   # base Serverless en cours de réveil
        raise last  # pragma: no cover

    def _rows(self, sql: str, *params) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(sql, *params)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def _exec(self, statements: List[tuple]) -> None:
        """Exécute plusieurs requêtes dans UNE transaction (état + événement ensemble)."""
        with self._connect() as conn:
            cur = conn.cursor()
            for sql, params in statements:
                cur.execute(sql, *params)
            conn.commit()

    # ------------------------------------------------------------ émetteurs
    _ISSUER_COLS = ("CONVERT(NVARCHAR(36), issuer_id) AS guid, engine_issuer_id, issuer_name, "
                    "issuer_identifier, status, public_key_id, public_jwk, created_at")

    def _issuer_from_row(self, row: Dict[str, Any]) -> Issuer:
        issuer = Issuer(
            issuer_id=row["engine_issuer_id"] or row["guid"],
            name=row["issuer_name"],
            identifier=row["issuer_identifier"],
            public_key_id=row["public_key_id"] or "",
            public_jwk=json.loads(row["public_jwk"]) if row["public_jwk"] else {},
            status=ISSUER_FROM_DB.get(row["status"], row["status"].lower()),
            created_at=_iso(row.get("created_at")),
        )
        issuer.registry_guid = row["guid"]
        for k in self._rows(
                "SELECT key_id, public_jwk, status, activated_at, retired_at FROM dbo.IssuerKeys "
                "WHERE issuer_id = ? ORDER BY activated_at", row["guid"]):
            issuer.keys[k["key_id"]] = {"jwk": json.loads(k["public_jwk"]), "status": k["status"].lower(),
                                        "activated_at": _iso(k["activated_at"]),
                                        "retired_at": _iso(k["retired_at"])}
        return issuer

    def _issuer_row(self, issuer_id: str) -> Optional[Dict[str, Any]]:
        col = "issuer_id" if _GUID.match(issuer_id or "") else "engine_issuer_id"
        rows = self._rows(f"SELECT {self._ISSUER_COLS} FROM dbo.Issuers WHERE {col} = ?", issuer_id)
        return rows[0] if rows else None

    def get_issuer(self, issuer_id: str) -> Optional[Issuer]:
        row = self._issuer_row(issuer_id)
        return self._issuer_from_row(row) if row else None

    def list_issuers(self) -> List[Issuer]:
        rows = self._rows(f"SELECT {self._ISSUER_COLS} FROM dbo.Issuers ORDER BY created_at")
        return [self._issuer_from_row(r) for r in rows]

    _INSERT_ISSUER = (
        "DECLARE @id UNIQUEIDENTIFIER = NEWID(); "
        "INSERT INTO dbo.Issuers (issuer_id, issuer_name, issuer_identifier, verification_method, "
        "signing_key_reference, status, engine_issuer_id, public_key_id, public_jwk) "
        "VALUES (@id, ?, ?, ?, ?, ?, ?, ?, ?); "
        "INSERT INTO dbo.IssuerEvents (issuer_id, event_type, previous_status, new_status, actor_id, details) "
        "VALUES (@id, 'ISSUER_REGISTERED', NULL, ?, ?, ?);"
    )

    def register_issuer(self, issuer: Issuer, actor: str = "admin") -> Issuer:
        """Inscrit un émetteur en statut PENDING : un admin doit ensuite l'ACTIVER."""
        if self.get_issuer(issuer.issuer_id) is not None:
            raise LifecycleError(f"Émetteur « {issuer.issuer_id} » déjà inscrit.", code="already_exists")
        vm = f"did:certichain:issuer:{issuer.issuer_id}#{issuer.public_key_id}"
        self._exec([(self._INSERT_ISSUER, (
            issuer.name, issuer.identifier, vm, issuer.public_key_id, "PENDING", issuer.issuer_id,
            issuer.public_key_id, json.dumps(issuer.public_jwk),
            "PENDING", actor, "Émetteur inscrit via l'API, en attente d'activation"))])
        return self.get_issuer(issuer.issuer_id)

    def ensure_issuer(self, issuer: Issuer) -> Issuer:
        """
        Au démarrage : rattache la clé Key Vault ACTIVE de l'émetteur du moteur à sa
        fiche du registre (création si absente, mise à jour si la clé a tourné).
        """
        row = self._issuer_row(issuer.issuer_id)
        vm = f"did:certichain:issuer:{issuer.issuer_id}#{issuer.public_key_id}"
        if row is None:
            self._exec([(self._INSERT_ISSUER, (
                issuer.name, issuer.identifier, vm, issuer.public_key_id, "ACTIVE", issuer.issuer_id,
                issuer.public_key_id, json.dumps(issuer.public_jwk),
                "ACTIVE", "system:bootstrap", "Émetteur du moteur enregistré au démarrage"))])
            row = self._issuer_row(issuer.issuer_id)
        elif row["public_key_id"] != issuer.public_key_id:
            # ROTATION (concept §9) : l'ancienne clé passe RETIRED (reste vérifiable pour
            # les credentials émis avant), la nouvelle devient ACTIVE. Tout est tracé.
            self._exec([
                ("IF NOT EXISTS (SELECT 1 FROM dbo.IssuerKeys WHERE key_id = ?) "
                 "INSERT INTO dbo.IssuerKeys (key_id, issuer_id, public_jwk, status) VALUES (?, ?, ?, 'ACTIVE')",
                 (row["public_key_id"], row["public_key_id"], row["guid"], row["public_jwk"] or "{}")),
                ("UPDATE dbo.IssuerKeys SET status = 'RETIRED', retired_at = SYSUTCDATETIME() "
                 "WHERE issuer_id = ? AND status = 'ACTIVE'", (row["guid"],)),
                ("INSERT INTO dbo.IssuerKeys (key_id, issuer_id, public_jwk, status) VALUES (?, ?, ?, 'ACTIVE')",
                 (issuer.public_key_id, row["guid"], json.dumps(issuer.public_jwk))),
                ("UPDATE dbo.Issuers SET public_key_id = ?, public_jwk = ?, verification_method = ?, "
                 "signing_key_reference = ?, updated_at = SYSUTCDATETIME() WHERE issuer_id = ?",
                 (issuer.public_key_id, json.dumps(issuer.public_jwk), vm, issuer.public_key_id, row["guid"])),
                ("INSERT INTO dbo.IssuerEvents (issuer_id, event_type, previous_status, new_status, actor_id, details) "
                 "VALUES (?, 'ISSUER_KEY_ROTATED', ?, ?, 'system:key-rotation', ?)",
                 (row["guid"], row["status"], row["status"],
                  f"Ancienne clé RETIRED : {row['public_key_id']} ; nouvelle clé ACTIVE : {issuer.public_key_id}"[:2000])),
            ])
            row = self._issuer_row(issuer.issuer_id)
        # Garantit que la clé active figure dans l'historique des clés.
        self._exec([(
            "IF NOT EXISTS (SELECT 1 FROM dbo.IssuerKeys WHERE key_id = ?) "
            "INSERT INTO dbo.IssuerKeys (key_id, issuer_id, public_jwk, status) VALUES (?, ?, ?, 'ACTIVE')",
            (issuer.public_key_id, issuer.public_key_id, row["guid"], json.dumps(issuer.public_jwk)))])
        return self.get_issuer(issuer.issuer_id)

    def _save_issuer_status(self, issuer_id: str, status: str) -> None:
        row = self._issuer_row(issuer_id)
        self._exec([("UPDATE dbo.Issuers SET status = ?, updated_at = SYSUTCDATETIME() WHERE issuer_id = ?",
                     (ISSUER_TO_DB[status], row["guid"]))])

    # ------------------------------------------------------------ droits & sécurité
    def _user_roles(self, email: str) -> Optional[set]:
        rows = self._rows(
            "SELECT u.status, r.role_name FROM dbo.Users u "
            "LEFT JOIN dbo.UserRoles ur ON ur.user_id = u.user_id "
            "LEFT JOIN dbo.Roles r ON r.role_id = ur.role_id "
            "WHERE LOWER(u.email) = LOWER(?)", email or "")
        if not rows or rows[0]["status"] != "ACTIVE":
            return None
        return {r["role_name"] for r in rows if r["role_name"]}

    def _allowed_types(self, issuer_id: str) -> set:
        rows = self._rows(
            "SELECT t.credential_type FROM dbo.IssuerCredentialTypes t "
            "JOIN dbo.Issuers i ON i.issuer_id = t.issuer_id WHERE i.engine_issuer_id = ?", issuer_id)
        return {r["credential_type"] for r in rows}

    def _log_security_event(self, event_type, actor, action, target, details) -> None:
        self._exec([(
            "INSERT INTO dbo.SecurityEvents (event_type, actor_id, action, target, details) "
            "VALUES (?, ?, ?, ?, ?)",
            (event_type, (actor or "")[:400] or None, action, (target or "")[:400] or None,
             (details or "")[:2000] or None))])

    def security_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        rows = self._rows(
            "SELECT TOP (?) event_id, event_type, actor_id, action, target, details, event_time, "
            "ledger_start_transaction_id FROM dbo.SecurityEvents ORDER BY event_id DESC", int(limit))
        return [{"event_id": r["event_id"], "event_type": r["event_type"], "actor": r["actor_id"],
                 "action": r["action"], "target": r["target"], "details": r["details"],
                 "occurred_at": _iso(r["event_time"]),
                 "ledger_transaction_id": r["ledger_start_transaction_id"]} for r in rows]

    # ------------------------------------------------------------ credentials
    _CRED_COLS = ("CONVERT(NVARCHAR(36), c.credential_id) AS guid, c.credential_reference, "
                  "i.engine_issuer_id, CONVERT(NVARCHAR(36), c.issuer_id) AS issuer_guid, "
                  "c.holder_reference, c.credential_type, c.credential_format, c.document_reference, "
                  "c.status, c.issued_at, c.valid_from, c.expires_at, c.updated_at")

    def _record_row(self, credential_id: str) -> Optional[Dict[str, Any]]:
        base = f"SELECT {self._CRED_COLS} FROM dbo.Credentials c JOIN dbo.Issuers i ON i.issuer_id = c.issuer_id "
        if _GUID.match(credential_id or ""):
            rows = self._rows(base + "WHERE c.credential_id = ?", credential_id)
        else:
            rows = self._rows(base + "WHERE c.credential_reference = ?", credential_id)
        return rows[0] if rows else None

    def get_record(self, credential_id: str) -> Optional[Dict[str, Any]]:
        row = self._record_row(credential_id)
        if row is None:
            return None
        return {
            "credential_id": row["credential_reference"],
            "registry_id": row["guid"],
            "issuer_id": row["engine_issuer_id"] or row["issuer_guid"],
            "holder_id": row["holder_reference"],
            "credential_type": row["credential_type"],
            "credential_format": row["credential_format"],
            "document_reference": row["document_reference"],
            "status": CRED_FROM_DB.get(row["status"], row["status"].lower()),
            "registry_status": row["status"],
            "issued_at": _iso(row["issued_at"]),
            "valid_from": _iso(row["valid_from"]),
            "expires_at": _iso(row["expires_at"]),
            "updated_at": _iso(row["updated_at"]),
        }

    def record_issuance(self, credential: Dict[str, Any], actor: str = "issuer",
                        document_id: Optional[str] = None) -> Dict[str, Any]:
        """Émission = ligne Credentials + événement CREDENTIAL_ISSUED (+ rattachement du PDF), en UNE transaction."""
        rec = build_credential_record(credential)
        issuer_row = self._issuer_row(rec["issuer_id"])
        if issuer_row is None:
            raise LifecycleError(f"Émetteur « {rec['issuer_id']} » absent du registre.",
                                 code="unknown_issuer")
        cred_guid = credential["id"].split(":")[-1]
        details = json.dumps({"credential_hash_sha256": rec["credential_hash"]})
        self._exec([
            ("INSERT INTO dbo.Credentials (credential_id, credential_reference, issuer_id, holder_reference, "
             "credential_type, credential_format, document_reference, issued_at, valid_from, expires_at, status) "
             "VALUES (?, ?, ?, ?, ?, 'W3C_VC_JSON', ?, ?, ?, ?, 'ISSUED')",
             (cred_guid, credential["id"], issuer_row["guid"], rec["holder_id"], rec["credential_type"],
              rec.get("document_reference"), _dt(credential.get("issuanceDate")),
              _dt(credential.get("validFrom")), _dt(credential.get("expirationDate")))),
            ("INSERT INTO dbo.CredentialEvents (credential_id, event_type, previous_status, new_status, actor_id, details) "
             "VALUES (?, 'CREDENTIAL_ISSUED', NULL, 'ISSUED', ?, ?)",
             (cred_guid, actor, details)),
        ] + ([(
            "UPDATE dbo.Documents SET credential_id = ?, status = 'LINKED', updated_at = SYSUTCDATETIME() "
            "WHERE document_id = ? AND status = 'UPLOADED'", (cred_guid, document_id))] if document_id else []))
        return self.get_record(credential["id"])

    # ------------------------------------------------------------ Phase 4 : documents
    _DOC_COLS = ("CONVERT(NVARCHAR(36), document_id) AS document_id, "
                 "CONVERT(NVARCHAR(36), credential_id) AS credential_id, blob_reference, content_hash, "
                 "media_type, size_bytes, original_name, retention_metadata, status, uploaded_by, "
                 "created_at, ledger_start_transaction_id")

    def record_document(self, meta: Dict[str, Any], actor: str) -> Dict[str, Any]:
        self._exec([(
            "INSERT INTO dbo.Documents (document_id, blob_reference, content_hash, media_type, size_bytes, "
            "original_name, retention_metadata, status, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?, 'UPLOADED', ?)",
            (meta["document_id"], meta["blob_reference"], meta["content_hash"], meta["media_type"],
             meta["size_bytes"], meta.get("original_name"), meta.get("retention_metadata"), actor))])
        return self.get_document(meta["document_id"])

    def get_document(self, document_id: str) -> Optional[Dict[str, Any]]:
        if not _GUID.match(document_id or ""):
            return None
        rows = self._rows(f"SELECT {self._DOC_COLS} FROM dbo.Documents WHERE document_id = ?", document_id)
        if not rows:
            return None
        r = rows[0]
        r["created_at"] = _iso(r["created_at"])
        r["ledger_transaction_id"] = r.pop("ledger_start_transaction_id")
        return r

    def _link_document(self, document_id: str, credential_id: str) -> None:  # pragma: no cover
        pass  # fait dans la transaction de record_issuance()

    # ------------------------------------------------------------ Phase 5 : portefeuille & partage
    def user_id_for(self, email: str, role: Optional[str] = None) -> Optional[str]:
        sql = ("SELECT CONVERT(NVARCHAR(36), u.user_id) AS uid FROM dbo.Users u "
               "LEFT JOIN dbo.UserRoles ur ON ur.user_id = u.user_id "
               "LEFT JOIN dbo.Roles r ON r.role_id = ur.role_id "
               "WHERE LOWER(u.email) = LOWER(?) AND u.status = 'ACTIVE'")
        params = [email or ""]
        if role:
            sql += " AND r.role_name = ?"
            params.append(role)
        rows = self._rows(sql, *params)
        return rows[0]["uid"] if rows else None

    def credentials_for_holder(self, holder_did: str) -> List[Dict[str, Any]]:
        rows = self._rows(
            "SELECT c.credential_reference FROM dbo.Credentials c WHERE c.holder_reference = ? "
            "ORDER BY c.issued_at DESC", holder_did)
        return [self.get_record(r["credential_reference"]) for r in rows]

    _SHARE_COLS = ("CONVERT(NVARCHAR(36), s.share_id) AS share_id, c.credential_reference, s.created_by, "
                   "s.created_at, s.expires_at, s.revoked, s.access_count, s.ledger_start_transaction_id")

    def _share_out(self, r: Dict[str, Any]) -> Dict[str, Any]:
        return {"share_id": r["share_id"], "credential_id": r["credential_reference"],
                "created_by": r["created_by"], "created_at": _iso(r["created_at"]),
                "expires_at": _iso(r["expires_at"]), "revoked": bool(r["revoked"]),
                "access_count": r["access_count"],
                "ledger_transaction_id": r["ledger_start_transaction_id"]}

    def create_share(self, credential_id, token_hash, expires_at, actor) -> Dict[str, Any]:
        row = self._record_row(credential_id)
        import uuid
        share_id = str(uuid.uuid4()).upper()
        self._exec([(
            "INSERT INTO dbo.CredentialShares (share_id, credential_id, token_hash, created_by, expires_at) "
            "VALUES (?, ?, ?, ?, ?)", (share_id, row["guid"], token_hash, actor, _dt(expires_at)))])
        rows = self._rows(f"SELECT {self._SHARE_COLS} FROM dbo.CredentialShares s JOIN dbo.Credentials c "
                          "ON c.credential_id = s.credential_id WHERE s.share_id = ?", share_id)
        return self._share_out(rows[0])

    def resolve_share(self, token_hash: str) -> Optional[Dict[str, Any]]:
        rows = self._rows(f"SELECT {self._SHARE_COLS} FROM dbo.CredentialShares s JOIN dbo.Credentials c "
                          "ON c.credential_id = s.credential_id WHERE s.token_hash = ?", token_hash)
        if not rows:
            return None
        self._exec([("UPDATE dbo.CredentialShares SET access_count = access_count + 1, "
                     "last_accessed_at = SYSUTCDATETIME() WHERE share_id = ?", (rows[0]["share_id"],))])
        return self._share_out(rows[0])

    def revoke_share(self, share_id: str, actor: str) -> None:
        if not _GUID.match(share_id or ""):
            raise LifecycleError("Partage inconnu.", code="not_found", http_status=404)
        self._exec([("UPDATE dbo.CredentialShares SET revoked = 1, revoked_at = SYSUTCDATETIME() "
                     "WHERE share_id = ?", (share_id,))])

    def shares_for_credential(self, credential_id: str) -> List[Dict[str, Any]]:
        row = self._record_row(credential_id)
        if row is None:
            return []
        rows = self._rows(f"SELECT {self._SHARE_COLS} FROM dbo.CredentialShares s JOIN dbo.Credentials c "
                          "ON c.credential_id = s.credential_id WHERE s.credential_id = ? "
                          "ORDER BY s.created_at DESC", row["guid"])
        return [self._share_out(r) for r in rows]

    def _insert_record(self, record: Dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError("Utiliser record_issuance().")

    def _save_status(self, credential_id: str, status: CredentialStatus,
                     reason: Optional[str]) -> None:
        row = self._record_row(credential_id)
        self._exec([("UPDATE dbo.Credentials SET status = ?, updated_at = SYSUTCDATETIME() "
                     "WHERE credential_id = ?", (CRED_TO_DB[status.value], row["guid"]))])

    # ------------------------------------------------------------ journaux ledger
    def _append_event(self, entity_type, entity_id, event_type, old_status, new_status,
                      reason, actor) -> None:
        if entity_type == "credential":
            row = self._record_row(entity_id)
            self._exec([(
                "INSERT INTO dbo.CredentialEvents (credential_id, event_type, previous_status, new_status, actor_id, details) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (row["guid"], _CRED_EVENT.get(event_type, event_type),
                 _upper(old_status, CRED_TO_DB), _upper(new_status, CRED_TO_DB), actor, reason))])
        else:
            row = self._issuer_row(entity_id)
            evt = event_type
            if event_type == "ISSUER_REACTIVATED" and old_status == "pending":
                evt = "ISSUER_ACTIVATED"
            self._exec([(
                "INSERT INTO dbo.IssuerEvents (issuer_id, event_type, previous_status, new_status, actor_id, details) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (row["guid"], evt, _upper(old_status, ISSUER_TO_DB), _upper(new_status, ISSUER_TO_DB),
                 actor, reason))])

    def history(self, entity_id: str) -> List[Dict[str, Any]]:
        issuer_row = None if entity_id.startswith("urn:") else self._issuer_row(entity_id)
        if issuer_row is not None:
            rows = self._rows(
                "SELECT event_type, previous_status, new_status, actor_id, event_time, details, "
                "ledger_start_transaction_id FROM dbo.IssuerEvents WHERE issuer_id = ? "
                "ORDER BY event_time", issuer_row["guid"])
        else:
            row = self._record_row(entity_id)
            if row is None:
                return []
            rows = self._rows(
                "SELECT event_type, previous_status, new_status, actor_id, event_time, details, "
                "ledger_start_transaction_id FROM dbo.CredentialEvents WHERE credential_id = ? "
                "ORDER BY event_time", row["guid"])
        return [{
            "event_type": r["event_type"],
            "old_status": r["previous_status"],
            "new_status": r["new_status"],
            "actor": r["actor_id"],
            "occurred_at": _iso(r["event_time"]),
            "details": r["details"],
            "ledger_transaction_id": r["ledger_start_transaction_id"],
        } for r in rows]


def _iso(value) -> Optional[str]:
    if value is None:
        return None
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


def _dt(value):
    """ISO 8601 « 2026-11-16T14:00:00Z » -> datetime naïf UTC pour DATETIME2."""
    if not value:
        return None
    from datetime import datetime
    return datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
