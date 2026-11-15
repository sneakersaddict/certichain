
from __future__ import annotations

import abc
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional


class CredentialStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    UNKNOWN = "UNKNOWN"


class StatusStore(abc.ABC):
    @abc.abstractmethod
    def get_status(self, credential_id: str) -> CredentialStatus:
        ...

    @abc.abstractmethod
    def set_status(
        self,
        credential_id: str,
        status: CredentialStatus,
        reason: Optional[str] = None,
    ) -> None:
        ...

    @abc.abstractmethod
    def register_credential(
        self,
        credential: dict,
        issuer_id: str,
        actor_id: str = "certichain-system",
    ) -> None:
        ...


class InMemoryStatusStore(StatusStore):
    """In-memory implementation for local tests only."""

    def __init__(self):
        self._statuses: Dict[str, CredentialStatus] = {}

    def get_status(self, credential_id: str) -> CredentialStatus:
        return self._statuses.get(
            credential_id, CredentialStatus.UNKNOWN
        )

    def set_status(
        self,
        credential_id: str,
        status: CredentialStatus,
        reason: Optional[str] = None,
    ) -> None:
        self._statuses[credential_id] = status

    def register_credential(
        self,
        credential: dict,
        issuer_id: str,
        actor_id: str = "certichain-system",
    ) -> None:
        self._statuses[credential["id"]] = CredentialStatus.ACTIVE


class SqlLedgerStatusStore(StatusStore):
    """
    SQL-backed credential lifecycle store.

    Uses the existing dbo.Credentials and dbo.CredentialEvents tables.
    """

    def __init__(self, connection_string: str):
        try:
            import pyodbc  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(
                "pyodbc is required for SQL credential persistence."
            ) from exc

        self._conn_str = connection_string

    @staticmethod
    def _parse_datetime(value):
        if not value:
            return None

        if isinstance(value, datetime):
            parsed = value
        else:
            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )

        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)

        return parsed

    @staticmethod
    def _db_status(status: CredentialStatus) -> str:
        mapping = {
            CredentialStatus.ACTIVE: "ISSUED",
            CredentialStatus.SUSPENDED: "SUSPENDED",
            CredentialStatus.REVOKED: "REVOKED",
            CredentialStatus.EXPIRED: "EXPIRED",
        }

        if status not in mapping:
            raise ValueError(
                "UNKNOWN cannot be stored as a credential status."
            )

        return mapping[status]

    @staticmethod
    def _app_status(status: str) -> CredentialStatus:
        mapping = {
            "ISSUED": CredentialStatus.ACTIVE,
            "ACTIVE": CredentialStatus.ACTIVE,
            "SUSPENDED": CredentialStatus.SUSPENDED,
            "REVOKED": CredentialStatus.REVOKED,
            "EXPIRED": CredentialStatus.EXPIRED,
        }

        return mapping.get(str(status).upper(), CredentialStatus.UNKNOWN)

    def get_status(self, credential_id: str) -> CredentialStatus:
        import pyodbc

        query = """
            SELECT status
            FROM dbo.Credentials
            WHERE credential_reference = ?
        """

        with pyodbc.connect(self._conn_str) as conn:
            row = conn.cursor().execute(
                query, credential_id
            ).fetchone()

        if row is None:
            return CredentialStatus.UNKNOWN

        return self._app_status(row[0])

    def register_credential(
        self,
        credential: dict,
        issuer_id: str,
        actor_id: str = "certichain-system",
    ) -> None:
        import pyodbc

        credential_id = credential.get("id")
        if not credential_id:
            raise ValueError("Credential ID is missing.")

        subject = credential.get("credentialSubject") or {}
        credential_types = credential.get("type", [])

        if isinstance(credential_types, list):
            credential_type = (
                credential_types[-1]
                if credential_types
                else "AcademicCredential"
            )
        else:
            credential_type = str(credential_types)

        document_info = credential.get("credentialSchema") or {}
        document_reference = document_info.get("documentReference")

        issued_at = self._parse_datetime(
            credential.get("issuanceDate")
        )
        valid_from = self._parse_datetime(
            credential.get("validFrom")
        )
        expires_at = self._parse_datetime(
            credential.get("expirationDate")
        )

        with pyodbc.connect(self._conn_str) as conn:
            cursor = conn.cursor()

            issuer_row = cursor.execute(
                """
                SELECT issuer_id
                FROM dbo.Issuers
                WHERE engine_issuer_id = ?
                  AND status = 'ACTIVE'
                """,
                issuer_id,
            ).fetchone()

            if issuer_row is None:
                raise ValueError(
                    f"Active SQL issuer not found for '{issuer_id}'."
                )

            issuer_guid = issuer_row[0]

            existing = cursor.execute(
                """
                SELECT credential_id
                FROM dbo.Credentials
                WHERE credential_reference = ?
                """,
                credential_id,
            ).fetchone()

            if existing is not None:
                raise ValueError(
                    f"Credential '{credential_id}' is already registered."
                )

            cursor.execute(
                """
                INSERT INTO dbo.Credentials (
                    credential_reference,
                    issuer_id,
                    holder_reference,
                    credential_type,
                    credential_format,
                    document_reference,
                    issued_at,
                    valid_from,
                    expires_at,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ISSUED')
                """,
                credential_id,
                issuer_guid,
                subject.get("id", ""),
                credential_type,
                "W3C_VC_JSON",
                document_reference,
                issued_at,
                valid_from,
                expires_at,
            )

            credential_row = cursor.execute(
                """
                SELECT credential_id
                FROM dbo.Credentials
                WHERE credential_reference = ?
                """,
                credential_id,
            ).fetchone()

            if credential_row is None:
                raise RuntimeError(
                    "Credential insert could not be confirmed."
                )

            cursor.execute(
                """
                INSERT INTO dbo.CredentialEvents (
                    credential_id,
                    event_type,
                    previous_status,
                    new_status,
                    actor_id,
                    event_time,
                    details
                )
                VALUES (
                    ?, 'ISSUED', NULL, 'ISSUED',
                    ?, SYSUTCDATETIME(), ?
                )
                """,
                credential_row[0],
                actor_id,
                "Credential issued and registered by CertiChain.",
            )

            conn.commit()

    def set_status(
        self,
        credential_id: str,
        status: CredentialStatus,
        reason: Optional[str] = None,
    ) -> None:
        import pyodbc

        new_status = self._db_status(status)

        with pyodbc.connect(self._conn_str) as conn:
            cursor = conn.cursor()

            row = cursor.execute(
                """
                SELECT credential_id, status
                FROM dbo.Credentials
                WHERE credential_reference = ?
                """,
                credential_id,
            ).fetchone()

            if row is None:
                raise ValueError(
                    f"Credential '{credential_id}' does not exist."
                )

            db_id = row[0]
            previous_status = str(row[1]).upper()

            if previous_status == new_status:
                return

            if previous_status in ("REVOKED", "EXPIRED"):
                raise ValueError(
                    f"Cannot change credential from {previous_status}."
                )

            if new_status == "ISSUED":
                event_type = "REACTIVATED"
            else:
                event_type = new_status

            cursor.execute(
                """
                UPDATE dbo.Credentials
                SET status = ?,
                    updated_at = SYSUTCDATETIME()
                WHERE credential_id = ?
                """,
                new_status,
                db_id,
            )

            cursor.execute(
                """
                INSERT INTO dbo.CredentialEvents (
                    credential_id,
                    event_type,
                    previous_status,
                    new_status,
                    actor_id,
                    event_time,
                    details
                )
                VALUES (
                    ?, ?, ?, ?, ?,
                    SYSUTCDATETIME(), ?
                )
                """,
                db_id,
                event_type,
                previous_status,
                new_status,
                "certichain-system",
                reason or "Credential status updated.",
            )

            conn.commit()
