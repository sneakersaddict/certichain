
"""
CertiChain credential engine package.

Local mode:
    Software ECDSA signer + in-memory issuer registry + in-memory status store.

Azure mode:
    Azure Key Vault signer + SQL issuer registry + SQL credential status store.
"""

from __future__ import annotations

import os
from typing import Optional

from .models import CredentialSubject
from .engine import (
    CredentialEngine,
    VerificationResult,
    VerificationStatus,
)
from .signing import LocalECDSASigner, Signer
from .status_store import (
    CredentialStatus,
    InMemoryStatusStore,
    SqlLedgerStatusStore,
    StatusStore,
)
from .issuer_registry import (
    Issuer,
    IssuerRegistry,
    InMemoryIssuerRegistry,
    SqlIssuerRegistry,
)

__all__ = [
    "CredentialSubject",
    "CredentialEngine",
    "VerificationResult",
    "VerificationStatus",
    "Signer",
    "LocalECDSASigner",
    "Issuer",
    "IssuerRegistry",
    "InMemoryIssuerRegistry",
    "SqlIssuerRegistry",
    "CredentialStatus",
    "InMemoryStatusStore",
    "SqlLedgerStatusStore",
    "StatusStore",
    "build_engine_from_env",
    "build_local_engine",
]

DEFAULT_ISSUER_ID = "uir"
DEFAULT_ISSUER_NAME = "Université Internationale de Rabat"
DEFAULT_ISSUER_IDENTIFIER = "uir.ac.ma"


def build_local_engine(
    issuer_id: str = DEFAULT_ISSUER_ID,
    issuer_name: str = DEFAULT_ISSUER_NAME,
    issuer_identifier: str = DEFAULT_ISSUER_IDENTIFIER,
    key_path: Optional[str] = None,
) -> CredentialEngine:
    """Build a local engine without Azure dependencies."""

    if key_path and os.path.exists(key_path):
        signer = LocalECDSASigner.from_pem_file(key_path)
    else:
        signer = LocalECDSASigner.generate()

        if key_path:
            directory = os.path.dirname(key_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            signer.save_pem_file(key_path)

    registry = InMemoryIssuerRegistry()

    registry.register_from_signer(
        issuer_id=issuer_id,
        name=issuer_name,
        identifier=issuer_identifier,
        signer=signer,
    )

    return CredentialEngine(
        signer=signer,
        issuer_registry=registry,
        issuer_id=issuer_id,
        status_store=InMemoryStatusStore(),
    )


def build_engine_from_env() -> CredentialEngine:
    """Build the engine using the current environment configuration."""

    issuer_id = os.environ.get(
        "CERTICHAIN_ISSUER_ID",
        DEFAULT_ISSUER_ID,
    )

    issuer_name = os.environ.get(
        "CERTICHAIN_ISSUER_NAME",
        DEFAULT_ISSUER_NAME,
    )

    issuer_identifier = os.environ.get(
        "CERTICHAIN_ISSUER_IDENTIFIER",
        DEFAULT_ISSUER_IDENTIFIER,
    )

    vault_url = os.environ.get("CERTICHAIN_KEYVAULT_URL")
    sql_conn = os.environ.get("CERTICHAIN_SQL_CONN")

    # Local mode
    if not vault_url:
        key_path = os.environ.get(
            "CERTICHAIN_LOCAL_KEY_PATH",
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "keys",
                "local_issuer_key.pem",
            ),
        )

        return build_local_engine(
            issuer_id=issuer_id,
            issuer_name=issuer_name,
            issuer_identifier=issuer_identifier,
            key_path=key_path,
        )

    # Azure mode: signing key remains in Key Vault.
    from .keyvault_signer import AzureKeyVaultSigner

    key_name = os.environ.get(
        "CERTICHAIN_KEY_NAME",
        "certichain-issuer-key",
    )

    signer: Signer = AzureKeyVaultSigner(
        vault_url,
        key_name,
    )

    # Azure SQL mode
    if sql_conn:
        issuer_registry = SqlIssuerRegistry(sql_conn)
        status_store = SqlLedgerStatusStore(sql_conn)

    # Azure without SQL: temporary in-memory fallback
    else:
        issuer_registry = InMemoryIssuerRegistry()

        issuer_registry.register_from_signer(
            issuer_id=issuer_id,
            name=issuer_name,
            identifier=issuer_identifier,
            signer=signer,
        )

        status_store = InMemoryStatusStore()

    return CredentialEngine(
        signer=signer,
        issuer_registry=issuer_registry,
        issuer_id=issuer_id,
        status_store=status_store,
    )
