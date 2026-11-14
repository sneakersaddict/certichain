"""
CertiChain — Moteur de credentials (Phase 2).

Expose l'API publique du package et une fabrique `build_engine_from_env()` qui
construit automatiquement le moteur :
- en LOCAL (tests/démo)  : signataire logiciel ECDSA P-256 + registre en mémoire ;
- sur AZURE (production)  : Azure Key Vault (clé non exportable) + registre SQL si
  configuré, sinon registre en mémoire amorcé avec la clé publique de Key Vault.

Variables d'environnement reconnues :
    CERTICHAIN_KEYVAULT_URL      ex. https://kv-certichain-ct26.vault.azure.net/
    CERTICHAIN_KEY_NAME          ex. certichain-issuer-key
    CERTICHAIN_ISSUER_ID         ex. uir
    CERTICHAIN_ISSUER_NAME       ex. Université Internationale de Rabat
    CERTICHAIN_ISSUER_IDENTIFIER ex. uir.ac.ma
    CERTICHAIN_SQL_CONN          chaîne de connexion ODBC (optionnelle)
    CERTICHAIN_LOCAL_KEY_PATH    chemin de la clé locale (défaut: keys/local_issuer_key.pem)
"""

from __future__ import annotations

import os
from typing import Optional

from .models import CredentialSubject
from .engine import CredentialEngine, VerificationResult, VerificationStatus
from .signing import LocalECDSASigner, Signer
from .issuer_registry import (
    Issuer,
    IssuerRegistry,
    InMemoryIssuerRegistry,
    SqlIssuerRegistry,
)
from .status_store import CredentialStatus, InMemoryStatusStore, StatusStore

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
    """Moteur 100% local (aucune dépendance Azure). Clé persistée si key_path fourni."""
    if key_path and os.path.exists(key_path):
        signer = LocalECDSASigner.from_pem_file(key_path)
    else:
        signer = LocalECDSASigner.generate()
        if key_path:
            os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
            signer.save_pem_file(key_path)

    registry = InMemoryIssuerRegistry()
    registry.register_from_signer(issuer_id, issuer_name, issuer_identifier, signer)
    return CredentialEngine(signer, registry, issuer_id, InMemoryStatusStore())


def build_engine_from_env() -> CredentialEngine:
    """Construit le moteur selon l'environnement (local vs Azure)."""
    issuer_id = os.environ.get("CERTICHAIN_ISSUER_ID", DEFAULT_ISSUER_ID)
    issuer_name = os.environ.get("CERTICHAIN_ISSUER_NAME", DEFAULT_ISSUER_NAME)
    issuer_identifier = os.environ.get(
        "CERTICHAIN_ISSUER_IDENTIFIER", DEFAULT_ISSUER_IDENTIFIER
    )
    vault_url = os.environ.get("CERTICHAIN_KEYVAULT_URL")
    sql_conn = os.environ.get("CERTICHAIN_SQL_CONN")

    if not vault_url:
        key_path = os.environ.get(
            "CERTICHAIN_LOCAL_KEY_PATH",
            os.path.join(os.path.dirname(__file__), "..", "keys", "local_issuer_key.pem"),
        )
        return build_local_engine(issuer_id, issuer_name, issuer_identifier, key_path)

    # --- Mode Azure ---
    from .keyvault_signer import AzureKeyVaultSigner

    key_name = os.environ.get("CERTICHAIN_KEY_NAME", "certichain-issuer-key")
    signer: Signer = AzureKeyVaultSigner(vault_url, key_name)

    if sql_conn:
        registry: IssuerRegistry = SqlIssuerRegistry(sql_conn)
    else:
        mem = InMemoryIssuerRegistry()
        mem.register_from_signer(issuer_id, issuer_name, issuer_identifier, signer)
        registry = mem

    return CredentialEngine(signer, registry, issuer_id, InMemoryStatusStore())
