"""
Modèle de données du credential, aligné sur le modèle W3C Verifiable Credentials.

Un Verifiable Credential (VC) est une déclaration structurée et signée. On reprend
les champs du modèle W3C (@context, type, issuer, issuanceDate, credentialSubject,
credentialStatus, proof) pour rester interopérable.

Honnêteté sur la conformité (voir concept, §9) : utiliser des champs inspirés du
W3C ne rend pas automatiquement l'implémentation « conforme ». Notre preuve est
une signature ES256 (ECDSA P-256 + SHA-256) sur une canonicalisation JSON
déterministe, documentée et cohérente de bout en bout — pas une suite de preuve
W3C certifiée.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Contextes (références ; l'URL CertiChain est illustrative pour le projet)
W3C_VC_CONTEXT = "https://www.w3.org/2018/credentials/v1"
CERTICHAIN_CONTEXT = "https://certichain.uir.ac.ma/credentials/v1"

# Préfixes d'identifiants (schéma DID simplifié, propre au projet)
ISSUER_DID_PREFIX = "did:certichain:issuer:"
HOLDER_DID_PREFIX = "did:certichain:holder:"

# Type de preuve (nommage explicite et honnête)
PROOF_TYPE = "CertiChainEcdsaSecp256r1_ES256"
PROOF_PURPOSE = "assertionMethod"
# Format de preuve déclaré explicitement dans chaque credential (concept §9) :
# signature ES256 sur une canonicalisation JSON déterministe. Aligné W3C, mais ce
# n'est PAS une suite de preuve W3C normalisée (ex. ecdsa-rdfc-2019).
PROOF_FORMAT = "certichain-es256-canonical-json/v1"
STATUS_TYPE = "CertiChainCredentialStatus"


def utcnow_iso() -> str:
    """Horodatage ISO-8601 en UTC, suffixe Z (ex. 2026-11-14T19:30:00Z)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def issuer_did(issuer_id: str) -> str:
    return f"{ISSUER_DID_PREFIX}{issuer_id}"


def holder_did(holder_id: str) -> str:
    return f"{HOLDER_DID_PREFIX}{holder_id}"


def verification_method(issuer_id: str, public_key_id: str) -> str:
    """Référence la clé publique utilisée pour la preuve : <issuer_did>#<key_id>."""
    return f"{issuer_did(issuer_id)}#{public_key_id}"


def new_credential_id() -> str:
    """Identifiant unique de credential (URN UUID)."""
    return f"urn:uuid:{uuid.uuid4()}"


@dataclass
class CredentialSubject:
    """Le « sujet » du credential : l'étudiant et ce qui est attesté."""

    holder_id: str
    full_name: str
    credential_name: str          # ex. « Licence en Génie Informatique »
    credential_type_label: str    # ex. « Degree », « Certificate »
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        subject: Dict[str, Any] = {
            "id": holder_did(self.holder_id),
            "name": self.full_name,
            "achievement": {
                "type": self.credential_type_label,
                "name": self.credential_name,
            },
        }
        subject.update(self.extra)
        return subject


def build_unsigned_credential(
    *,
    issuer_id: str,
    subject: CredentialSubject,
    credential_type: str = "AcademicCredential",
    valid_from: Optional[str] = None,
    expires_at: Optional[str] = None,
    credential_id: Optional[str] = None,
    issued_at: Optional[str] = None,
    document_reference: Optional[str] = None,
    document_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Construit un credential NON signé (dictionnaire prêt à être haché puis signé).
    Le champ `proof` est ajouté ensuite par le moteur.
    """
    issued = issued_at or utcnow_iso()
    cred_id = credential_id or new_credential_id()

    credential: Dict[str, Any] = {
        "@context": [W3C_VC_CONTEXT, CERTICHAIN_CONTEXT],
        "id": cred_id,
        "type": ["VerifiableCredential", credential_type],
        "issuer": issuer_did(issuer_id),
        "issuanceDate": issued,
        "validFrom": valid_from or issued,
        "credentialSubject": subject.to_dict(),
        "credentialStatus": {
            "id": f"{cred_id}#status",
            "type": STATUS_TYPE,
            "statusPurpose": "revocation",
        },
    }
    if expires_at:
        credential["expirationDate"] = expires_at

    # Référence au document archivé (ex. PDF dans Blob Storage) + son empreinte.
    # On ne met PAS le PDF lui-même dans le credential (minimisation des données).
    if document_reference or document_hash:
        credential["credentialSchema"] = {
            "documentReference": document_reference,
            "documentHash": document_hash,
            "hashAlg": "SHA-256",
        }

    return credential


REQUIRED_TOP_LEVEL_FIELDS: List[str] = [
    "@context",
    "id",
    "type",
    "issuer",
    "issuanceDate",
    "credentialSubject",
]
