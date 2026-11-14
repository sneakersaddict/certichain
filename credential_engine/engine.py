"""
Moteur de credentials CertiChain — Phase 2.

Responsabilités (concept, §7, §11, §12) :
- issue_credential  : construit un credential structuré, calcule son empreinte
                      SHA-256, demande la signature (Key Vault ou local) et attache
                      la preuve.  -> POST /api/credentials
- verify_credential : vérifie la preuve avec la clé PUBLIQUE de l'émetteur, contrôle
                      la confiance de l'émetteur, l'expiration et le statut de
                      révocation, puis renvoie un résultat clair.
                      -> POST /api/credentials/verify
- get_issuer_info   : expose les infos publiques d'un émetteur (clé publique,
                      confiance).  -> GET /api/issuers/{id}

Le moteur ne stocke rien lui-même : il reçoit un Signer, un IssuerRegistry et un
StatusStore (injection de dépendances). Cela le rend testable sans Azure et
branchable sur Azure en production.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from . import models
from .errors import CredentialStructureError
from .hashing import credential_digest
from .issuer_registry import IssuerRegistry
from .signing import Signer, b64url_encode, b64url_decode, verify_digest
from .status_store import CredentialStatus, InMemoryStatusStore, StatusStore


class VerificationStatus(str, Enum):
    VALID = "Valid"
    INVALID = "Invalid"
    REVOKED = "Revoked"
    EXPIRED = "Expired"
    ISSUER_NOT_TRUSTED = "Issuer Not Trusted"


@dataclass
class VerificationResult:
    status: VerificationStatus
    reason: str
    issuer_id: Optional[str] = None
    credential_id: Optional[str] = None
    checks: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        return self.status == VerificationStatus.VALID

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result": self.status.value,
            "valid": self.is_valid,
            "reason": self.reason,
            "issuer_id": self.issuer_id,
            "credential_id": self.credential_id,
            "checks": self.checks,
        }


def _parse_iso(ts: str) -> Optional[datetime]:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


class CredentialEngine:
    def __init__(
        self,
        signer: Signer,
        issuer_registry: IssuerRegistry,
        issuer_id: str,
        status_store: Optional[StatusStore] = None,
    ):
        self.signer = signer
        self.registry = issuer_registry
        self.issuer_id = issuer_id
        self.status_store = status_store or InMemoryStatusStore()

    # ------------------------------------------------------------------ ISSUE
    def issue_credential(
        self,
        subject: models.CredentialSubject,
        credential_type: str = "AcademicCredential",
        valid_from: Optional[str] = None,
        expires_at: Optional[str] = None,
        document_reference: Optional[str] = None,
        document_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Construit et signe un credential. Retourne le VC complet (avec `proof`)."""
        credential = models.build_unsigned_credential(
            issuer_id=self.issuer_id,
            subject=subject,
            credential_type=credential_type,
            valid_from=valid_from,
            expires_at=expires_at,
            document_reference=document_reference,
            document_hash=document_hash,
        )

        # 1) empreinte SHA-256 de la forme canonique (sans proof)
        digest = credential_digest(credential)
        # 2) signature de l'empreinte (local ou Key Vault)
        raw_sig = self.signer.sign_digest(digest)
        # 3) attache la preuve
        credential["proof"] = {
            "type": models.PROOF_TYPE,
            "created": models.utcnow_iso(),
            "verificationMethod": models.verification_method(
                self.issuer_id, self.signer.key_id
            ),
            "proofPurpose": models.PROOF_PURPOSE,
            "proofValue": b64url_encode(raw_sig),
            "hashAlg": "SHA-256",
            "signatureAlg": "ES256",
        }

        # 4) statut initial : actif
        self.status_store.set_status(credential["id"], CredentialStatus.ACTIVE)
        return credential

    # ----------------------------------------------------------------- VERIFY
    def verify_credential(self, credential: Dict[str, Any]) -> VerificationResult:
        """Vérifie un credential et renvoie un résultat clair (concept §7.3, §14)."""
        checks: Dict[str, Any] = {}

        # (a) structure
        missing = [f for f in models.REQUIRED_TOP_LEVEL_FIELDS if f not in credential]
        if missing or "proof" not in credential:
            return VerificationResult(
                VerificationStatus.INVALID,
                f"Structure invalide, champs manquants : {missing or ['proof']}",
                checks={"structure": False},
            )
        checks["structure"] = True

        proof = credential["proof"]
        cred_id = credential.get("id")
        vm = proof.get("verificationMethod", "")

        # (b) confiance de l'émetteur + résolution de la clé publique
        resolved = self.registry.resolve_verification_method(vm)
        if resolved is None:
            return VerificationResult(
                VerificationStatus.ISSUER_NOT_TRUSTED,
                "Émetteur inconnu ou clé non rattachée à un émetteur reconnu.",
                credential_id=cred_id,
                checks={**checks, "issuer_known": False},
            )
        issuer, public_key = resolved
        checks["issuer_known"] = True
        if not issuer.is_trusted():
            return VerificationResult(
                VerificationStatus.ISSUER_NOT_TRUSTED,
                f"Émetteur « {issuer.name} » suspendu / non autorisé.",
                issuer_id=issuer.issuer_id,
                credential_id=cred_id,
                checks={**checks, "issuer_trusted": False},
            )
        checks["issuer_trusted"] = True

        # (c) vérification cryptographique de la preuve (clé publique uniquement)
        try:
            digest = credential_digest(credential)  # recalcule sans `proof`
            raw_sig = b64url_decode(proof.get("proofValue", ""))
            sig_ok = verify_digest(public_key, digest, raw_sig)
        except Exception:
            sig_ok = False
        checks["signature"] = sig_ok
        if not sig_ok:
            # Signature invalide => credential altéré ou mauvaise clé.
            return VerificationResult(
                VerificationStatus.INVALID,
                "La preuve cryptographique est invalide (credential altéré "
                "ou signature non conforme).",
                issuer_id=issuer.issuer_id,
                credential_id=cred_id,
                checks=checks,
            )

        # (d) expiration
        exp = credential.get("expirationDate")
        if exp:
            exp_dt = _parse_iso(exp)
            if exp_dt and exp_dt < datetime.now(timezone.utc):
                checks["not_expired"] = False
                return VerificationResult(
                    VerificationStatus.EXPIRED,
                    f"Credential expiré le {exp}.",
                    issuer_id=issuer.issuer_id,
                    credential_id=cred_id,
                    checks=checks,
                )
            checks["not_expired"] = True

        # (e) statut de révocation
        status = self.status_store.get_status(cred_id)
        checks["status"] = status.value
        if status == CredentialStatus.REVOKED:
            return VerificationResult(
                VerificationStatus.REVOKED,
                "La preuve est mathématiquement valide, mais le credential a été révoqué.",
                issuer_id=issuer.issuer_id,
                credential_id=cred_id,
                checks=checks,
            )
        if status == CredentialStatus.SUSPENDED:
            return VerificationResult(
                VerificationStatus.REVOKED,
                "Credential suspendu.",
                issuer_id=issuer.issuer_id,
                credential_id=cred_id,
                checks=checks,
            )

        # (f) tout est bon
        return VerificationResult(
            VerificationStatus.VALID,
            "Signature valide, émetteur reconnu, credential actif.",
            issuer_id=issuer.issuer_id,
            credential_id=cred_id,
            checks=checks,
        )

    # --------------------------------------------------------------- REVOKE
    def revoke_credential(self, credential_id: str, reason: str) -> None:
        """
        Marque un credential comme révoqué (commodité Phase 2).
        En Phase 3 : contrôle d'autorisation + événement dans le ledger SQL.
        """
        self.status_store.set_status(credential_id, CredentialStatus.REVOKED, reason)

    # ------------------------------------------------------------- ISSUER INFO
    def get_issuer_info(self, issuer_id: str) -> Optional[Dict[str, Any]]:
        """Infos publiques d'un émetteur (GET /api/issuers/{id}). Jamais de clé privée."""
        issuer = self.registry.get_issuer(issuer_id)
        return issuer.public_info() if issuer else None
