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

import hashlib
import json
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


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


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
        record: bool = True,
    ) -> Dict[str, Any]:
        """Construit et signe un credential. Retourne le VC complet (avec `proof`).

        record=False : le credential est seulement signé ; l'enregistrement (registre +
        archive) est orchestré par IssuanceService (gestion des pannes partielles, Phase 6).
        """
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
            "proofFormat": models.PROOF_FORMAT,
            "proofValue": b64url_encode(raw_sig),
            "hashAlg": "SHA-256",
            "signatureAlg": "ES256",
        }

        # 4) statut initial : actif. Avec le registre Phase 3 (TrustLedger), le
        #    credential est en plus enregistré + événement ISSUED dans le ledger.
        if not record:
            return credential
        if hasattr(self.status_store, "record_issuance"):
            self.status_store.record_issuance(credential)
        else:
            self.status_store.set_status(credential["id"], CredentialStatus.ACTIVE)
        return credential

    # ----------------------------------------------------------------- VERIFY
    # ------------------------------------------------- FORMAT STANDARD (VC-JOSE)
    def issue_jwt(self, credential: Dict[str, Any]) -> str:
        """
        Encode le MÊME credential au format standard « vc+jwt » (W3C VC-JOSE-COSE) :
        JWS compact, algorithme ES256, signé par Key Vault (clé non exportable).
        Le payload est le credential sans son bloc `proof` (la preuve est le JWS).
        """
        payload = {k: v for k, v in credential.items() if k != "proof"}
        header = {"alg": "ES256", "typ": "vc+jwt", "cty": "vc",
                  "kid": models.verification_method(self.issuer_id, self.signer.key_id)}
        signing_input = (b64url_encode(_json_bytes(header)) + "." + b64url_encode(_json_bytes(payload)))
        digest = hashlib.sha256(signing_input.encode("ascii")).digest()
        return signing_input + "." + b64url_encode(self.signer.sign_digest(digest))

    def verify_jwt(self, token: str) -> VerificationResult:
        """Vérifie un credential au format « vc+jwt » (mêmes contrôles que le format JSON)."""
        try:
            h64, p64, s64 = token.strip().split(".")
            header = json.loads(b64url_decode(h64))
            credential = json.loads(b64url_decode(p64))
            raw_sig = b64url_decode(s64)
        except Exception:
            return VerificationResult(VerificationStatus.INVALID, "JWS mal formé.",
                                      checks={"structure": False, "format": "vc+jwt"})
        if header.get("alg") != "ES256":
            return VerificationResult(VerificationStatus.INVALID,
                                      "Algorithme non accepté (ES256 attendu).",
                                      checks={"structure": False, "format": "vc+jwt"})
        digest = hashlib.sha256(f"{h64}.{p64}".encode("ascii")).digest()
        return self._verify(credential, header.get("kid", ""),
                            lambda pk: verify_digest(pk, digest, raw_sig), fmt="vc+jwt")

    def verify_credential(self, credential: Dict[str, Any]) -> VerificationResult:
        """Vérifie un credential (format JSON avec bloc `proof`)."""
        if "proof" not in credential:
            return VerificationResult(VerificationStatus.INVALID,
                                      "Structure invalide, champs manquants : ['proof']",
                                      checks={"structure": False})
        proof = credential["proof"]

        def check(public_key) -> bool:
            digest = credential_digest(credential)  # recalcule sans `proof`
            return verify_digest(public_key, digest, b64url_decode(proof.get("proofValue", "")))

        return self._verify(credential, proof.get("verificationMethod", ""), check, fmt="json-proof")

    def _verify(self, credential: Dict[str, Any], vm: str, signature_check,
                fmt: str) -> VerificationResult:
        """Contrôles communs (concept §7.3, §14) : structure, émetteur, signature, expiration, statut."""
        checks: Dict[str, Any] = {"format": fmt}

        # (a) structure
        missing = [f for f in models.REQUIRED_TOP_LEVEL_FIELDS if f not in credential]
        if missing:
            return VerificationResult(
                VerificationStatus.INVALID,
                f"Structure invalide, champs manquants : {missing}",
                checks={**checks, "structure": False},
            )
        checks["structure"] = True
        cred_id = credential.get("id")

        # (b) confiance de l'émetteur + résolution de la clé publique
        resolved = self.registry.resolve_verification_method(
            vm, issued_at=credential.get("issuanceDate"))
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
            sig_ok = bool(signature_check(public_key))
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

        # (e) le credential doit exister dans le registre : une signature valide d'un
        #     credential dont l'émission n'a pas été finalisée (panne partielle) ne suffit pas.
        if hasattr(self.status_store, "get_record") and self.status_store.get_record(cred_id) is None:
            checks["registered"] = False
            return VerificationResult(
                VerificationStatus.INVALID,
                "Credential absent du registre de l'émetteur (émission non finalisée ou inconnue).",
                issuer_id=issuer.issuer_id,
                credential_id=cred_id,
                checks=checks,
            )
        checks["registered"] = True

        # (f) statut de révocation
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
        if status == CredentialStatus.EXPIRED:
            return VerificationResult(
                VerificationStatus.EXPIRED,
                "Le registre indique que ce credential est expiré.",
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
        if hasattr(self.status_store, "change_status"):
            self.status_store.change_status(credential_id, CredentialStatus.REVOKED, reason)
        else:
            self.status_store.set_status(credential_id, CredentialStatus.REVOKED, reason)

    # ------------------------------------------------------------- ISSUER INFO
    def get_issuer_info(self, issuer_id: str) -> Optional[Dict[str, Any]]:
        """Infos publiques d'un émetteur (GET /api/issuers/{id}). Jamais de clé privée."""
        issuer = self.registry.get_issuer(issuer_id)
        return issuer.public_info() if issuer else None
