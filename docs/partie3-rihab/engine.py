
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from . import models
from .hashing import credential_digest
from .issuer_registry import IssuerRegistry
from .signing import Signer, b64url_encode, b64url_decode, verify_digest
from .status_store import CredentialStatus, StatusStore, InMemoryStatusStore


class VerificationStatus(str, Enum):
    VALID = "Valid"
    INVALID = "Invalid"
    REVOKED = "Revoked"
    SUSPENDED = "Suspended"
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
    if not isinstance(ts, str):
        return None

    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
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

    def issue_credential(
        self,
        subject: models.CredentialSubject,
        credential_type: str = "AcademicCredential",
        valid_from: Optional[str] = None,
        expires_at: Optional[str] = None,
        document_reference: Optional[str] = None,
        document_hash: Optional[str] = None,
    ) -> Dict[str, Any]:

        credential = models.build_unsigned_credential(
            issuer_id=self.issuer_id,
            subject=subject,
            credential_type=credential_type,
            valid_from=valid_from,
            expires_at=expires_at,
            document_reference=document_reference,
            document_hash=document_hash,
        )

        digest = credential_digest(credential)
        raw_sig = self.signer.sign_digest(digest)

        credential["proof"] = {
            "type": models.PROOF_TYPE,
            "created": models.utcnow_iso(),
            "verificationMethod": models.verification_method(
                self.issuer_id,
                self.signer.key_id,
            ),
            "proofPurpose": models.PROOF_PURPOSE,
            "proofValue": b64url_encode(raw_sig),
            "hashAlg": "SHA-256",
            "signatureAlg": "ES256",
        }

        # Persist credential metadata and its initial event.
        self.status_store.register_credential(
            credential=credential,
            issuer_id=self.issuer_id,
        )

        return credential

    def verify_credential(
        self,
        credential: Dict[str, Any],
    ) -> VerificationResult:

        checks: Dict[str, Any] = {}

        if not isinstance(credential, dict):
            return VerificationResult(
                VerificationStatus.INVALID,
                "Credential must be a JSON object.",
                checks={"structure": False},
            )

        missing = [
            field for field in models.REQUIRED_TOP_LEVEL_FIELDS
            if field not in credential
        ]

        proof = credential.get("proof")

        if missing or not isinstance(proof, dict):
            return VerificationResult(
                VerificationStatus.INVALID,
                f"Invalid structure. Missing fields: {missing or ['proof']}",
                checks={"structure": False},
            )

        checks["structure"] = True

        # Validate proof profile.
        expected_proof_fields = {
            "type": models.PROOF_TYPE,
            "proofPurpose": models.PROOF_PURPOSE,
            "hashAlg": "SHA-256",
            "signatureAlg": "ES256",
        }

        for field_name, expected in expected_proof_fields.items():
            if proof.get(field_name) != expected:
                return VerificationResult(
                    VerificationStatus.INVALID,
                    f"Unsupported or invalid proof field: {field_name}.",
                    credential_id=credential.get("id"),
                    checks={**checks, "proof_metadata": False},
                )

        checks["proof_metadata"] = True

        cred_id = credential.get("id")
        vm = proof.get("verificationMethod", "")

        # Resolve issuer and public key.
        resolved = self.registry.resolve_verification_method(vm)

        if resolved is None:
            return VerificationResult(
                VerificationStatus.ISSUER_NOT_TRUSTED,
                "Unknown issuer or unrecognized verification key.",
                credential_id=cred_id,
                checks={**checks, "issuer_known": False},
            )

        issuer, public_key = resolved
        checks["issuer_known"] = True

        if not issuer.is_trusted():
            return VerificationResult(
                VerificationStatus.ISSUER_NOT_TRUSTED,
                "The issuer is suspended or unauthorized.",
                issuer_id=issuer.issuer_id,
                credential_id=cred_id,
                checks={**checks, "issuer_trusted": False},
            )

        checks["issuer_trusted"] = True

        # Verify cryptographic proof.
        try:
            digest = credential_digest(credential)
            raw_sig = b64url_decode(proof.get("proofValue", ""))
            signature_ok = verify_digest(public_key, digest, raw_sig)
        except Exception:
            signature_ok = False

        checks["signature"] = signature_ok

        if not signature_ok:
            return VerificationResult(
                VerificationStatus.INVALID,
                "Cryptographic signature is invalid.",
                issuer_id=issuer.issuer_id,
                credential_id=cred_id,
                checks=checks,
            )

        # Validate expiration field if present.
        expiration = credential.get("expirationDate")

        if expiration:
            expiration_dt = _parse_iso(expiration)

            if expiration_dt is None:
                return VerificationResult(
                    VerificationStatus.INVALID,
                    "Invalid expiration date format.",
                    issuer_id=issuer.issuer_id,
                    credential_id=cred_id,
                    checks={**checks, "expiration_format": False},
                )

            if expiration_dt < datetime.now(timezone.utc):
                return VerificationResult(
                    VerificationStatus.EXPIRED,
                    f"Credential expired on {expiration}.",
                    issuer_id=issuer.issuer_id,
                    credential_id=cred_id,
                    checks={**checks, "not_expired": False},
                )

        checks["not_expired"] = True

        # Retrieve persistent lifecycle status.
        status = self.status_store.get_status(cred_id)
        checks["status"] = status.value

        if status == CredentialStatus.UNKNOWN:
            return VerificationResult(
                VerificationStatus.INVALID,
                "Credential is not registered in the trusted database.",
                issuer_id=issuer.issuer_id,
                credential_id=cred_id,
                checks=checks,
            )

        if status == CredentialStatus.REVOKED:
            return VerificationResult(
                VerificationStatus.REVOKED,
                "Credential has been revoked.",
                issuer_id=issuer.issuer_id,
                credential_id=cred_id,
                checks=checks,
            )

        if status == CredentialStatus.SUSPENDED:
            return VerificationResult(
                VerificationStatus.SUSPENDED,
                "Credential is temporarily suspended.",
                issuer_id=issuer.issuer_id,
                credential_id=cred_id,
                checks=checks,
            )

        if status == CredentialStatus.EXPIRED:
            return VerificationResult(
                VerificationStatus.EXPIRED,
                "Credential has expired.",
                issuer_id=issuer.issuer_id,
                credential_id=cred_id,
                checks=checks,
            )

        return VerificationResult(
            VerificationStatus.VALID,
            "Signature valid, issuer trusted, credential active.",
            issuer_id=issuer.issuer_id,
            credential_id=cred_id,
            checks=checks,
        )

    def revoke_credential(
        self,
        credential_id: str,
        reason: str,
    ) -> None:
        self.status_store.set_status(
            credential_id,
            CredentialStatus.REVOKED,
            reason,
        )

    def suspend_credential(
        self,
        credential_id: str,
        reason: str,
    ) -> None:
        self.status_store.set_status(
            credential_id,
            CredentialStatus.SUSPENDED,
            reason,
        )

    def activate_credential(
        self,
        credential_id: str,
        reason: str,
    ) -> None:
        self.status_store.set_status(
            credential_id,
            CredentialStatus.ACTIVE,
            reason,
        )

    def get_issuer_info(
        self,
        issuer_id: str,
    ) -> Optional[Dict[str, Any]]:
        issuer = self.registry.get_issuer(issuer_id)
        return issuer.public_info() if issuer else None
