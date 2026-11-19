"""
Orchestration de l'émission à travers plusieurs services (Phases 4 et 6).

Il n'existe PAS de transaction distribuée entre Key Vault, Blob Storage et Azure SQL.
Concept §9 « Atomicity » : on utilise des étapes explicites, un ordre choisi et une
RÉCONCILIATION, au lieu de supposer que tout réussit ou échoue ensemble.

Ordre des étapes :
    0. (option) contrôle du PDF archivé : il doit exister et ne pas être déjà rattaché
    1. signature du credential (Key Vault) — rien n'est encore persisté
    2. ARCHIVE du credential signé dans Blob (conteneur WORM « credentials »)
    3. ENREGISTREMENT dans le registre SQL Ledger (credential + événement + lien PDF,
       en UNE transaction SQL)

Cas de panne :
    - échec en 1 ou 2  -> rien n'est enregistré : réponse « NOT_ISSUED » (HTTP 503) ;
    - échec en 3       -> le credential est archivé mais ABSENT du registre :
                          réponse « PENDING_RECONCILIATION » (HTTP 503), jamais « émis ».
                          Tant qu'il n'est pas dans le registre, la vérification répond
                          Invalid (« absent du registre »). La réconciliation
                          (POST /api/maintenance/reconcile) compare l'archive et le registre et
                          termine l'enregistrement manquant (idempotent).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .errors import CredentialEngineError
from .models import CredentialSubject
from .storage import CREDENTIALS_CONTAINER, DocumentStore, StorageError

FAULT_POINTS = ("blob", "sql")


class IssuanceError(CredentialEngineError):
    def __init__(self, message: str, state: str, http_status: int = 503,
                 credential_id: Optional[str] = None, code: str = "issuance_failed"):
        super().__init__(message)
        self.state = state
        self.http_status = http_status
        self.credential_id = credential_id
        self.code = code

    def to_dict(self) -> Dict[str, Any]:
        return {"error": str(self), "code": self.code, "state": self.state,
                "credential_id": self.credential_id}


class IssuanceService:
    def __init__(self, engine, store: Optional[DocumentStore] = None,
                 allow_fault_injection: bool = False) -> None:
        self.engine = engine
        self.ledger = engine.registry
        self.store = store
        self.allow_fault_injection = allow_fault_injection

    def _fault(self, simulate: Optional[str], point: str) -> None:
        if self.allow_fault_injection and simulate == point:
            raise RuntimeError(f"Panne simulée : {point}")

    def sync_signing_key(self) -> None:
        """
        Rotation de clé multi-instances : si le registre annonce une clé plus récente que
        celle de cette instance, on recharge la clé Key Vault avant de signer ; si c'est
        cette instance qui découvre la nouvelle version, elle met le registre à jour
        (ancienne clé RETIRED, nouvelle ACTIVE, événement ISSUER_KEY_ROTATED).
        """
        signer = self.engine.signer
        if not hasattr(signer, "refresh"):
            return
        issuer = self.ledger.get_issuer(self.engine.issuer_id)
        stale = issuer is not None and issuer.public_key_id != signer.key_id
        signer.refresh(force=stale)
        if issuer is not None and issuer.public_key_id != signer.key_id and hasattr(self.ledger, "ensure_issuer"):
            from .issuer_registry import Issuer
            self.ledger.ensure_issuer(Issuer(
                issuer_id=issuer.issuer_id, name=issuer.name, identifier=issuer.identifier,
                public_key_id=signer.key_id, public_jwk=signer.public_jwk()))

    def issue(self, subject: CredentialSubject, actor: str, *, credential_type: str = "AcademicCredential",
              valid_from: Optional[str] = None, expires_at: Optional[str] = None,
              document_id: Optional[str] = None, simulate: Optional[str] = None) -> Dict[str, Any]:
        # 0) PDF associé : référence + empreinte viennent du SERVEUR, pas du client
        doc_ref = doc_hash = None
        if document_id:
            doc = self.ledger.get_document(document_id)
            if doc is None:
                raise IssuanceError("Document inconnu.", state="NOT_ISSUED", http_status=404,
                                    code="document_not_found")
            if doc["status"] != "UPLOADED":
                raise IssuanceError("Ce document est déjà rattaché à un credential.",
                                    state="NOT_ISSUED", http_status=409, code="document_already_linked")
            doc_ref, doc_hash = doc["blob_reference"], doc["content_hash"]

        # 1) signature (Key Vault) — avec la version COURANTE de la clé (rotation)
        self.sync_signing_key()
        vc = self.engine.issue_credential(subject, credential_type=credential_type,
                                          valid_from=valid_from, expires_at=expires_at,
                                          document_reference=doc_ref, document_hash=doc_hash,
                                          record=False)
        token = self.engine.issue_jwt(vc)

        # 2) archive (Blob WORM)
        archive_ref = None
        if self.store is not None:
            try:
                self._fault(simulate, "blob")
                archive_ref = self.store.archive_credential(vc, token)
            except (StorageError, RuntimeError) as exc:
                raise IssuanceError(
                    f"Archivage impossible ({exc}) : le credential N'A PAS été émis.",
                    state="NOT_ISSUED", credential_id=vc["id"], code="archive_failed")

        # 3) registre (SQL Ledger, une transaction)
        try:
            self._fault(simulate, "sql")
            record = self.ledger.record_issuance(vc, actor=actor, document_id=document_id)
        except Exception as exc:
            state = "PENDING_RECONCILIATION" if archive_ref else "NOT_ISSUED"
            raise IssuanceError(
                f"Enregistrement dans le registre impossible ({type(exc).__name__}) : émission NON "
                + ("finalisée, credential archivé en attente de réconciliation." if archive_ref
                   else "réalisée."),
                state=state, credential_id=vc["id"], code="registry_failed")

        return {"credential": vc, "jwt": token, "record": record, "archive_reference": archive_ref,
                "state": "ISSUED"}

    def reconcile(self, actor: str) -> Dict[str, Any]:
        """Termine les émissions archivées mais absentes du registre (idempotent)."""
        if self.store is None:
            return {"checked": 0, "recovered": [], "errors": []}
        recovered: List[str] = []
        errors: List[Dict[str, str]] = []
        names = self.store.list_names(CREDENTIALS_CONTAINER)
        for name in names:
            cred_guid = name.rsplit(".", 1)[0]
            if self.ledger.get_record(cred_guid) is not None:
                continue
            try:
                saved = self.store.load_credential(cred_guid)
                vc = saved["credential"]
                ref = (vc.get("credentialSchema") or {}).get("documentReference") or ""
                doc_id = ref.split("/")[-1].rsplit(".", 1)[0] if ref.startswith("documents/") else None
                self.ledger.record_issuance(vc, actor=f"system:reconciliation ({actor})",
                                            document_id=doc_id)
                recovered.append(vc["id"])
            except Exception as exc:  # pragma: no cover - réseau
                errors.append({"blob": name, "error": type(exc).__name__})
        return {"checked": len(names), "recovered": recovered, "errors": errors}
