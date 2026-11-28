"""
Stockage sécurisé des documents (Phase 4) — Azure Blob Storage.

Deux conteneurs PRIVÉS (aucun accès anonyme) dans le compte de stockage de la Phase 1 :
    documents    PDF originaux (diplômes lisibles), WORM : rétention d'immutabilité
    credentials  archive des credentials signés (VC JSON + JWT), WORM aussi

Principes (concept §6, §8) :
- la Function App accède au stockage avec son IDENTITÉ MANAGÉE (rôle
  « Storage Blob Data Contributor ») : aucune clé de compte, aucun secret ;
- le navigateur n'accède jamais directement au conteneur : soit l'API renvoie le
  fichier après contrôle des droits, soit elle génère un lien SAS « user delegation »
  très court (lecture seule, 1 seul fichier, quelques minutes) ;
- validation du fichier : type PDF (signature « %PDF- »), taille maximale, nom nettoyé ;
- empreinte SHA-256 calculée côté serveur (on ne fait pas confiance au client) ;
  elle est inscrite dans le credential signé => lien vérifiable PDF <-> credential.
"""

from __future__ import annotations

import abc
import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .errors import CredentialEngineError

DOCUMENTS_CONTAINER = "documents"
CREDENTIALS_CONTAINER = "credentials"
MAX_DOCUMENT_BYTES = 5 * 1024 * 1024          # 5 Mo
ALLOWED_MEDIA_TYPES = {"application/pdf"}
SAS_MAX_MINUTES = 15


class StorageError(CredentialEngineError):
    def __init__(self, message: str, code: str = "storage_error", http_status: int = 400):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_filename(name: Optional[str]) -> str:
    base = (name or "document.pdf").replace("\\", "/").split("/")[-1]
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:100] or "document.pdf"
    return base if base.lower().endswith(".pdf") else base + ".pdf"


def validate_pdf(data: bytes, media_type: Optional[str] = "application/pdf") -> None:
    """Validation côté serveur (concept §8 « Input validation »)."""
    if not data:
        raise StorageError("Fichier vide.", code="empty_file")
    if len(data) > MAX_DOCUMENT_BYTES:
        raise StorageError(f"Fichier trop volumineux (max {MAX_DOCUMENT_BYTES // (1024 * 1024)} Mo).",
                           code="file_too_large", http_status=413)
    if (media_type or "application/pdf").split(";")[0].strip().lower() not in ALLOWED_MEDIA_TYPES:
        raise StorageError("Type de fichier refusé (PDF uniquement).", code="bad_media_type",
                           http_status=415)
    if not data.startswith(b"%PDF-"):
        raise StorageError("Le contenu n'est pas un PDF valide (signature %PDF- absente).",
                           code="not_a_pdf", http_status=415)


class DocumentStore(abc.ABC):
    """Interface du stockage de fichiers (Blob en production, mémoire en test)."""

    @abc.abstractmethod
    def put(self, container: str, name: str, data: bytes, content_type: str,
            metadata: Dict[str, str]) -> str:
        """Écrit un blob NOUVEAU (jamais d'écrasement). Retourne la référence « conteneur/nom »."""

    @abc.abstractmethod
    def get(self, container: str, name: str) -> Optional[bytes]:
        ...

    @abc.abstractmethod
    def list_names(self, container: str) -> List[str]:
        ...

    @abc.abstractmethod
    def read_link(self, container: str, name: str, minutes: int) -> str:
        """Lien de lecture temporaire (SAS user delegation en production)."""

    # ---- helpers communs ----
    def put_document(self, data: bytes, filename: Optional[str], media_type: str,
                     uploaded_by: str) -> Dict[str, Any]:
        validate_pdf(data, media_type)
        document_id = str(uuid.uuid4())
        content_hash = sha256_hex(data)
        name = f"{document_id}.pdf"
        ref = self.put(DOCUMENTS_CONTAINER, name, data, "application/pdf", {
            "document_id": document_id, "sha256": content_hash,
            "original_name": safe_filename(filename), "uploaded_by": uploaded_by or "",
        })
        return {"document_id": document_id, "blob_reference": ref, "content_hash": content_hash,
                "media_type": "application/pdf", "size_bytes": len(data),
                "original_name": safe_filename(filename)}

    def archive_credential(self, credential: Dict[str, Any], jwt: Optional[str]) -> str:
        cred_guid = credential["id"].split(":")[-1]
        body = json.dumps({"credential": credential, "jwt": jwt}, ensure_ascii=False).encode("utf-8")
        return self.put(CREDENTIALS_CONTAINER, f"{cred_guid}.json", body, "application/json",
                        {"credential_id": cred_guid})

    def load_credential(self, credential_id: str) -> Optional[Dict[str, Any]]:
        raw = self.get(CREDENTIALS_CONTAINER, f"{credential_id.split(':')[-1]}.json")
        return json.loads(raw) if raw else None


class InMemoryDocumentStore(DocumentStore):
    def __init__(self) -> None:
        self._blobs: Dict[str, Dict[str, Any]] = {}
        self.fail_next: Optional[str] = None     # simulation de panne (tests)

    def put(self, container, name, data, content_type, metadata) -> str:
        if self.fail_next == container:
            self.fail_next = None
            raise StorageError("Panne simulée du stockage Blob.", code="storage_unavailable",
                               http_status=503)
        key = f"{container}/{name}"
        if key in self._blobs:
            raise StorageError("Le blob existe déjà (WORM : pas d'écrasement).",
                               code="blob_exists", http_status=409)
        self._blobs[key] = {"data": data, "content_type": content_type, "metadata": dict(metadata)}
        return key

    def get(self, container, name) -> Optional[bytes]:
        b = self._blobs.get(f"{container}/{name}")
        return b["data"] if b else None

    def list_names(self, container) -> List[str]:
        p = container + "/"
        return [k[len(p):] for k in self._blobs if k.startswith(p)]

    def read_link(self, container, name, minutes) -> str:
        exp = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return f"memory://{container}/{name}?se={exp}&sp=r"


class BlobDocumentStore(DocumentStore):
    """Azure Blob Storage via identité managée (DefaultAzureCredential)."""

    def __init__(self, account_url: str, credential: Optional[object] = None) -> None:
        from azure.identity import DefaultAzureCredential
        from azure.storage.blob import BlobServiceClient

        self._account_url = account_url.rstrip("/")
        self._service = BlobServiceClient(self._account_url,
                                          credential=credential or DefaultAzureCredential())

    def put(self, container, name, data, content_type, metadata) -> str:
        from azure.core.exceptions import AzureError, ResourceExistsError
        from azure.storage.blob import ContentSettings

        try:
            self._service.get_blob_client(container, name).upload_blob(
                data, overwrite=False, metadata=metadata,
                content_settings=ContentSettings(content_type=content_type))
        except ResourceExistsError:
            raise StorageError("Le blob existe déjà (WORM : pas d'écrasement).",
                               code="blob_exists", http_status=409)
        except AzureError as exc:
            raise StorageError(f"Stockage Blob indisponible : {type(exc).__name__}",
                               code="storage_unavailable", http_status=503)
        return f"{container}/{name}"

    def get(self, container, name) -> Optional[bytes]:
        from azure.core.exceptions import ResourceNotFoundError
        try:
            return self._service.get_blob_client(container, name).download_blob().readall()
        except ResourceNotFoundError:
            return None

    def list_names(self, container) -> List[str]:
        return [b.name for b in self._service.get_container_client(container).list_blobs()]

    def read_link(self, container, name, minutes) -> str:
        """SAS « user delegation » : signé avec une clé dérivée d'Entra ID (pas de clé de compte)."""
        from azure.storage.blob import BlobSasPermissions, generate_blob_sas

        minutes = max(1, min(int(minutes), SAS_MAX_MINUTES))
        start = datetime.now(timezone.utc) - timedelta(minutes=2)
        expiry = datetime.now(timezone.utc) + timedelta(minutes=minutes)
        key = self._service.get_user_delegation_key(start, expiry)
        account = self._account_url.split("//")[1].split(".")[0]
        sas = generate_blob_sas(account_name=account, container_name=container, blob_name=name,
                                user_delegation_key=key, permission=BlobSasPermissions(read=True),
                                start=start, expiry=expiry, protocol="https")
        return f"{self._account_url}/{container}/{name}?{sas}"
