"""
Registre de confiance & cycle de vie des credentials (Phase 3).

Ce module ajoute au moteur de la Phase 2 :
- un REGISTRE DES ÉMETTEURS gérable (inscription, suspension, réactivation) ;
- un REGISTRE DES CREDENTIALS émis (enregistrement à l'émission, sans données
  personnelles en clair : empreinte SHA-256 + métadonnées minimales) ;
- des TRANSITIONS DE STATUT contrôlées (active -> suspended -> active,
  active/suspended -> revoked ; une révocation est définitive) ;
- un JOURNAL D'ÉVÉNEMENTS (émission, suspension, réactivation, révocation, et
  changements de statut des émetteurs) qui, sur Azure, est stocké dans des tables
  Azure SQL Ledger (historique infalsifiable).

Deux implémentations respectent la même interface `TrustLedger` :
- InMemoryTrustLedger : tests unitaires / démo locale ;
- SqlTrustLedger (sql_ledger.py) : Azure SQL Database avec tables Ledger.

`TrustLedger` est À LA FOIS un IssuerRegistry et un StatusStore : le moteur de la
Phase 2 l'utilise donc directement, sans changer sa logique de vérification.
"""

from __future__ import annotations

import abc
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .errors import CredentialEngineError
from .hashing import credential_digest
from .issuer_registry import SUSPENDED, TRUSTED, Issuer, IssuerRegistry
from .status_store import CredentialStatus, StatusStore

# --- Types d'événements journalisés -------------------------------------------
EVT_ISSUED = "ISSUED"
EVT_SUSPENDED = "SUSPENDED"
EVT_REACTIVATED = "REACTIVATED"
EVT_REVOKED = "REVOKED"
EVT_ISSUER_REGISTERED = "ISSUER_REGISTERED"
EVT_ISSUER_SUSPENDED = "ISSUER_SUSPENDED"
EVT_ISSUER_REACTIVATED = "ISSUER_REACTIVATED"

ISSUER_STATUSES = (TRUSTED, SUSPENDED)

# --- Machine à états des credentials ------------------------------------------
# Clé = statut actuel, valeur = statuts autorisés ensuite. "revoked" est terminal.
ALLOWED_TRANSITIONS: Dict[CredentialStatus, set] = {
    CredentialStatus.ACTIVE: {CredentialStatus.SUSPENDED, CredentialStatus.REVOKED},
    CredentialStatus.SUSPENDED: {CredentialStatus.ACTIVE, CredentialStatus.REVOKED},
    CredentialStatus.REVOKED: set(),
    CredentialStatus.EXPIRED: set(),
}

_EVENT_FOR_TARGET = {
    CredentialStatus.SUSPENDED: EVT_SUSPENDED,
    CredentialStatus.ACTIVE: EVT_REACTIVATED,
    CredentialStatus.REVOKED: EVT_REVOKED,
}


class LifecycleError(CredentialEngineError):
    """Opération de cycle de vie refusée (transition interdite, objet inconnu...)."""

    def __init__(self, message: str, code: str = "lifecycle_error", http_status: int = 409):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


class NotFoundError(LifecycleError):
    def __init__(self, message: str):
        super().__init__(message, code="not_found", http_status=404)


class AuthorizationError(LifecycleError):
    """Action refusée faute de droits (journalisée comme événement de sécurité)."""

    def __init__(self, message: str, code: str = "forbidden"):
        super().__init__(message, code=code, http_status=403)


# --- Autorisations (concept §7.1, §7.4, §8 « least privilege ») -------------------
# Rôles = table dbo.Roles de la Phase 3 (ADMINISTRATOR, UNIVERSITY_STAFF, STUDENT, RECRUITER)
ROLE_ADMIN = "ADMINISTRATOR"
ROLE_STAFF = "UNIVERSITY_STAFF"
ACTION_ROLES: Dict[str, set] = {
    "issue": {ROLE_ADMIN, ROLE_STAFF},          # émettre un credential
    "suspend": {ROLE_ADMIN, ROLE_STAFF},        # suspendre / réactiver
    "revoke": {ROLE_ADMIN},                     # révoquer (définitif) : administrateur seulement
    "manage_issuer": {ROLE_ADMIN},              # inscrire / suspendre un émetteur
    "upload_document": {ROLE_ADMIN, ROLE_STAFF},  # archiver un PDF (Phase 4)
    "read_document": {ROLE_ADMIN, ROLE_STAFF, "STUDENT"},  # + contrôle « propriétaire » (Phase 5)
    "view_wallet": {ROLE_ADMIN, ROLE_STAFF, "STUDENT"},
    "share": {ROLE_ADMIN, ROLE_STAFF, "STUDENT"},          # + contrôle « propriétaire »
    "reconcile": {ROLE_ADMIN},                  # réconciliation après panne partielle (Phase 6)
}


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_status(value: str) -> CredentialStatus:
    try:
        return CredentialStatus(str(value).lower())
    except ValueError:
        raise LifecycleError(
            f"Statut inconnu « {value} » (attendu : active, suspended, revoked).",
            code="bad_status",
            http_status=400,
        )


def check_transition(current: CredentialStatus, target: CredentialStatus) -> None:
    """Lève LifecycleError si la transition current -> target est interdite."""
    if target == current:
        raise LifecycleError(
            f"Le credential est déjà « {current.value} ».", code="no_change"
        )
    if target not in ALLOWED_TRANSITIONS[current]:
        if current == CredentialStatus.REVOKED:
            msg = "Un credential révoqué ne peut plus changer de statut (révocation définitive)."
        elif current == CredentialStatus.EXPIRED:
            msg = "Un credential expiré ne peut plus changer de statut."
        else:
            msg = f"Transition interdite : {current.value} -> {target.value}."
        raise LifecycleError(msg, code="forbidden_transition")


def normalize_credential_id(value: str) -> str:
    """Accepte « urn:uuid:<uuid> » ou seulement « <uuid> » (pratique dans une URL)."""
    value = (value or "").strip()
    return value if value.startswith("urn:") else f"urn:uuid:{value}"


def build_credential_record(credential: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fiche minimale enregistrée dans le registre à l'émission.
    Minimisation des données : pas de nom de l'étudiant, seulement son identifiant
    (DID) et l'EMPREINTE SHA-256 du credential signé.
    """
    subject = credential.get("credentialSubject", {}) or {}
    types = credential.get("type", [])
    issuer_did = credential.get("issuer", "")
    return {
        "credential_id": credential["id"],
        "issuer_id": issuer_did.split(":")[-1] if issuer_did else "",
        "holder_id": subject.get("id", ""),
        "credential_type": (subject.get("achievement") or {}).get("type")
        or (types[-1] if types else ""),
        "credential_hash": credential_digest(credential).hex(),
        "document_reference": (credential.get("credentialSchema") or {}).get("documentReference"),
        "status": CredentialStatus.ACTIVE.value,
        "issued_at": credential.get("issuanceDate"),
        "expires_at": credential.get("expirationDate"),
    }


class TrustLedger(IssuerRegistry, StatusStore):
    """Interface commune du registre de confiance + cycle de vie."""

    # ---------------- émetteurs ----------------
    @abc.abstractmethod
    def register_issuer(self, issuer: Issuer, actor: str = "system") -> Issuer:
        ...

    @abc.abstractmethod
    def list_issuers(self) -> List[Issuer]:
        ...

    @abc.abstractmethod
    def _save_issuer_status(self, issuer_id: str, status: str) -> None:
        ...

    def set_issuer_status(self, issuer_id: str, status: str, reason: Optional[str] = None,
                          actor: str = "admin") -> Issuer:
        status = (status or "").lower()
        if status not in ISSUER_STATUSES:
            raise LifecycleError(
                f"Statut émetteur inconnu « {status} » (attendu : trusted, suspended).",
                code="bad_status", http_status=400,
            )
        issuer = self.get_issuer(issuer_id)
        if issuer is None:
            raise NotFoundError(f"Émetteur « {issuer_id} » introuvable.")
        if issuer.status == status:
            raise LifecycleError(f"L'émetteur est déjà « {status} ».", code="no_change")
        self._save_issuer_status(issuer_id, status)
        self._append_event(
            entity_type="issuer", entity_id=issuer_id,
            event_type=EVT_ISSUER_SUSPENDED if status == SUSPENDED else EVT_ISSUER_REACTIVATED,
            old_status=issuer.status, new_status=status, reason=reason, actor=actor,
        )
        issuer.status = status
        return issuer

    # ---------------- autorisations & sécurité ----------------
    @abc.abstractmethod
    def _user_roles(self, email: str) -> Optional[set]:
        """Rôles d'un utilisateur ACTIF (None si inconnu ou inactif)."""

    @abc.abstractmethod
    def _allowed_types(self, issuer_id: str) -> set:
        """Types de credentials que l'émetteur est autorisé à délivrer."""

    @abc.abstractmethod
    def _log_security_event(self, event_type: str, actor: Optional[str], action: str,
                            target: Optional[str], details: Optional[str]) -> None:
        ...

    @abc.abstractmethod
    def security_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        ...

    def authorize(self, actor: Optional[str], action: str, issuer_id: Optional[str] = None,
                  credential_type: Optional[str] = None, target: Optional[str] = None) -> set:
        """
        Vérifie que `actor` a le droit de faire `action`. En cas de refus : événement
        de sécurité dans le journal (ledger) puis AuthorizationError (HTTP 403).
        """
        def deny(event_type: str, message: str):
            self._log_security_event(event_type, actor, action, target, message)
            raise AuthorizationError(message, code=event_type.lower())

        if not actor:
            deny("UNAUTHENTICATED_ACTION", "Utilisateur non identifié (champ « actor » manquant).")
        roles = self._user_roles(actor)
        if roles is None:
            deny("UNKNOWN_OR_INACTIVE_USER", f"Utilisateur « {actor} » inconnu ou inactif.")
        needed = ACTION_ROLES.get(action, set())
        if not roles & needed:
            deny("UNAUTHORIZED_" + action.upper(),
                 f"« {actor} » (rôles : {', '.join(sorted(roles)) or 'aucun'}) n'a pas le droit "
                 f"de faire « {action} » (requis : {' ou '.join(sorted(needed))}).")
        if action == "issue":
            allowed = {t.lower() for t in self._allowed_types(issuer_id or "")}
            if (credential_type or "").lower() not in allowed:
                deny("CREDENTIAL_TYPE_NOT_ALLOWED",
                     f"L'émetteur « {issuer_id} » n'est pas autorisé à délivrer le type "
                     f"« {credential_type} » (autorisés : {', '.join(sorted(allowed)) or 'aucun'}).")
        return roles

    # ---------------- credentials ----------------
    @abc.abstractmethod
    def _insert_record(self, record: Dict[str, Any]) -> None:
        ...

    @abc.abstractmethod
    def get_record(self, credential_id: str) -> Optional[Dict[str, Any]]:
        ...

    @abc.abstractmethod
    def _save_status(self, credential_id: str, status: CredentialStatus,
                     reason: Optional[str]) -> None:
        ...

    @abc.abstractmethod
    def _append_event(self, entity_type: str, entity_id: str, event_type: str,
                      old_status: Optional[str], new_status: Optional[str],
                      reason: Optional[str], actor: str) -> None:
        ...

    @abc.abstractmethod
    def history(self, entity_id: str) -> List[Dict[str, Any]]:
        ...

    def record_issuance(self, credential: Dict[str, Any], actor: str = "issuer",
                        document_id: Optional[str] = None) -> Dict[str, Any]:
        """Enregistre un credential émis + événement ISSUED (appelé par le moteur)."""
        record = build_credential_record(credential)
        self._insert_record(record)
        if document_id:
            self._link_document(document_id, record["credential_id"])
        self._append_event(
            entity_type="credential", entity_id=record["credential_id"],
            event_type=EVT_ISSUED, old_status=None, new_status=record["status"],
            reason=None, actor=actor,
        )
        return record

    def change_status(self, credential_id: str, target: CredentialStatus,
                      reason: Optional[str] = None, actor: str = "admin") -> Dict[str, Any]:
        """Applique une transition contrôlée et la journalise."""
        record = self.get_record(credential_id)
        if record is None:
            raise NotFoundError(f"Credential « {credential_id} » absent du registre.")
        current = CredentialStatus(record["status"])
        check_transition(current, target)
        if target == CredentialStatus.REVOKED and not reason:
            raise LifecycleError("Une révocation doit être motivée (champ « reason »).",
                                 code="reason_required", http_status=400)
        self._save_status(credential_id, target, reason)
        self._append_event(
            entity_type="credential", entity_id=credential_id,
            event_type=_EVENT_FOR_TARGET[target], old_status=current.value,
            new_status=target.value, reason=reason, actor=actor,
        )
        return self.get_record(credential_id)

    # ---------------- Phase 4 : documents archivés (référence, jamais le contenu) -------
    def record_document(self, meta: Dict[str, Any], actor: str) -> Dict[str, Any]:
        raise NotImplementedError

    def get_document(self, document_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    def _link_document(self, document_id: str, credential_id: str) -> None:
        raise NotImplementedError

    # ---------------- Phase 5 : portefeuille étudiant & partage contrôlé -------------
    def user_id_for(self, email: str, role: Optional[str] = None) -> Optional[str]:
        """Identifiant interne (GUID) d'un utilisateur actif — sert d'identifiant porteur."""
        raise NotImplementedError

    def credentials_for_holder(self, holder_did: str) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def create_share(self, credential_id: str, token_hash: str, expires_at: str,
                     actor: str) -> Dict[str, Any]:
        raise NotImplementedError

    def resolve_share(self, token_hash: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    def revoke_share(self, share_id: str, actor: str) -> None:
        raise NotImplementedError

    def shares_for_credential(self, credential_id: str) -> List[Dict[str, Any]]:
        raise NotImplementedError

    # --- StatusStore (utilisé par le moteur Phase 2) ---
    def get_status(self, credential_id: str) -> CredentialStatus:
        record = self.get_record(credential_id)
        # Un credential absent du registre reste vérifiable par sa signature ;
        # on le considère actif (il n'a jamais été révoqué).
        return CredentialStatus(record["status"]) if record else CredentialStatus.ACTIVE

    def set_status(self, credential_id: str, status: CredentialStatus,
                   reason: Optional[str] = None) -> None:
        # Compatibilité Phase 2 : l'émission passe par record_issuance().
        if status == CredentialStatus.ACTIVE and self.get_record(credential_id) is None:
            return
        self.change_status(credential_id, status, reason)


class InMemoryTrustLedger(TrustLedger):
    """Implémentation en mémoire (tests / démo). Même comportement que la version SQL."""

    def __init__(self) -> None:
        self._issuers: Dict[str, Issuer] = {}
        self._records: Dict[str, Dict[str, Any]] = {}
        self._events: List[Dict[str, Any]] = []
        self._users: Dict[str, set] = {}
        self._types: Dict[str, set] = {}
        self._security: List[Dict[str, Any]] = []
        self._user_ids: Dict[str, str] = {}
        self._documents: Dict[str, Dict[str, Any]] = {}
        self._shares: Dict[str, Dict[str, Any]] = {}

    # utilisateurs / types autorisés (démo et tests)
    def add_user(self, email: str, *roles: str) -> None:
        import uuid
        self._users[email.lower()] = set(roles)
        self._user_ids.setdefault(email.lower(), str(uuid.uuid4()).upper())

    def user_id_for(self, email: str, role: Optional[str] = None) -> Optional[str]:
        roles = self._users.get((email or "").lower())
        if roles is None or (role and role not in roles):
            return None
        return self._user_ids[(email or "").lower()]

    # documents
    def record_document(self, meta: Dict[str, Any], actor: str) -> Dict[str, Any]:
        doc = {**meta, "credential_id": None, "status": "UPLOADED", "uploaded_by": actor,
               "created_at": utcnow_iso()}
        self._documents[meta["document_id"].upper()] = doc
        return dict(doc)

    def get_document(self, document_id: str) -> Optional[Dict[str, Any]]:
        d = self._documents.get((document_id or "").upper())
        return dict(d) if d else None

    def _link_document(self, document_id: str, credential_id: str) -> None:
        d = self._documents.get(document_id.upper())
        if d is None or d["status"] != "UPLOADED":
            raise LifecycleError("Document absent ou déjà rattaché à un credential.",
                                 code="document_unavailable")
        d.update(status="LINKED", credential_id=normalize_credential_id(credential_id))

    # portefeuille & partage
    def credentials_for_holder(self, holder_did: str) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._records.values() if r["holder_id"] == holder_did]

    def create_share(self, credential_id, token_hash, expires_at, actor) -> Dict[str, Any]:
        import uuid
        share = {"share_id": str(uuid.uuid4()).upper(),
                 "credential_id": normalize_credential_id(credential_id),
                 "token_hash": token_hash, "expires_at": expires_at, "created_by": actor,
                 "revoked": False, "created_at": utcnow_iso(), "access_count": 0}
        self._shares[share["share_id"]] = share
        return {k: v for k, v in share.items() if k != "token_hash"}

    def resolve_share(self, token_hash: str) -> Optional[Dict[str, Any]]:
        for sh in self._shares.values():
            if sh["token_hash"] == token_hash:
                sh["access_count"] += 1
                return {k: v for k, v in sh.items() if k != "token_hash"}
        return None

    def revoke_share(self, share_id: str, actor: str) -> None:
        sh = self._shares.get((share_id or "").upper())
        if sh is None:
            raise NotFoundError("Partage inconnu.")
        sh["revoked"] = True

    def shares_for_credential(self, credential_id: str) -> List[Dict[str, Any]]:
        cid = normalize_credential_id(credential_id)
        return [{k: v for k, v in s.items() if k != "token_hash"}
                for s in self._shares.values() if s["credential_id"] == cid]

    def allow_types(self, issuer_id: str, *types: str) -> None:
        self._types.setdefault(issuer_id, set()).update(types)

    def _user_roles(self, email: str) -> Optional[set]:
        return self._users.get((email or "").lower())

    def _allowed_types(self, issuer_id: str) -> set:
        return self._types.get(issuer_id, set())

    def _log_security_event(self, event_type, actor, action, target, details) -> None:
        self._security.append({"event_id": len(self._security) + 1, "event_type": event_type,
                               "actor": actor, "action": action, "target": target,
                               "details": details, "occurred_at": utcnow_iso()})

    def security_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(reversed(self._security))[:limit]

    def rotate_key(self, issuer_id: str, new_key_id: str, new_jwk: Dict[str, Any]) -> Issuer:
        """Rotation : ancienne clé « retired » (reste vérifiable), nouvelle clé active."""
        issuer = self._issuers[issuer_id]
        now = utcnow_iso()
        old_id = issuer.public_key_id
        issuer.keys.setdefault(old_id, {"jwk": issuer.public_jwk, "status": "active"})
        issuer.keys[old_id].update(status="retired", retired_at=now)
        issuer.keys[new_key_id] = {"jwk": new_jwk, "status": "active", "activated_at": now}
        issuer.public_key_id, issuer.public_jwk = new_key_id, new_jwk
        self._append_event("issuer", issuer_id, "ISSUER_KEY_ROTATED", old_id, new_key_id,
                           None, "admin")
        return issuer

    # émetteurs
    def register_issuer(self, issuer: Issuer, actor: str = "system") -> Issuer:
        if issuer.issuer_id in self._issuers:
            raise LifecycleError(f"Émetteur « {issuer.issuer_id} » déjà inscrit.",
                                 code="already_exists")
        self._issuers[issuer.issuer_id] = issuer
        self._append_event("issuer", issuer.issuer_id, EVT_ISSUER_REGISTERED,
                           None, issuer.status, None, actor)
        return issuer

    def register_from_signer(self, issuer_id: str, name: str, identifier: str, signer,
                             status: str = TRUSTED) -> Issuer:
        return self.register_issuer(Issuer(
            issuer_id=issuer_id, name=name, identifier=identifier,
            public_key_id=signer.key_id, public_jwk=signer.public_jwk(), status=status,
        ))

    def get_issuer(self, issuer_id: str) -> Optional[Issuer]:
        return self._issuers.get(issuer_id)

    def list_issuers(self) -> List[Issuer]:
        return list(self._issuers.values())

    def _save_issuer_status(self, issuer_id: str, status: str) -> None:
        self._issuers[issuer_id].status = status

    # credentials
    def _insert_record(self, record: Dict[str, Any]) -> None:
        if record["credential_id"] in self._records:
            raise LifecycleError("Credential déjà enregistré.", code="already_exists")
        self._records[record["credential_id"]] = {**record, "status_reason": None,
                                                  "updated_at": utcnow_iso()}

    def get_record(self, credential_id: str) -> Optional[Dict[str, Any]]:
        rec = self._records.get(normalize_credential_id(credential_id))
        return dict(rec) if rec else None

    def _save_status(self, credential_id: str, status: CredentialStatus,
                     reason: Optional[str]) -> None:
        rec = self._records[normalize_credential_id(credential_id)]
        rec["status"] = status.value
        rec["status_reason"] = reason
        rec["updated_at"] = utcnow_iso()

    def _append_event(self, entity_type, entity_id, event_type, old_status, new_status,
                      reason, actor) -> None:
        if entity_type == "credential":
            entity_id = normalize_credential_id(entity_id)
        self._events.append({
            "event_id": len(self._events) + 1, "entity_type": entity_type,
            "entity_id": entity_id, "event_type": event_type, "old_status": old_status,
            "new_status": new_status, "reason": reason, "actor": actor,
            "occurred_at": utcnow_iso(),
        })

    def history(self, entity_id: str) -> List[Dict[str, Any]]:
        if not entity_id.startswith("urn:") and entity_id not in self._issuers:
            entity_id = normalize_credential_id(entity_id)
        return [dict(e) for e in self._events if e["entity_id"] == entity_id]
