"""
API Azure Functions — Phase 2 (CertiChain).

Endpoints Phase 2 (moteur) :
    POST /api/credentials         -> émettre un credential signé
    POST /api/credentials/verify  -> vérifier un credential
    GET  /api/issuers/{id}        -> infos publiques d'un émetteur (clé publique, confiance)

Endpoints Phase 3 (registre de confiance & cycle de vie, Azure SQL Ledger) :
    GET  /api/issuers                        -> liste des émetteurs
    POST /api/issuers                        -> inscrire un émetteur        (clé ADMIN)
    POST /api/issuers/{id}/status            -> suspendre / réactiver       (clé ADMIN)
    GET  /api/credentials/{id}/status        -> statut + fiche du registre
    POST /api/credentials/{id}/revoke        -> révoquer (motif obligatoire) (clé ADMIN)
    POST /api/credentials/{id}/status        -> suspendre / réactiver       (clé ADMIN)
    GET  /api/credentials/{id}/history       -> journal ledger (infalsifiable)
    GET  /api/issuers/{id}/history           -> journal ledger de l'émetteur
    GET  /api/credentials/{id}               -> métadonnées autorisées d'un credential
    GET  /api/security/events                -> tentatives refusées (clé ADMIN)

Endpoints Phase 4 (documents, Blob Storage WORM, identité managée) :
    POST /api/documents                      -> archiver un PDF (validation + SHA-256)
    GET  /api/documents/{id}                 -> fiche du document (contrôle d'accès)
    GET  /api/documents/{id}/link            -> lien SAS user-delegation lecture seule ≤ 15 min

Endpoints Phase 5 (portails) :
    GET  /api/me                             -> rôles de l'utilisateur du portail
    GET  /api/wallet                         -> credentials de l'étudiant
    POST /api/credentials/{id}/share         -> lien de partage limité (jeton haché, expiration)
    GET  /api/credentials/{id}/shares        -> partages existants
    POST /api/shares/{share_id}/revoke       -> retirer un partage
    POST /api/shares/resolve                 -> ouvrir un partage (vérificateur)

Endpoint Phase 6 :
    POST /api/maintenance/reconcile          -> terminer les émissions interrompues (clé ADMIN)

Droits : chaque action qui modifie le registre est contrôlée par rôle (tables Users /
Roles / UserRoles) ; l'utilisateur est transmis dans l'en-tête X-CertiChain-User.

Modèle de programmation Python v2 (décorateurs). Le moteur est construit via
build_engine_from_env() : en local il utilise une clé logicielle ; sur Azure, il
utilise Key Vault + SQL selon les variables d'application (App Settings).

Sécurité : auth_level=FUNCTION par défaut (clé de fonction). En production, placer
derrière App Service + Managed Identity (concept §6, §8). Ne jamais exposer la clé
privée : la vérification n'utilise que la clé publique.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import azure.functions as func

from credential_engine import (
    CredentialSubject,
    Issuer,
    LifecycleError,
    build_engine_from_env,
    normalize_credential_id,
    parse_status,
)
from credential_engine.engine import CredentialEngine
from credential_engine.issuance import IssuanceError, IssuanceService
from credential_engine.models import holder_did
from credential_engine.status_store import CredentialStatus
from credential_engine.storage import (
    DOCUMENTS_CONTAINER,
    BlobDocumentStore,
    DocumentStore,
    StorageError,
)

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Construit une seule fois par instance (réutilisé entre invocations).
_engine: CredentialEngine = None
_store: Optional[DocumentStore] = None
_store_ready = False


def get_engine() -> CredentialEngine:
    global _engine
    if _engine is None:
        _engine = build_engine_from_env()
    return _engine


def get_store() -> Optional[DocumentStore]:
    """Stockage Blob (Phase 4) si CERTICHAIN_BLOB_ACCOUNT_URL est défini."""
    global _store, _store_ready
    if not _store_ready:
        url = os.environ.get("CERTICHAIN_BLOB_ACCOUNT_URL")
        _store = BlobDocumentStore(url) if url else None
        _store_ready = True
    return _store


def get_issuance() -> IssuanceService:
    return IssuanceService(get_engine(), get_store(),
                           allow_fault_injection=os.environ.get("CERTICHAIN_ALLOW_FAULT_INJECTION") == "1")


def _json(body: dict, status: int = 200) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps(body, ensure_ascii=False),
        status_code=status,
        mimetype="application/json",
    )


@app.route(route="credentials", methods=["POST"])
def issue_credential(req: func.HttpRequest) -> func.HttpResponse:
    """Émet un credential. Corps attendu : subject + options (voir README)."""
    try:
        data = req.get_json()
    except ValueError:
        return _json({"error": "Corps JSON invalide."}, 400)

    subj = data.get("subject") or {}
    engine = get_engine()
    ledger = engine.registry
    # Porteur : l'étudiant est désigné par son e-mail de compte ; on inscrit dans le
    # credential son identifiant interne (GUID), pas son e-mail (minimisation, §8).
    if subj.get("holder_email") and not subj.get("holder_id"):
        uid = ledger.user_id_for(subj["holder_email"], role="STUDENT")
        if uid is None:
            return _json({"error": "Étudiant inconnu (compte STUDENT actif requis).",
                          "code": "unknown_holder"}, 400)
        subj["holder_id"] = uid
    required = ["holder_id", "full_name", "credential_name", "credential_type_label"]
    missing = [f for f in required if not subj.get(f)]
    if missing:
        return _json({"error": f"Champs 'subject' manquants : {missing}"}, 400)

    # Droits (concept §7.1) : l'acteur doit être UNIVERSITY_STAFF ou ADMINISTRATOR et
    # l'émetteur doit être autorisé à délivrer ce type de diplôme. Refus -> 403 + journal.
    actor = _actor(req, data)
    try:
        ledger.authorize(actor, "issue", issuer_id=engine.issuer_id,
                         credential_type=subj["credential_type_label"], target=subj["holder_id"])
    except LifecycleError as exc:
        return _lifecycle_error(exc)

    subject = CredentialSubject(
        holder_id=subj["holder_id"],
        full_name=subj["full_name"],
        credential_name=subj["credential_name"],
        credential_type_label=subj["credential_type_label"],
        extra=subj.get("extra", {}),
    )
    # Émission orchestrée : signature -> archive Blob -> registre SQL (Phases 4 et 6)
    try:
        out = get_issuance().issue(
            subject, actor,
            credential_type=data.get("credential_type", "AcademicCredential"),
            valid_from=data.get("valid_from"), expires_at=data.get("expires_at"),
            document_id=data.get("document_id"),
            simulate=req.headers.get("x-certichain-simulate-failure"),
        )
    except IssuanceError as exc:
        logging.warning("Émission non finalisée : %s", exc)
        return _json(exc.to_dict(), exc.http_status)
    except Exception as exc:  # erreur non sensible
        logging.exception("Échec d'émission")
        return _json({"error": "Échec d'émission du credential.", "detail": type(exc).__name__,
                      "state": "NOT_ISSUED"}, 500)
    return _json({"credential": out["credential"], "jwt": out["jwt"], "state": out["state"],
                  "archive_reference": out["archive_reference"],
                  "document_reference": (out["record"] or {}).get("document_reference"),
                  "proof_formats": ["json-proof (CertiChainEcdsaSecp256r1_ES256)",
                                    "vc+jwt (W3C VC-JOSE, ES256)"]}, 201)


@app.route(route="credentials/verify", methods=["POST"])
def verify_credential(req: func.HttpRequest) -> func.HttpResponse:
    """Vérifie un credential. Corps attendu : {"credential": {...}}."""
    try:
        data = req.get_json()
    except ValueError:
        return _json({"error": "Corps JSON invalide."}, 400)

    # Deux formats acceptés : {"jwt": "<vc+jwt>"} (standard) ou {"credential": {...}}.
    token = data.get("jwt") or (data.get("credential") if isinstance(data.get("credential"), str) else None)
    if token:
        return _json(get_engine().verify_jwt(token).to_dict(), 200)
    credential = data.get("credential", data)
    if not isinstance(credential, dict):
        return _json({"error": "Credential manquant."}, 400)

    result = get_engine().verify_credential(credential)
    return _json(result.to_dict(), 200)


def _lifecycle_error(exc: LifecycleError) -> func.HttpResponse:
    return _json({"error": str(exc), "code": exc.code}, exc.http_status)


def _actor(req: func.HttpRequest, data: dict) -> str:
    """
    Identité de l'utilisateur qui agit. Le portail (Phase 5) la transmet dans l'en-tête
    X-CertiChain-User après authentification ; à défaut, champ « actor » du corps.
    """
    return (req.headers.get("x-certichain-user") or data.get("actor") or "").strip()


def _body(req: func.HttpRequest) -> dict:
    try:
        data = req.get_json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


@app.route(route="issuers/{id}", methods=["GET"])
def get_issuer(req: func.HttpRequest) -> func.HttpResponse:
    """Infos publiques d'un émetteur (jamais de clé privée)."""
    issuer_id = req.route_params.get("id")
    info = get_engine().get_issuer_info(issuer_id)
    if info is None:
        return _json({"error": "Émetteur inconnu."}, 404)
    return _json({"issuer": info}, 200)


# =========================================================================
# Phase 3 — registre de confiance & cycle de vie (Azure SQL Ledger)
# Les opérations qui MODIFIENT le registre exigent la clé ADMIN (master key) :
# séparation des rôles entre le portail université (émission/vérification) et
# l'administration du registre (inscription, suspension, révocation).
# =========================================================================


@app.route(route="issuers", methods=["GET"])
def list_issuers(req: func.HttpRequest) -> func.HttpResponse:
    issuers = get_engine().registry.list_issuers()
    return _json({"count": len(issuers), "issuers": [i.public_info() for i in issuers]})


@app.route(route="issuers", methods=["POST"], auth_level=func.AuthLevel.ADMIN)
def register_issuer(req: func.HttpRequest) -> func.HttpResponse:
    data = _body(req)
    required = ["issuer_id", "name", "identifier", "public_key_id", "publicKeyJwk"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return _json({"error": f"Champs manquants : {missing}"}, 400)
    jwk = data["publicKeyJwk"]
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        return _json({"error": "La clé publique doit être un JWK EC P-256."}, 400)
    try:
        get_engine().registry.authorize(_actor(req, data), "manage_issuer", target=data["issuer_id"])
        issuer = get_engine().registry.register_issuer(
            Issuer(issuer_id=data["issuer_id"], name=data["name"],
                   identifier=data["identifier"], public_key_id=data["public_key_id"],
                   public_jwk=jwk),
            actor=_actor(req, data),
        )
    except LifecycleError as exc:
        return _lifecycle_error(exc)
    return _json({"issuer": issuer.public_info()}, 201)


@app.route(route="issuers/{id}/status", methods=["POST"], auth_level=func.AuthLevel.ADMIN)
def set_issuer_status(req: func.HttpRequest) -> func.HttpResponse:
    data = _body(req)
    try:
        get_engine().registry.authorize(_actor(req, data), "manage_issuer",
                                        target=req.route_params.get("id"))
        issuer = get_engine().registry.set_issuer_status(
            req.route_params.get("id"), data.get("status", ""), data.get("reason"),
            actor=_actor(req, data),
        )
    except LifecycleError as exc:
        return _lifecycle_error(exc)
    return _json({"issuer": issuer.public_info()})


@app.route(route="issuers/{id}/history", methods=["GET"])
def issuer_history(req: func.HttpRequest) -> func.HttpResponse:
    issuer_id = req.route_params.get("id")
    events = get_engine().registry.history(issuer_id)
    return _json({"issuer_id": issuer_id, "events": events})


@app.route(route="credentials/{id}/status", methods=["GET"])
def credential_status(req: func.HttpRequest) -> func.HttpResponse:
    cred_id = req.route_params.get("id")
    record = get_engine().registry.get_record(cred_id)
    if record is None:
        return _json({"error": "Credential absent du registre.", "credential_id": cred_id}, 404)
    return _json({"credential": record})


@app.route(route="credentials/{id}/revoke", methods=["POST"])
def revoke_credential(req: func.HttpRequest) -> func.HttpResponse:
    data = _body(req)
    try:
        get_engine().registry.authorize(_actor(req, data), "revoke", target=req.route_params.get("id"))
        record = get_engine().registry.change_status(
            req.route_params.get("id"), CredentialStatus.REVOKED, data.get("reason"),
            actor=_actor(req, data),
        )
    except LifecycleError as exc:
        return _lifecycle_error(exc)
    return _json({"credential": record})


@app.route(route="credentials/{id}/status", methods=["POST"])
def set_credential_status(req: func.HttpRequest) -> func.HttpResponse:
    data = _body(req)
    try:
        target = parse_status(data.get("status", ""))
        get_engine().registry.authorize(
            _actor(req, data), "revoke" if target == CredentialStatus.REVOKED else "suspend",
            target=req.route_params.get("id"))
        record = get_engine().registry.change_status(
            req.route_params.get("id"), target, data.get("reason"),
            actor=_actor(req, data),
        )
    except LifecycleError as exc:
        return _lifecycle_error(exc)
    return _json({"credential": record})


@app.route(route="credentials/{id}/history", methods=["GET"])
def credential_history(req: func.HttpRequest) -> func.HttpResponse:
    cred_id = req.route_params.get("id")
    events = get_engine().registry.history(cred_id)
    if not events:
        return _json({"error": "Aucun événement pour ce credential.", "credential_id": cred_id}, 404)
    return _json({"credential_id": cred_id, "events": events})


@app.route(route="credentials/{id}", methods=["GET"])
def get_credential(req: func.HttpRequest) -> func.HttpResponse:
    """Métadonnées autorisées d'un credential (concept §12) — sans données personnelles."""
    record = get_engine().registry.get_record(req.route_params.get("id"))
    if record is None:
        return _json({"error": "Credential absent du registre."}, 404)
    return _json({"credential": record})


@app.route(route="security/events", methods=["GET"], auth_level=func.AuthLevel.ADMIN)
def security_events(req: func.HttpRequest) -> func.HttpResponse:
    """Journal des tentatives refusées (table ledger append-only dbo.SecurityEvents)."""
    limit = min(int(req.params.get("limit", "50") or 50), 200)
    events = get_engine().registry.security_events(limit)
    return _json({"count": len(events), "events": events})


@app.route(route="me", methods=["GET"])
def me(req: func.HttpRequest) -> func.HttpResponse:
    """Rôles de l'utilisateur connecté au portail (+ types de diplômes autorisés pour l'émetteur)."""
    actor = _actor(req, {})
    ledger = get_engine().registry
    roles = ledger._user_roles(actor)
    if roles is None:
        return _json({"error": "Utilisateur inconnu ou inactif."}, 404)
    out = {"email": actor, "roles": sorted(roles), "issuer_id": get_engine().issuer_id}
    if _is_staff(roles):
        out["allowed_types"] = sorted(ledger._allowed_types(get_engine().issuer_id))
    return _json(out)


# =========================================================================
# Phase 4 — stockage sécurisé des documents (Azure Blob Storage, WORM)
# =========================================================================

def _roles(actor: str) -> set:
    return get_engine().registry._user_roles(actor) or set()


def _is_staff(roles: set) -> bool:
    return bool(roles & {"ADMINISTRATOR", "UNIVERSITY_STAFF"})


def _owns(actor: str, record: Optional[dict]) -> bool:
    """Un étudiant n'accède qu'à SES credentials (holder = son identifiant interne)."""
    uid = get_engine().registry.user_id_for(actor, role="STUDENT")
    return bool(uid and record and record.get("holder_id") == holder_did(uid))


def _deny(actor: str, action: str, target: str, message: str) -> func.HttpResponse:
    get_engine().registry._log_security_event("UNAUTHORIZED_" + action.upper(), actor, action,
                                              target, message)
    return _json({"error": message, "code": "unauthorized_" + action}, 403)


def _no_store() -> func.HttpResponse:
    return _json({"error": "Stockage Blob non configuré (CERTICHAIN_BLOB_ACCOUNT_URL)."}, 501)


@app.route(route="documents", methods=["POST"])
def upload_document(req: func.HttpRequest) -> func.HttpResponse:
    """
    Archive un PDF original. Deux formes acceptées :
      - corps brut PDF (Content-Type: application/pdf) + en-tête X-CertiChain-Filename ;
      - JSON {"filename": "...", "content_base64": "..."}.
    Retour : document_id + empreinte SHA-256 (à passer à POST /api/credentials).
    """
    store = get_store()
    if store is None:
        return _no_store()
    ctype = (req.headers.get("content-type") or "").split(";")[0].strip().lower()
    if ctype == "application/json":
        data = _body(req)
        try:
            raw = base64.b64decode(data.get("content_base64", ""), validate=True)
        except Exception:
            return _json({"error": "content_base64 invalide."}, 400)
        filename, media = data.get("filename"), data.get("media_type", "application/pdf")
    else:
        data, raw = {}, req.get_body()
        filename, media = req.headers.get("x-certichain-filename"), ctype or "application/pdf"
    actor = _actor(req, data)
    ledger = get_engine().registry
    try:
        ledger.authorize(actor, "upload_document", target=filename)
    except LifecycleError as exc:
        return _lifecycle_error(exc)
    # 1) Blob (WORM) puis 2) fiche Documents dans le ledger SQL
    try:
        meta = store.put_document(raw, filename, media, actor)
    except StorageError as exc:
        return _json({"error": str(exc), "code": exc.code}, exc.http_status)
    meta["retention_metadata"] = os.environ.get("CERTICHAIN_DOC_RETENTION", "WORM container policy")
    try:
        doc = ledger.record_document(meta, actor)
    except Exception as exc:
        logging.exception("Fiche document non enregistrée")
        return _json({"error": "PDF archivé mais fiche non enregistrée : réconciliation requise.",
                      "state": "PENDING_RECONCILIATION", "document_id": meta["document_id"],
                      "detail": type(exc).__name__}, 503)
    return _json({"document": doc}, 201)


def _document_access(req: func.HttpRequest):
    """Contrôle d'accès commun aux opérations de lecture d'un document."""
    actor = _actor(req, {})
    ledger = get_engine().registry
    doc = ledger.get_document(req.route_params.get("id"))
    if doc is None:
        return None, _json({"error": "Document inconnu."}, 404)
    try:
        roles = ledger.authorize(actor, "read_document", target=doc["document_id"])
    except LifecycleError as exc:
        return None, _lifecycle_error(exc)
    if not _is_staff(roles):
        rec = ledger.get_record(doc["credential_id"]) if doc.get("credential_id") else None
        if not _owns(actor, rec):
            return None, _deny(actor, "read_document", doc["document_id"],
                               "Ce document n'appartient pas à cet utilisateur.")
    return doc, None


@app.route(route="documents/{id}", methods=["GET"])
def get_document(req: func.HttpRequest) -> func.HttpResponse:
    doc, err = _document_access(req)
    return err or _json({"document": doc})


@app.route(route="documents/{id}/link", methods=["GET"])
def document_link(req: func.HttpRequest) -> func.HttpResponse:
    """Lien de téléchargement temporaire (SAS user delegation, lecture seule, ≤ 15 min)."""
    store = get_store()
    if store is None:
        return _no_store()
    doc, err = _document_access(req)
    if err:
        return err
    minutes = int(req.params.get("minutes", "5") or 5)
    name = doc["blob_reference"].split("/", 1)[1]
    url = store.read_link(DOCUMENTS_CONTAINER, name, minutes)
    return _json({"document_id": doc["document_id"], "url": url, "expires_in_minutes": min(minutes, 15)})


# =========================================================================
# Phase 5 — portefeuille étudiant et partage contrôlé (lien / QR code)
# =========================================================================

@app.route(route="wallet", methods=["GET"])
def wallet(req: func.HttpRequest) -> func.HttpResponse:
    """Credentials d'un étudiant (le sien ; le personnel peut consulter celui d'un étudiant)."""
    actor = _actor(req, {})
    ledger = get_engine().registry
    try:
        roles = ledger.authorize(actor, "view_wallet")
    except LifecycleError as exc:
        return _lifecycle_error(exc)
    email = req.params.get("holder_email") or actor
    if email.lower() != actor.lower() and not _is_staff(roles):
        return _deny(actor, "view_wallet", email, "Accès au portefeuille d'un autre étudiant refusé.")
    uid = ledger.user_id_for(email, role="STUDENT")
    if uid is None:
        return _json({"holder_email": email, "count": 0, "credentials": []})
    store = get_store()
    items = []
    for rec in ledger.credentials_for_holder(holder_did(uid)):
        saved = store.load_credential(rec["credential_id"]) if store else None
        items.append({"record": rec, "credential": (saved or {}).get("credential"),
                      "jwt": (saved or {}).get("jwt")})
    return _json({"holder_email": email, "count": len(items), "credentials": items})


def _share_target(req: func.HttpRequest, data: dict):
    actor = _actor(req, data)
    ledger = get_engine().registry
    try:
        roles = ledger.authorize(actor, "share", target=req.route_params.get("id"))
    except LifecycleError as exc:
        return None, None, _lifecycle_error(exc)
    rec = ledger.get_record(req.route_params.get("id"))
    if rec is None:
        return None, None, _json({"error": "Credential absent du registre."}, 404)
    if not _is_staff(roles) and not _owns(actor, rec):
        return None, None, _deny(actor, "share", rec["credential_id"],
                                 "Seul le titulaire du credential peut le partager.")
    return actor, rec, None


@app.route(route="credentials/{id}/share", methods=["POST"])
def share_credential(req: func.HttpRequest) -> func.HttpResponse:
    """
    Crée une référence de partage LIMITÉE (concept §7.2) : jeton aléatoire de 256 bits,
    durée de vie bornée, révocable. Seule l'EMPREINTE du jeton est stockée (ledger) :
    même un accès à la base ne permet pas de reconstituer les liens.
    """
    data = _body(req)
    actor, rec, err = _share_target(req, data)
    if err:
        return err
    if rec["status"] != "active":
        return _json({"error": f"Credential « {rec['status']} » : partage impossible."}, 409)
    minutes = max(5, min(int(data.get("expires_in_minutes", 1440) or 1440), 7 * 24 * 60))
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    share = get_engine().registry.create_share(rec["credential_id"],
                                               hashlib.sha256(token.encode()).hexdigest(), expires, actor)
    base = os.environ.get("CERTICHAIN_PORTAL_URL", "").rstrip("/")
    return _json({"share": share, "token": token,
                  "share_url": f"{base}/v/{token}" if base else None,
                  "note": "Le jeton n'est affiché qu'une fois ; seule son empreinte est conservée."}, 201)


@app.route(route="credentials/{id}/shares", methods=["GET"])
def list_shares(req: func.HttpRequest) -> func.HttpResponse:
    actor, rec, err = _share_target(req, {})
    if err:
        return err
    return _json({"credential_id": rec["credential_id"],
                  "shares": get_engine().registry.shares_for_credential(rec["credential_id"])})


@app.route(route="shares/{share_id}/revoke", methods=["POST"])
def revoke_share(req: func.HttpRequest) -> func.HttpResponse:
    data = _body(req)
    actor = _actor(req, data)
    ledger = get_engine().registry
    try:
        roles = ledger.authorize(actor, "share", target=req.route_params.get("share_id"))
        cred_id = data.get("credential_id", "")
        rec = ledger.get_record(cred_id) if cred_id else None
        shares = ledger.shares_for_credential(cred_id) if rec else []
        if not any(s["share_id"].upper() == req.route_params.get("share_id", "").upper() for s in shares):
            return _json({"error": "Partage inconnu pour ce credential."}, 404)
        if not _is_staff(roles) and not _owns(actor, rec):
            return _deny(actor, "share", cred_id, "Seul le titulaire peut retirer ce partage.")
        ledger.revoke_share(req.route_params.get("share_id"), actor)
    except LifecycleError as exc:
        return _lifecycle_error(exc)
    return _json({"share_id": req.route_params.get("share_id"), "revoked": True})


@app.route(route="shares/resolve", methods=["POST"])
def resolve_share(req: func.HttpRequest) -> func.HttpResponse:
    """
    Ouvre un lien de partage (vérificateur). Le jeton est envoyé dans le CORPS (pas dans
    l'URL de l'API, pour ne pas finir dans les journaux). Le QR code n'est qu'un moyen de
    retrouver ce flux : l'authenticité vient de la vérification ci-dessous (§7.2-11).
    """
    token = (_body(req).get("token") or "").strip()
    if len(token) < 20:
        return _json({"error": "Jeton de partage invalide."}, 400)
    ledger = get_engine().registry
    share = ledger.resolve_share(hashlib.sha256(token.encode()).hexdigest())
    if share is None:
        return _json({"error": "Lien de partage inconnu."}, 404)
    if share["revoked"]:
        return _json({"error": "Ce lien de partage a été retiré par son titulaire.", "code": "share_revoked"}, 410)
    if share["expires_at"] and share["expires_at"] < datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"):
        return _json({"error": "Ce lien de partage a expiré.", "code": "share_expired"}, 410)
    store = get_store()
    saved = store.load_credential(share["credential_id"]) if store else None
    if not saved:
        return _json({"error": "Credential archivé introuvable."}, 404)
    engine = get_engine()
    result = engine.verify_jwt(saved["jwt"]) if saved.get("jwt") else engine.verify_credential(saved["credential"])
    doc_link = None
    ref = (saved["credential"].get("credentialSchema") or {}).get("documentReference")
    if ref and result.status.value == "Valid" and store:
        doc_link = store.read_link(DOCUMENTS_CONTAINER, ref.split("/", 1)[1], 5)
    return _json({"verification": result.to_dict(), "credential": saved["credential"],
                  "jwt": saved.get("jwt"), "document_url": doc_link,
                  "share": {k: share[k] for k in ("share_id", "expires_at", "access_count")}})


# =========================================================================
# Phase 6 — réconciliation après panne partielle
# =========================================================================

@app.route(route="maintenance/reconcile", methods=["POST"], auth_level=func.AuthLevel.ADMIN)
def reconcile(req: func.HttpRequest) -> func.HttpResponse:
    data = _body(req)
    actor = _actor(req, data)
    try:
        get_engine().registry.authorize(actor, "reconcile")
    except LifecycleError as exc:
        return _lifecycle_error(exc)
    return _json(get_issuance().reconcile(actor))
