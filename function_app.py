"""
API Azure Functions — Phase 2 (CertiChain).

Endpoints possédés par la Phase 2 (concept §12) :
    POST /api/credentials         -> émettre un credential signé
    POST /api/credentials/verify  -> vérifier un credential
    GET  /api/issuers/{id}        -> infos publiques d'un émetteur (clé publique, confiance)

Modèle de programmation Python v2 (décorateurs). Le moteur est construit via
build_engine_from_env() : en local il utilise une clé logicielle ; sur Azure, il
utilise Key Vault + SQL selon les variables d'application (App Settings).

Sécurité : auth_level=FUNCTION par défaut (clé de fonction). En production, placer
derrière App Service + Managed Identity (concept §6, §8). Ne jamais exposer la clé
privée : la vérification n'utilise que la clé publique.
"""

from __future__ import annotations

import json
import logging

import azure.functions as func

from credential_engine import build_engine_from_env, CredentialSubject
from credential_engine.engine import CredentialEngine

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Construit une seule fois par instance (réutilisé entre invocations).
_engine: CredentialEngine = None


def get_engine() -> CredentialEngine:
    global _engine
    if _engine is None:
        _engine = build_engine_from_env()
    return _engine


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
    required = ["holder_id", "full_name", "credential_name", "credential_type_label"]
    missing = [f for f in required if not subj.get(f)]
    if missing:
        return _json({"error": f"Champs 'subject' manquants : {missing}"}, 400)

    subject = CredentialSubject(
        holder_id=subj["holder_id"],
        full_name=subj["full_name"],
        credential_name=subj["credential_name"],
        credential_type_label=subj["credential_type_label"],
        extra=subj.get("extra", {}),
    )
    try:
        vc = get_engine().issue_credential(
            subject,
            credential_type=data.get("credential_type", "AcademicCredential"),
            valid_from=data.get("valid_from"),
            expires_at=data.get("expires_at"),
            document_reference=data.get("document_reference"),
            document_hash=data.get("document_hash"),
        )
    except Exception as exc:  # erreur non sensible
        logging.exception("Échec d'émission")
        return _json({"error": "Échec d'émission du credential.", "detail": str(exc)}, 500)

    return _json({"credential": vc}, 201)


@app.route(route="credentials/verify", methods=["POST"])
def verify_credential(req: func.HttpRequest) -> func.HttpResponse:
    """Vérifie un credential. Corps attendu : {"credential": {...}}."""
    try:
        data = req.get_json()
    except ValueError:
        return _json({"error": "Corps JSON invalide."}, 400)

    credential = data.get("credential", data)
    if not isinstance(credential, dict):
        return _json({"error": "Credential manquant."}, 400)

    result = get_engine().verify_credential(credential)
    return _json(result.to_dict(), 200)


@app.route(route="issuers/{id}", methods=["GET"])
def get_issuer(req: func.HttpRequest) -> func.HttpResponse:
    """Infos publiques d'un émetteur (jamais de clé privée)."""
    issuer_id = req.route_params.get("id")
    info = get_engine().get_issuer_info(issuer_id)
    if info is None:
        return _json({"error": "Émetteur inconnu."}, 404)
    return _json({"issuer": info}, 200)
