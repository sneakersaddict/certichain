"""
CertiChain — portails web (Phase 5), Flask sur Azure App Service.

Trois espaces (concept §3, §6) :
    /issuer   tableau de bord Université (UNIVERSITY_STAFF / ADMINISTRATOR)
    /wallet   portefeuille Étudiant (STUDENT) : voir, télécharger, PARTAGER (lien + QR code)
    /verify   portail Vérificateur (public) : coller un credential, ou ouvrir /v/<jeton>

Le navigateur ne parle QU'À ce portail. Le portail appelle l'API Azure Functions en HTTPS
avec une clé de fonction lue dans Key Vault (référence Key Vault de l'App Service) et
transmet l'utilisateur connecté dans l'en-tête X-CertiChain-User. Il n'a accès ni à la
clé de signature, ni à la base, ni au stockage privé.

Variables d'application :
    CERTICHAIN_API_BASE   https://<function-app>/api
    CERTICHAIN_API_KEY    clé de fonction           (@Microsoft.KeyVault(...))
    FLASK_SECRET_KEY      secret de session         (@Microsoft.KeyVault(...))
    DEMO_PASSWORD         mot de passe des comptes de démonstration (@Microsoft.KeyVault(...))
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
from functools import wraps

import requests
import segno
from flask import (Flask, abort, flash, redirect, render_template, request, session,
                   url_for)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_SECURE=os.environ.get("WEBSITE_SITE_NAME") is not None,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  MAX_CONTENT_LENGTH=6 * 1024 * 1024)

API = os.environ.get("CERTICHAIN_API_BASE", "http://localhost:7071/api").rstrip("/")
API_KEY = os.environ.get("CERTICHAIN_API_KEY", "")
DEMO_ACCOUNTS = ["scolarite@uir.ac.ma", "admin@uir.ac.ma", "etudiant@uir.ac.ma"]
STAFF = {"ADMINISTRATOR", "UNIVERSITY_STAFF"}


# ------------------------------------------------------------------ appels API
def api(method: str, path: str, *, json_body=None, data=None, headers=None, params=None,
        user: str | None = None):
    h = {"x-functions-key": API_KEY}
    if user:
        h["X-CertiChain-User"] = user
    h.update(headers or {})
    try:
        r = requests.request(method, f"{API}/{path}", json=json_body, data=data, headers=h,
                             params=params, timeout=90)
    except requests.RequestException:
        return 503, {"error": "Service CertiChain momentanément indisponible."}
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {"error": f"Réponse inattendue (HTTP {r.status_code})."}


# ------------------------------------------------------------------ sécurité
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"          # le jeton de partage ne fuit pas
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; "
                                               "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
    return resp


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not hmac.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Jeton CSRF invalide.")


def login_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if "user" not in session:
                return redirect(url_for("login", next=request.path))
            if roles and not set(session.get("roles", [])) & set(roles):
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


# ------------------------------------------------------------------ connexion
@app.route("/")
def home():
    if "user" not in session:
        return render_template("home.html")
    return redirect(url_for("issuer" if set(session["roles"]) & STAFF else "wallet"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pwd = request.form.get("password", "")
        expected = os.environ.get("DEMO_PASSWORD", "")
        if not expected or email not in DEMO_ACCOUNTS or not hmac.compare_digest(pwd, expected):
            flash("Identifiants incorrects.", "error")
            return render_template("login.html", accounts=DEMO_ACCOUNTS), 401
        st, me = api("GET", "me", user=email)
        if st != 200:
            flash(me.get("error", "Compte inconnu."), "error")
            return render_template("login.html", accounts=DEMO_ACCOUNTS), 403
        session.clear()
        session.update(user=email, roles=me["roles"], allowed_types=me.get("allowed_types", []))
        nxt = request.args.get("next", "")
        return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("home"))
    return render_template("login.html", accounts=DEMO_ACCOUNTS)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


# ------------------------------------------------------------------ Université
@app.route("/issuer", methods=["GET", "POST"])
@login_required(*STAFF)
def issuer():
    result = None
    if request.method == "POST":
        form = request.form
        document_id = None
        pdf = request.files.get("pdf")
        if pdf and pdf.filename:
            st, d = api("POST", "documents", data=pdf.read(), user=session["user"],
                        headers={"Content-Type": "application/pdf",
                                 "X-CertiChain-Filename": pdf.filename})
            if st != 201:
                flash(f"PDF refusé : {d.get('error')}", "error")
                return redirect(url_for("issuer"))
            document_id = d["document"]["document_id"]
        body = {"subject": {"holder_email": form.get("holder_email", "").strip(),
                            "full_name": form.get("full_name", "").strip(),
                            "credential_name": form.get("credential_name", "").strip(),
                            "credential_type_label": form.get("credential_type", "")},
                "document_id": document_id}
        if form.get("expires_at"):
            body["expires_at"] = form["expires_at"] + "T23:59:59Z"
        st, d = api("POST", "credentials", json_body=body, user=session["user"])
        if st == 201:
            flash("Credential émis, signé (Key Vault), archivé (Blob WORM) et enregistré (SQL Ledger).", "ok")
            result = d
        else:
            flash(f"Émission refusée ({st}) : {d.get('error')} — état : {d.get('state', '-')}", "error")
    lookup = request.args.get("holder_email")
    wallet = None
    if lookup:
        _, wallet = api("GET", "wallet", params={"holder_email": lookup}, user=session["user"])
    return render_template("issuer.html", result=result, wallet=wallet, lookup=lookup,
                           types=session.get("allowed_types", []))


@app.route("/issuer/status", methods=["POST"])
@login_required(*STAFF)
def change_status():
    cid = request.form.get("credential_id", "").split(":")[-1]
    action = request.form.get("action")
    reason = request.form.get("reason", "").strip()
    if action == "revoke":
        st, d = api("POST", f"credentials/{cid}/revoke", json_body={"reason": reason}, user=session["user"])
    else:
        st, d = api("POST", f"credentials/{cid}/status",
                    json_body={"status": action, "reason": reason}, user=session["user"])
    flash(f"Statut mis à jour : {d['credential']['status']}" if st == 200
          else f"Refusé ({st}) : {d.get('error')}", "ok" if st == 200 else "error")
    return redirect(url_for("issuer", holder_email=request.form.get("holder_email") or None))


# ------------------------------------------------------------------ Étudiant
@app.route("/wallet")
@login_required("STUDENT")
def wallet():
    st, d = api("GET", "wallet", user=session["user"])
    shares = {}
    for item in d.get("credentials", []):
        cid = item["record"]["credential_id"].split(":")[-1]
        _, sh = api("GET", f"credentials/{cid}/shares", user=session["user"])
        shares[cid] = sh.get("shares", [])
    return render_template("wallet.html", data=d, shares=shares, new_share=session.pop("new_share", None))


@app.route("/wallet/<cid>/share", methods=["POST"])
@login_required("STUDENT")
def create_share(cid):
    hours = max(1, min(int(request.form.get("hours", "24") or 24), 168))
    st, d = api("POST", f"credentials/{cid}/share", json_body={"expires_in_minutes": hours * 60},
                user=session["user"])
    if st != 201:
        flash(f"Partage refusé : {d.get('error')}", "error")
        return redirect(url_for("wallet"))
    url = d.get("share_url") or url_for("open_share", token=d["token"], _external=True)
    qr = segno.make(url, error="m").svg_data_uri(scale=4)
    session["new_share"] = {"cid": cid, "url": url, "qr": qr, "expires_at": d["share"]["expires_at"]}
    return redirect(url_for("wallet"))


@app.route("/wallet/<cid>/share/<share_id>/revoke", methods=["POST"])
@login_required("STUDENT")
def revoke_share(cid, share_id):
    st, d = api("POST", f"shares/{share_id}/revoke", json_body={"credential_id": cid}, user=session["user"])
    flash("Lien de partage retiré." if st == 200 else f"Erreur : {d.get('error')}",
          "ok" if st == 200 else "error")
    return redirect(url_for("wallet"))


@app.route("/document/<doc_id>")
@login_required()
def document(doc_id):
    st, d = api("GET", f"documents/{doc_id}/link", user=session["user"])
    if st != 200:
        abort(st if st in (403, 404) else 502)
    return redirect(d["url"])       # SAS lecture seule, 5 minutes


@app.route("/wallet/<cid>/download")
@login_required("STUDENT")
def download(cid):
    _, d = api("GET", "wallet", user=session["user"])
    for item in d.get("credentials", []):
        if item["record"]["credential_id"].endswith(cid):
            body = json.dumps({"credential": item["credential"], "jwt": item["jwt"]}, ensure_ascii=False, indent=2)
            return app.response_class(body, mimetype="application/json", headers={
                "Content-Disposition": f"attachment; filename=credential-{cid[:8]}.json"})
    abort(404)


# ------------------------------------------------------------------ Vérificateur
@app.route("/verify", methods=["GET", "POST"])
def verify():
    result = None
    if request.method == "POST":
        raw = request.form.get("credential", "").strip()
        if raw.startswith("{"):
            try:
                obj = json.loads(raw)
            except ValueError:
                flash("JSON invalide.", "error")
                return render_template("verify.html", result=None)
            body = {"jwt": obj["jwt"]} if isinstance(obj.get("jwt"), str) else {"credential": obj.get("credential", obj)}
        else:
            body = {"jwt": raw}
        _, result = api("POST", "credentials/verify", json_body=body)
    return render_template("verify.html", result=result)


@app.route("/v/<token>")
def open_share(token):
    st, d = api("POST", "shares/resolve", json_body={"token": token})
    return render_template("shared.html", st=st, d=d), (200 if st == 200 else st)


@app.route("/healthz")
def healthz():
    return {"status": "ok"}


@app.errorhandler(403)
def forbidden(_):
    return render_template("message.html", title="Accès refusé",
                           message="Votre compte n'a pas accès à cette page."), 403


if __name__ == "__main__":
    app.run(debug=True, port=5000)
