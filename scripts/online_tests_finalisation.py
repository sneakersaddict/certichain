"""Tests en ligne de la finalisation Parties 2-3 (JWT W3C, droits + SecurityEvents, rotation de clé).

Usage : python scripts/online_tests_finalisation.py HOST FUNCKEY MASTERKEY ADMIN STAFF STUDENT [avant|apres]
  avant : émet, vérifie (JSON + JWT), teste les refus, sauvegarde le credential dans before.json
  apres : (après rotation de la clé Key Vault) re-vérifie before.json + émet avec la nouvelle clé
"""
import json, sys, urllib.request, urllib.error

H, K, M, ADMIN, STAFF, STUDENT = sys.argv[1:7]
PHASE = sys.argv[7] if len(sys.argv) > 7 else "avant"


def call(method, path, body=None, admin=False, user=None):
    headers = {"Content-Type": "application/json"}
    if user:
        headers["X-CertiChain-User"] = user
    req = urllib.request.Request(f"https://{H}/api/{path}?code={M if admin else K}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw or b"{}")
        except Exception:
            return e.code, {"raw": raw[:300].decode(errors="ignore")}


def show(t, st, d, keys=None):
    if keys and isinstance(d, dict):
        d = {k: d.get(k) for k in keys}
    print(f"\n=== {t} -> HTTP {st}\n" + json.dumps(d, ensure_ascii=False)[:400])


def subject(label="Master", holder="student-final-001"):
    return {"subject": {"holder_id": holder, "full_name": "Etudiant Final",
                        "credential_name": f"{label} Cloud Computing", "credential_type_label": label}}


if PHASE == "avant":
    st, d = call("POST", "credentials", subject(), user=STAFF)
    vc, token = d.get("credential", {}), d.get("jwt")
    show("1) Emission par UNIVERSITY_STAFF", st, {"id": vc.get("id"), "kid": vc.get("proof", {}).get("verificationMethod"),
                                                  "proof_formats": d.get("proof_formats"), "error": d.get("error")})
    print("   JWT (debut) :", (token or "")[:90], "...")
    json.dump({"credential": vc, "jwt": token}, open("before.json", "w"))
    st, d = call("POST", "credentials/verify", {"jwt": token}); show("2) Verification format W3C vc+jwt", st, d, ["result", "reason", "checks"])
    st, d = call("POST", "credentials/verify", {"credential": vc}); show("3) Verification format JSON proof", st, d, ["result", "reason"])
    parts = (token or "a.b.c").split(".")
    st, d = call("POST", "credentials/verify", {"jwt": parts[0] + "." + parts[1][:-4] + "AAAA." + parts[2]})
    show("4) JWT falsifie", st, d, ["result", "reason"])
    short = vc.get("id", "").split(":")[-1]
    st, d = call("GET", f"credentials/{short}"); show("5) GET /api/credentials/{id}", st, d.get("credential", d))
    st, d = call("POST", "credentials", subject(), user=STUDENT); show("6) Emission par un ETUDIANT (refus attendu)", st, d)
    st, d = call("POST", "credentials", subject(), user="inconnu@exemple.com"); show("7) Emission par un inconnu (refus attendu)", st, d)
    st, d = call("POST", "credentials", subject()); show("8) Emission sans utilisateur (refus attendu)", st, d)
    st, d = call("POST", "credentials", subject("PermisDeConduire"), user=STAFF); show("9) Type non autorise pour l'emetteur (refus attendu)", st, d)
    st, d = call("POST", f"credentials/{short}/revoke", {"reason": "test"}, admin=True, user=STAFF)
    show("10) Revocation par STAFF (reservee ADMIN, refus attendu)", st, d)
    st, d = call("GET", "security/events?limit=10", admin=True)
    print(f"\n=== 11) Journal SecurityEvents (ledger append-only) -> HTTP {st}")
    for e in d.get("events", []):
        print(f"  {e.get('occurred_at')}  {e.get('event_type'):<30} acteur={e.get('actor')}  action={e.get('action')}  cible={e.get('target')}")
else:
    saved = json.load(open("before.json"))
    old_kid = saved["credential"].get("proof", {}).get("verificationMethod")
    st, d = call("POST", "credentials/verify", {"credential": saved["credential"]})
    show("A) Ancien credential (cle retiree) - JSON", st, d, ["result", "reason"])
    st, d = call("POST", "credentials/verify", {"jwt": saved["jwt"]})
    show("B) Ancien credential (cle retiree) - JWT", st, d, ["result", "reason"])
    st, d = call("POST", "credentials", subject(holder="student-final-002"), user=STAFF)
    vc = d.get("credential", {}); new_kid = vc.get("proof", {}).get("verificationMethod")
    show("C) Nouveau credential", st, {"id": vc.get("id"), "ancienne_cle": old_kid, "nouvelle_cle": new_kid,
                                       "cle_differente": old_kid != new_kid})
    st, d = call("POST", "credentials/verify", {"jwt": d.get("jwt")}); show("D) Verification nouveau credential (JWT)", st, d, ["result", "reason"])
    st, d = call("GET", "issuers/uir")
    print(f"\n=== E) Cles publiees de l'emetteur -> HTTP {st}")
    for k in (d.get("issuer", d) or {}).get("keys", []):
        print("  ", {x: k.get(x) for x in ("key_id", "status", "activated_at", "retired_at")})
