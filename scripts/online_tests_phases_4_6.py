"""Tests en ligne Phases 4-6 (et re-test rotation). Usage : python3 t.py HOST FUNCKEY MASTERKEY"""
import base64, copy, hashlib, json, sys, urllib.error, urllib.request

H, K, M = sys.argv[1:4]
STAFF, ADMIN, STUDENT = "scolarite@uir.ac.ma", "admin@uir.ac.ma", "etudiant@uir.ac.ma"
PDF = b"%PDF-1.4\n% CertiChain demo\n1 0 obj<</Type/Catalog>>endobj\ntrailer<<>>\n%%EOF\n"
ok_count = [0, 0]


def call(method, path, body=None, user=None, admin=False, raw=None, headers=None):
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    if user:
        h["X-CertiChain-User"] = user
    sep = "&" if "?" in path else "?"
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(f"https://{H}/api/{path}{sep}code={M if admin else K}", data=data,
                                 method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


def check(label, cond, detail=""):
    ok_count[0 if cond else 1] += 1
    print(f"[{'OK ' if cond else 'KO '}] {label}" + (f"  -> {detail}" if detail else ""))


def get_url(url):
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


print("=== PHASE 4 : stockage sécurisé des documents")
st, d = call("POST", "documents", raw=PDF, user=STAFF,
             headers={"Content-Type": "application/pdf", "X-CertiChain-Filename": "diplome_master.pdf"})
doc = d.get("document", {})
check("Upload PDF par la scolarité (201)", st == 201, f"document_id={doc.get('document_id')} statut={doc.get('status')}")
check("Empreinte SHA-256 calculée côté serveur", doc.get("content_hash") == hashlib.sha256(PDF).hexdigest(),
      (doc.get("content_hash") or "")[:16] + "…")
st, d = call("POST", "documents", raw=PDF, user=STUDENT, headers={"Content-Type": "application/pdf"})
check("Upload refusé pour un étudiant (403)", st == 403, d.get("code"))
st, d = call("POST", "documents", raw=b"MZ\x90\x00exe", user=STAFF, headers={"Content-Type": "application/pdf"})
check("Fichier non-PDF refusé (415)", st == 415, d.get("code"))
st, _ = get_url(f"https://stdocsct26.blob.core.windows.net/documents/{doc.get('document_id')}.pdf")
check("Accès anonyme direct au Blob refusé", st in (403, 404, 409), f"HTTP {st}")

st, d = call("POST", "credentials", {"subject": {"holder_email": STUDENT, "full_name": "Etudiant Demo",
                                                  "credential_name": "Master Cloud Computing",
                                                  "credential_type_label": "Master"},
                                      "document_id": doc.get("document_id")}, user=STAFF)
vc, jwt = d.get("credential", {}), d.get("jwt")
cid = (vc.get("id") or "").split(":")[-1]
check("Émission avec PDF associé (201)", st == 201,
      f"archive={d.get('archive_reference')} pdf={d.get('document_reference')}")
check("Empreinte du PDF inscrite dans le credential signé",
      (vc.get("credentialSchema") or {}).get("documentHash") == doc.get("content_hash"))
check("Clé de signature = version courante (après rotation)",
      "458eda32abf940cb9d4e3aa0c333c44c" in (vc.get("proof") or {}).get("verificationMethod", ""),
      (vc.get("proof") or {}).get("verificationMethod", "")[-34:])
st, d = call("POST", "credentials", {"subject": {"holder_email": STUDENT, "full_name": "X", "credential_name": "Y",
                                                  "credential_type_label": "Master"},
                                      "document_id": doc.get("document_id")}, user=STAFF)
check("Même PDF refusé pour un 2e credential (409)", st == 409, d.get("code"))
st, d = call("GET", f"documents/{doc.get('document_id')}/link", user=STUDENT)
url = d.get("url", "")
check("Lien SAS temporaire pour le titulaire", st == 200 and "sig=" in url, f"expire dans {d.get('expires_in_minutes')} min")
st2, body = get_url(url) if url else (0, b"")
check("Téléchargement via SAS = PDF original intact", st2 == 200 and hashlib.sha256(body).hexdigest() == doc.get("content_hash"))
st, d = call("GET", f"documents/{doc.get('document_id')}/link", user="inconnu@exemple.com")
check("Lien refusé pour un inconnu (403)", st == 403, d.get("code"))

print("\n=== PHASE 5 : portefeuille et partage contrôlé")
st, d = call("GET", "wallet", user=STUDENT)
check("Portefeuille étudiant", st == 200 and any(i["record"]["credential_id"].endswith(cid) for i in d.get("credentials", [])),
      f"{d.get('count')} credential(s)")
st, d = call("GET", f"wallet?holder_email={STUDENT}", user="inconnu@exemple.com")
check("Portefeuille d'autrui refusé (403)", st == 403)
st, d = call("POST", f"credentials/{cid}/share", {"expires_in_minutes": 60}, user=STUDENT)
token, share = d.get("token"), d.get("share", {})
check("Lien de partage créé (jeton 256 bits, 60 min)", st == 201 and token, d.get("share_url"))
st, d = call("POST", "shares/resolve", {"token": token})
check("Vérificateur : lien valide -> Valid", st == 200 and d.get("verification", {}).get("result") == "Valid",
      f"PDF joint={'oui' if d.get('document_url') else 'non'}")
st, d = call("POST", "shares/resolve", {"token": token[:-4] + "AAAA"})
check("Jeton modifié -> inconnu (404)", st == 404)
st, d = call("POST", f"shares/{share.get('share_id')}/revoke", {"credential_id": cid}, user=STUDENT)
check("Titulaire retire le partage", st == 200)
st, d = call("POST", "shares/resolve", {"token": token})
check("Lien retiré -> 410", st == 410, d.get("code"))

print("\n=== PHASE 6 : sécurité et pannes partielles")
t = copy.deepcopy(vc)
t["credentialSubject"]["name"] = "Fraudeur"
st, d = call("POST", "credentials/verify", {"credential": t})
check("Credential falsifié -> Invalid", d.get("status") == "Invalid" or d.get("result") == "Invalid", d.get("reason"))
p = jwt.split(".")
pl = json.loads(base64.urlsafe_b64decode(p[1] + "=="))
pl["credentialSubject"]["name"] = "Fraudeur"
fake = p[0] + "." + base64.urlsafe_b64encode(json.dumps(pl).encode()).decode().rstrip("=") + "." + p[2]
st, d = call("POST", "credentials/verify", {"jwt": fake})
check("JWT falsifié (contenu modifié) -> Invalid", (d.get("status") or d.get("result")) == "Invalid", d.get("reason"))

base = {"subject": {"holder_email": STUDENT, "full_name": "Etudiant Demo", "credential_name": "Certificate Azure",
                    "credential_type_label": "Certificate"}}
st, d = call("POST", "credentials", base, user=STAFF, headers={"X-CertiChain-Simulate-Failure": "blob"})
check("Panne Blob simulée -> NOT_ISSUED (503)", st == 503 and d.get("state") == "NOT_ISSUED", d.get("error"))
lost = (d.get("credential_id") or "").split(":")[-1]
st, d = call("GET", f"credentials/{lost}")
check("... et rien dans le registre", st == 404)
st, d = call("POST", "credentials", base, user=STAFF, headers={"X-CertiChain-Simulate-Failure": "sql"})
pend = (d.get("credential_id") or "").split(":")[-1]
check("Panne SQL simulée -> PENDING_RECONCILIATION (503)", st == 503 and d.get("state") == "PENDING_RECONCILIATION", pend)
st, d = call("GET", f"credentials/{pend}")
check("... credential archivé mais absent du registre", st == 404)
st, d = call("POST", "maintenance/reconcile", {}, user=STAFF, admin=True)
check("Réconciliation refusée à la scolarité (403)", st == 403)
st, d = call("POST", "maintenance/reconcile", {}, user=ADMIN, admin=True)
check("Réconciliation par l'administrateur", st == 200 and any(r.endswith(pend) for r in d.get("recovered", [])),
      f"vérifiés={d.get('checked')} récupérés={len(d.get('recovered', []))}")
st, d = call("GET", f"credentials/{pend}")
check("... credential désormais enregistré (actif)", st == 200 and (d.get("credential") or {}).get("status") == "active")
st, d = call("POST", f"credentials/{cid}/revoke", {"reason": "test de révocation"}, user=ADMIN)
check("Révocation par l'administrateur", st == 200)
st, d = call("POST", "credentials/verify", {"jwt": jwt})
check("Credential révoqué -> Revoked", (d.get("status") or d.get("result")) == "Revoked", d.get("reason"))
st, d = call("GET", "issuers/uir")
keys = (d.get("issuer") or d).get("keys", [])
check("Registre des clés : 1 active, anciennes retirées",
      sum(k.get("status") == "active" for k in keys) == 1, ", ".join(k["key_id"][-8:] + ":" + k["status"] for k in keys))
st, d = call("GET", "security/events?limit=50", admin=True)
check("Journal de sécurité (ledger append-only)", st == 200, f"{d.get('count')} événements")
print(f"\nRÉSULTAT : {ok_count[0]} OK / {ok_count[1]} KO")
