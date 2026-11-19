# CertiChain — Credential Engine (Phase 2)

**Ma partie du projet CertiChain : le moteur de credentials.**
Mona Azzaoui — Cloud Computing (ING4 CYB, UIR) — Novembre 2026.

> Partie 1 (fondation cloud) : Ines · Autres parties : Rihab · **Phase 2 (ce module) : Mona.**

Ce module est le **cœur cryptographique** de CertiChain : il crée des credentials
académiques structurés, les **signe** (Azure Key Vault), et les **vérifie** avec la
clé publique de l'émetteur. Il expose les endpoints `POST /api/credentials`,
`POST /api/credentials/verify` et `GET /api/issuers/{id}`.

---

## 1. Ce que couvre la Phase 2 (d'après le concept)

| Exigence du concept (§10–§12) | Où c'est implémenté |
|---|---|
| Définir le modèle de credential (aligné W3C VC) | `credential_engine/models.py` |
| Hachage SHA-256 | `credential_engine/hashing.py` |
| Canonicalisation déterministe (octets à signer) | `credential_engine/canonical.py` |
| Signature ECDSA P-256 / ES256 via **Key Vault** | `credential_engine/keyvault_signer.py` |
| Signataire logiciel (tests/démo) | `credential_engine/signing.py` |
| Vérification par **clé publique** | `credential_engine/signing.py` + `engine.py` |
| Registre de confiance des émetteurs (issuer trust) | `credential_engine/issuer_registry.py` |
| Statut / révocation (pour la vérification) | `credential_engine/status_store.py` |
| Moteur : issue / verify / revoke | `credential_engine/engine.py` |
| API Azure Functions (3 endpoints Phase 2) | `function_app.py` |
| Tests unitaires | `tests/` (32 tests) |
| Métadonnées émetteur/clé en Azure SQL | `sql/issuer_schema.sql` + `SqlIssuerRegistry` |

---

## 2. Idée centrale (à savoir expliquer en soutenance)

1. On construit un credential structuré (JSON type W3C).
2. On en calcule une **empreinte SHA-256** sur une forme **canonique** (clés triées,
   sans le champ `proof`). Même credential ⇒ mêmes octets ⇒ même empreinte.
3. On **signe l'empreinte** avec la clé **privée** ECDSA P-256 de l'université.
   En production, la clé privée est **non exportable** et vit dans **Azure Key Vault** :
   le code demande une signature, il ne voit jamais la clé.
4. Le vérificateur recalcule l'empreinte et vérifie la signature avec la **clé publique**.
   - Signature invalide ⇒ **le credential a été modifié** (`Invalid`).
5. **Une signature valide ne suffit pas** : on vérifie aussi que l'**émetteur est reconnu**
   (registre de confiance), sinon n'importe qui pourrait signer avec sa propre clé
   (`Issuer Not Trusted`).
6. On vérifie enfin l'**expiration** et le **statut de révocation** (`Expired`, `Revoked`).

> **Authenticité ≠ vérité** (concept §9) : la crypto prouve *qui* a signé et que rien
> n'a changé, pas que les notes saisies sont exactes. La gouvernance de l'émetteur reste
> nécessaire.

---

## 3. Lancer en local (sans Azure)

```bash
# 1) dépendances (tests/démo)
pip install -r requirements-dev.txt

# 2) la démo complète (tous les scénarios de la Definition of Done)
python demo.py

# 3) les tests unitaires
python -m pytest -q
```

Résultats attendus : **32 tests passés**, et la démo affiche
`Valid → Invalid → Issuer Not Trusted → Revoked → Expired`.

---

## 4. Les endpoints (API Azure Functions)

| Méthode | Route | Rôle |
|---|---|---|
| `POST` | `/api/credentials` | Émettre et signer un credential |
| `POST` | `/api/credentials/verify` | Vérifier un credential |
| `GET`  | `/api/issuers/{id}` | Infos publiques + clé publique d'un émetteur |

**Émettre** — corps de la requête :
```json
{
  "subject": {
    "holder_id": "stu-2026-001",
    "full_name": "Mona Azzaoui",
    "credential_name": "Licence en Génie Informatique",
    "credential_type_label": "Degree"
  },
  "expires_at": "2032-01-01T00:00:00Z"
}
```
Réponse : `201` avec `{ "credential": { ...VC signé... } }`.

**Vérifier** — corps : `{ "credential": { ...VC... } }` →
`{ "result": "Valid|Invalid|Revoked|Expired|Issuer Not Trusted", "valid": true/false, ... }`.

---

## 5. Brancher Azure (Key Vault + SQL)

Le moteur bascule automatiquement selon les variables d'environnement
(App Settings de la Function App). Sans `CERTICHAIN_KEYVAULT_URL`, il reste en mode local.

### 5.1 Créer la clé dans Key Vault (clé non exportable)
```bash
az keyvault key create \
  --vault-name kv-certichain-ct26 \
  --name certichain-issuer-key \
  --kty EC --curve P-256 --ops sign verify
```

### 5.2 Donner à la Function App l'accès à Key Vault (Managed Identity)
```bash
# activer l'identité managée de la Function App
az functionapp identity assign -g rg-certichain-ct26 -n func-certichain-ct26

# rôle "Key Vault Crypto User" sur le Key Vault
az role assignment create \
  --assignee <principalId-de-la-FunctionApp> \
  --role "Key Vault Crypto User" \
  --scope <resourceId-du-KeyVault>
```

### 5.3 Variables d'application (Function App → Configuration)
```
CERTICHAIN_KEYVAULT_URL      = https://kv-certichain-ct26.vault.azure.net/
CERTICHAIN_KEY_NAME          = certichain-issuer-key
CERTICHAIN_ISSUER_ID         = uir
CERTICHAIN_ISSUER_NAME       = Université Internationale de Rabat
CERTICHAIN_ISSUER_IDENTIFIER = uir.ac.ma
CERTICHAIN_SQL_SERVER        = sql-certichain-ct26      (Phase 3 : registre SQL Ledger)
CERTICHAIN_SQL_DATABASE      = certichain-db
```

### 5.4 Base SQL (métadonnées émetteur/clé)
Les métadonnées émetteur/clé sont dans le registre de la Phase 3 (table Ledger
`dbo.Issuers` de `certichain-db`, schéma de Rihab). Au démarrage, l'API rattache
automatiquement la clé **publique** active du Key Vault à l'émetteur `uir`
(colonnes `public_key_id`, `public_jwk`). Aucune clé privée en base. Connexion par
identité managée, sans mot de passe (voir `sql/phase3_ledger_schema.sql`).

### 5.5 Déployer la Function App
```bash
# depuis la racine du projet (là où se trouve host.json)
func azure functionapp publish func-certichain-ct26
```

---

## 6. Conformité W3C — mise au point honnête (concept §9)

Reprendre les champs du modèle W3C VC **ne rend pas** automatiquement l'implémentation
« conforme ». Ici, la preuve est une **signature ES256** (ECDSA P-256 + SHA-256) sur une
**canonicalisation JSON déterministe** (proche de JCS / RFC 8785), documentée et
cohérente émission ↔ vérification. C'est volontairement simple et vérifiable pour le
périmètre du projet ; ce n'est **pas** une suite de preuve W3C certifiée (ex. Data
Integrity `ecdsa-rdfc-2019`). Évolution possible : adopter une suite normalisée.

Pour que ce soit explicite, chaque preuve déclare son format :
`"proofFormat": "certichain-es256-canonical-json/v1"`. Le champ est dans `proof`,
donc hors de l'empreinte signée : il documente le mécanisme sans changer la signature.

---

## 7. Frontières avec les autres phases (pour l'intégration d'équipe)

- **Phase 1 (Ines)** : ressources Azure, Managed Identity, RBAC. Ce moteur **consomme**
  Key Vault et SQL fournis par la Phase 1.
- **Phase 3 (registre de confiance & cycle de vie)** : persistance des émetteurs, des
  événements d'émission/révocation et l'**historique infalsifiable** (Azure SQL Ledger).
  Ici, `InMemoryStatusStore` sert à rendre la démo autonome ; il suffira de fournir une
  implémentation `StatusStore` / `IssuerRegistry` adossée à SQL Ledger (mêmes interfaces).
- **Phase 5 (portails)** : les portails appellent ces endpoints. Le contrat d'API est la
  section 4.

> **Contrat d'API à valider avec l'équipe avant intégration** (concept §11.4, §12).

---

## 8. Arborescence

```
certichain-credential-engine/
├── credential_engine/        # le moteur (package Python)
│   ├── models.py             # modèle de credential (W3C-aligné)
│   ├── canonical.py          # canonicalisation déterministe
│   ├── hashing.py            # SHA-256
│   ├── signing.py            # interface Signer + signataire LOCAL + vérification
│   ├── keyvault_signer.py    # signataire Azure Key Vault (ES256, clé non exportable)
│   ├── issuer_registry.py    # registre de confiance (in-memory + SQL)
│   ├── status_store.py       # statut / révocation
│   ├── engine.py             # issue / verify / revoke / issuer-info
│   └── errors.py
├── function_app.py           # API Azure Functions (3 endpoints Phase 2)
├── host.json                 # config Functions
├── requirements.txt          # dépendances de l'API (déploiement)
├── requirements-dev.txt      # dépendances tests/démo
├── local.settings.json.example
├── demo.py                   # démonstration end-to-end (sans Azure)
├── sql/issuer_schema.sql     # table émetteur/clé (Azure SQL)
├── keys/                     # clés locales (ignorées par Git)
└── tests/                    # 32 tests unitaires (pytest)
```
