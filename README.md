# CertiChain — Diplômes numériques vérifiables sur Azure

Plateforme cloud pour **émettre, détenir, partager et vérifier** des diplômes académiques
numériques. Une université signe un credential, l'étudiant le garde dans son portefeuille et
le partage par lien ou QR code, et un recruteur vérifie seul son **origine**, son **intégrité**
et son **statut** (actif, révoqué ou expiré).

Projet Cloud Computing, ING4 CYB, UIR, novembre 2026.

| Partie | Responsable | Contenu |
|---|---|---|
| 1. Fondation cloud | Ines Bouzekri | Groupe de ressources, 5 services Azure, Managed Identity, RBAC |
| 2. Moteur de credentials | Mona Azzaoui | Modèle W3C VC, SHA-256, signature ES256 par Key Vault, vérification |
| 3. Registre de confiance et cycle de vie | Rihab Chahir, avec Mona | Azure SQL Ledger : émetteurs, credentials, événements, révocation |
| 4. Stockage sécurisé des documents | Mona | Blob privé, WORM, SAS courts, émission orchestrée |
| 5. Portails et partage | Mona | Application Flask : université, portefeuille étudiant, vérificateur, QR code |
| 6. Intégration, tests et sécurité | Mona | 64 tests unitaires, 32 vérifications en ligne |

> **Ce n'est pas une blockchain.** Le registre est une base Azure SQL avec des **tables Ledger**,
> c'est-à-dire un historique où toute modification est détectable, sans réseau décentralisé.

---

## 1. Architecture

```
 Navigateur (université / étudiant / recruteur)
        │  HTTPS uniquement (TLS 1.2 minimum)
        ▼
 Azure App Service ── app-certichain-ct26 ── portail Flask (portal/)
        │  HTTPS + clé de fonction (stockée dans Key Vault) + en-tête X-CertiChain-User
        ▼
 Azure Functions ─── func-certichain-ct26 ── API (function_app.py + credential_engine/)
        │  Managed Identity : aucun mot de passe ni clé dans le code
        ├──► Azure Key Vault      kv-certichain-ct26   clé EC P-256 non exportable, signature ES256
        ├──► Azure SQL (Ledger)   sql-certichain-ct26 / certichain-db
        └──► Azure Blob Storage   stdocsct26           conteneurs privés documents + credentials (WORM)
 Supervision : Application Insights (Function App et portail)
```

Région : **Italy North**. Groupe de ressources : **rg-certichain-ct26**.

| Service | Rôle | Accès accordé à l'identité managée |
|---|---|---|
| App Service | Héberge le portail Flask | Key Vault Secrets User (secrets du portail par références Key Vault) |
| Functions (Flex Consumption, Python 3.11) | Toute la logique métier et l'API | Key Vault Crypto User, Storage Blob Data Contributor, utilisateur SQL Entra |
| Key Vault | Clé de signature, secrets du portail | — |
| Blob Storage | PDF originaux et credentials archivés | — |
| SQL Database avec Ledger | Émetteurs, clés, credentials, événements, documents, partages | — |

Le navigateur ne touche **jamais** la clé privée, la base de données ni le stockage privé.

---

## 2. Arborescence

```
.
├── function_app.py            # API Azure Functions (tous les endpoints)
├── host.json                  # configuration Functions
├── requirements.txt           # dépendances de l'API
├── requirements-dev.txt       # dépendances pour les tests et la démo
├── local.settings.json.example
├── demo.py                    # démo de bout en bout, sans Azure
├── credential_engine/         # le moteur (package Python)
│   ├── models.py              # modèle de credential aligné W3C VC
│   ├── canonical.py           # canonicalisation déterministe
│   ├── hashing.py             # SHA-256
│   ├── signing.py             # signataire local et vérification ES256
│   ├── keyvault_signer.py     # signataire Azure Key Vault (avec gestion de la rotation)
│   ├── issuer_registry.py     # registre des émetteurs de confiance
│   ├── status_store.py        # statut et révocation
│   ├── lifecycle.py           # cycle de vie, rôles, permissions (version en mémoire)
│   ├── sql_ledger.py          # même interface, adossée à Azure SQL Ledger
│   ├── storage.py             # stockage Blob : contrôle des PDF, archivage, liens SAS
│   ├── issuance.py            # émission orchestrée et réconciliation
│   ├── engine.py              # émettre / vérifier / révoquer
│   └── errors.py
├── portal/                    # portail web Flask (App Service)
│   ├── app.py
│   ├── requirements.txt
│   ├── templates/             # accueil, connexion, université, portefeuille, vérification…
│   └── static/style.css
├── sql/                       # scripts de schéma, à exécuter dans l'ordre (section 5)
├── tests/                     # 64 tests unitaires (pytest)
├── scripts/                   # tests en ligne contre l'API déployée
├── docs/  functions/  web/    # dossiers de la structure initiale (vides)
└── .env.example
```

Les dossiers `functions/` et `web/` de la structure initiale sont vides. En effet, Azure Functions
exige `function_app.py` et `host.json` **à la racine** du paquet déployé, et le portail se trouve
dans `portal/`.

---

## 3. Lancer en local, sans Azure

```bash
pip install -r requirements-dev.txt
python -m pytest -q        # 64 tests attendus
python demo.py             # Valid → Invalid → Issuer Not Trusted → Revoked → Expired
```

Sans `CERTICHAIN_KEYVAULT_URL`, le moteur utilise une clé logicielle locale (`keys/`, ignoré par
Git) et un registre en mémoire.

Pour lancer l'API et le portail ensemble :

```bash
cp local.settings.json.example local.settings.json
func start                                   # API sur http://localhost:7071/api
cd portal && pip install -r requirements.txt
CERTICHAIN_API_BASE=http://localhost:7071/api DEMO_PASSWORD=<choisir> flask --app app run
```

---

## 4. Configuration : variables d'application

**Ne jamais committer de secret.** En production, les secrets sont dans Key Vault et l'App Service
les lit par **références Key Vault**.

### Function App (`func-certichain-ct26`)

| Variable | Exemple ou valeur | Rôle |
|---|---|---|
| `CERTICHAIN_KEYVAULT_URL` | `https://kv-certichain-ct26.vault.azure.net/` | Active la signature par Key Vault |
| `CERTICHAIN_KEY_NAME` | `certichain-issuer-key` | Clé EC P-256 |
| `CERTICHAIN_ISSUER_ID` / `_NAME` / `_IDENTIFIER` | `uir` / `Université Internationale de Rabat` / `uir.ac.ma` | Identité de l'émetteur |
| `CERTICHAIN_SQL_SERVER` | `sql-certichain-ct26.database.windows.net` | Active le registre SQL Ledger |
| `CERTICHAIN_SQL_DATABASE` | `certichain-db` | |
| `CERTICHAIN_BLOB_ACCOUNT_URL` | `https://stdocsct26.blob.core.windows.net` | Active le stockage Blob |
| `CERTICHAIN_PORTAL_URL` | URL de l'App Service | Sert à construire les liens de partage |
| `CERTICHAIN_ALLOW_FAULT_INJECTION` | `0` (mettre `1` **uniquement** pendant les tests de panne) | Simulation de panne partielle |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | fournie par Azure | Supervision |

### Portail (`app-certichain-ct26`)

| Variable | Valeur | Rôle |
|---|---|---|
| `CERTICHAIN_API_BASE` | `https://<function-app>/api` | Adresse de l'API |
| `CERTICHAIN_API_KEY` | `@Microsoft.KeyVault(VaultName=kv-certichain-ct26;SecretName=portal-api-key)` | Clé de fonction |
| `FLASK_SECRET_KEY` | `@Microsoft.KeyVault(...;SecretName=portal-flask-secret)` | Signature des sessions |
| `DEMO_PASSWORD` | `@Microsoft.KeyVault(...;SecretName=portal-demo-password)` | Mot de passe des comptes de démo |
| `APPLICATIONINSIGHTS_CONNECTION_STRING`, `ApplicationInsightsAgent_EXTENSION_VERSION=~3` | | Supervision |
| Commande de démarrage | `gunicorn --bind=0.0.0.0 --timeout 120 app:app` | |

---

## 5. Déploiement sur Azure (résumé)

1. **Ressources (Partie 1)** : groupe de ressources, Function App, App Service, Key Vault, SQL
   (avec Ledger), Storage. Activer l'**identité managée** des deux applications.
2. **Clé de signature** :
   `az keyvault key create --vault-name kv-certichain-ct26 -n certichain-issuer-key --kty EC --curve P-256 --ops sign verify`
3. **Rôles RBAC** pour l'identité de la Function App : *Key Vault Crypto User* sur le Key Vault et
   *Storage Blob Data Contributor* sur `stdocsct26`. Pour l'identité du portail :
   *Key Vault Secrets User*.
4. **Base de données** : exécuter dans `certichain-db`, **dans cet ordre** :
   `sql/issuer_schema.sql` → `sql/phase3_ledger_schema.sql` → `sql/finalisation_schema.sql`
   → `sql/phase4_5_schema.sql`, puis créer l'utilisateur Entra de la Function App :
   `CREATE USER [func-certichain-ct26] FROM EXTERNAL PROVIDER;` et lui donner les rôles
   `db_datareader` et `db_datawriter`.
5. **Stockage** : conteneurs privés `documents` et `credentials`, avec une politique
   d'immutabilité (WORM) de 7 jours. **Ne pas la verrouiller** pendant le projet : une politique
   verrouillée empêche de supprimer les données avant la fin de la rétention.
6. **API** :
   `az functionapp deployment source config-zip -g rg-certichain-ct26 -n func-certichain-ct26 --src api.zip --build-remote true`
7. **Portail** (depuis `portal/`) : `az webapp deploy -g rg-certichain-ct26 -n app-certichain-ct26 --src-path portal.zip --type zip`
   avec `SCM_DO_BUILD_DURING_DEPLOYMENT=true`.

---

## 6. API (Azure Functions)

Base : `https://<function-app>/api`. Chaque appel exige la **clé de fonction**
(`x-functions-key`). Les routes d'administration exigent la **clé admin**. L'utilisateur
connecté est transmis dans l'en-tête `X-CertiChain-User`. Le backend vérifie son rôle en base et
**ne fait jamais confiance** aux métadonnées envoyées par le client.

| Méthode | Route | Rôle | Qui |
|---|---|---|---|
| POST | `/credentials` | Émettre et signer un credential (PDF joint en option) | Administrateur, personnel université |
| POST | `/credentials/verify` | Vérifier un credential (JSON ou `vc+jwt`) | Tous |
| GET | `/credentials/{id}` | Métadonnées autorisées | Propriétaire, personnel |
| GET / POST | `/credentials/{id}/status` | Lire / changer le statut (suspension…) | Personnel |
| POST | `/credentials/{id}/revoke` | Révoquer avec un motif | Personnel |
| GET | `/credentials/{id}/history` | Historique des événements | Personnel |
| GET | `/issuers`, `/issuers/{id}` | Émetteurs de confiance et clés publiques | Tous |
| POST | `/issuers`, `/issuers/{id}/status` | Gérer les émetteurs | **Admin** |
| GET | `/issuers/{id}/history` | Historique de l'émetteur (rotations de clé…) | Tous |
| GET | `/security/events` | Journal des événements de sécurité | **Admin** |
| GET | `/me` | Utilisateur courant et ses rôles | Connecté |
| POST | `/documents` | Déposer un PDF (5 Mo maximum, PDF uniquement) | Personnel |
| GET | `/documents/{id}`, `/documents/{id}/link` | Métadonnées / lien SAS lecture seule (15 min maximum) | Propriétaire, personnel |
| GET | `/wallet` | Portefeuille de l'étudiant | Étudiant (ou personnel avec `?holder_email=`) |
| POST | `/credentials/{id}/share` | Créer un lien de partage limité dans le temps | Propriétaire |
| GET | `/credentials/{id}/shares` | Lister les partages | Propriétaire |
| POST | `/shares/{share_id}/revoke` | Révoquer un partage | Propriétaire |
| POST | `/shares/resolve` | Ouvrir un lien partagé et vérifier | Public (avec le jeton) |
| POST | `/maintenance/reconcile` | Réconcilier après une panne partielle | **Admin** |

**Résultats de vérification** : `Valid`, `Invalid`, `Revoked`, `Expired`, `Issuer Not Trusted`,
avec le détail des contrôles (`structure`, `issuer_known`, `issuer_trusted`, `signature`, `not_expired`, `registered`, `status`).

Exemple d'émission :

```json
POST /api/credentials
{
  "subject": {
    "holder_email": "etudiant@uir.ac.ma",
    "full_name": "Étudiant Démo",
    "credential_name": "Licence en Génie Informatique",
    "credential_type_label": "Bachelor"
  },
  "expires_at": "2032-01-01T00:00:00Z",
  "document_id": "<optionnel, renvoyé par POST /api/documents>"
}
```

---

## 7. Portail web

URL : `https://app-certichain-ct26-d7edh6dqbkdnfrbg.italynorth-01.azurewebsites.net`

| Espace | Page | Fonctions |
|---|---|---|
| Université | `/issuer` | Émettre (avec PDF), suspendre, révoquer |
| Étudiant | `/wallet` | Voir ses diplômes, télécharger, créer ou révoquer un lien de partage et son QR code |
| Recruteur | `/verify`, `/v/<jeton>` | Coller un credential ou ouvrir un lien partagé, voir le résultat |

Comptes de démo (données fictives) : `admin@uir.ac.ma` (administrateur),
`scolarite@uir.ac.ma` (personnel université), `etudiant@uir.ac.ma` (étudiant). Le mot de passe
de démo est dans Key Vault (`portal-demo-password`) et **n'est pas dans le dépôt**.

Sécurité du portail : jeton CSRF sur chaque formulaire, cookies `Secure`, en-têtes CSP,
`X-Frame-Options` et `Referrer-Policy: no-referrer`. Seule l'empreinte SHA-256 des jetons de
partage (256 bits) est stockée.

---

## 8. Sécurité : ce qui est en place

| Principe (concept §8) | Mise en œuvre |
|---|---|
| Moindre privilège | Une identité managée par application, avec un rôle RBAC par service |
| Protection de la clé | Clé EC P-256 **non exportable** dans Key Vault ; le code demande une signature |
| Vérification par clé publique | ES256 vérifié avec la JWK publique de l'émetteur |
| Émetteur de confiance | Une signature valide ne suffit pas : l'émetteur et la clé doivent être reconnus et actifs |
| Rotation de clé | Ancienne clé `RETIRED`, toujours vérifiable pour les anciens credentials ; resynchronisation automatique |
| Registre infalsifiable | Tables Ledger (modifiables et en ajout seul) ; empreintes conservées dans `sqldbledgerdigests` |
| Stockage privé | Conteneurs privés, WORM 7 jours, liens SAS par délégation utilisateur en lecture seule |
| Transport | HTTPS obligatoire (redirection 301), TLS 1.2 minimum, FTP désactivé |
| Traçabilité | Table `SecurityEvents` (refus d'accès, rotation, réconciliation…) et Application Insights |
| Validation des entrées | Type, taille et signature `%PDF-` des fichiers ; champs obligatoires ; permission par type de credential |
| Pannes partielles | États `NOT_ISSUED` et `PENDING_RECONCILIATION`, puis `/maintenance/reconcile` |
| Minimisation des données | Le registre ne contient ni PDF, ni mot de passe, ni clé privée |

---

## 9. Tests

```bash
python -m pytest -q                              # 64 tests unitaires
python scripts/online_tests_finalisation.py HOTE CLE_FONCTION CLE_ADMIN admin@uir.ac.ma scolarite@uir.ac.ma etudiant@uir.ac.ma
python scripts/online_tests_phases_4_6.py HOTE CLE_FONCTION CLE_ADMIN      # 32 vérifications
```

Les clés sont passées en arguments au moment de l'exécution (par exemple depuis Cloud Shell avec
`az functionapp keys list`). Aucune clé n'est écrite dans le code.

Scénarios du concept (§14), tous validés : émission, vérification authentique, credential
modifié, émetteur inconnu, credential révoqué, émission ou révocation non autorisée, panne
partielle.

---

## 10. Limites connues (périmètre de la première version, concept §16)

- **Authentification de démo** : connexion par mot de passe partagé, sans Microsoft Entra ID.
  Évolution : connexion Entra ID (OpenID Connect) sur App Service.
- **Une seule université** émettrice ; pas de fédération entre établissements.
- **Pas de divulgation sélective** : l'étudiant partage le credential complet.
- **Format de preuve** : W3C VC avec VC-JOSE (`vc+jwt`, ES256). Ce n'est pas une suite Data
  Integrity certifiée.
- **Authenticité ≠ vérité** : la signature prouve *qui* a signé et que rien n'a changé, pas que
  les notes saisies sont exactes.

## 11. Avant et après la démo

- La base SQL se met en **pause automatique**. Faire un premier appel 2 à 5 minutes avant la démo.
- Après l'évaluation, supprimer le groupe de ressources `rg-certichain-ct26` pour arrêter les coûts.
