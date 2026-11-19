-- =====================================================================
-- CertiChain — Phase 3 : registre de confiance & cycle de vie
-- =====================================================================
-- Le schéma est celui créé par Rihab dans certichain-db (tables LEDGER) :
--   dbo.Issuers, dbo.IssuerEvents, dbo.Credentials, dbo.CredentialEvents,
--   dbo.Users, dbo.Roles, dbo.UserRoles  (+ tables d'historique ledger)
-- L'API (credential_engine/sql_ledger.py) s'y branche SANS le modifier.
--
-- Correspondances moteur <-> registre :
--   credential : active=ISSUED, suspended=SUSPENDED, revoked=REVOKED, expired=EXPIRED
--   émetteur   : trusted=ACTIVE, suspended=SUSPENDED, pending=PENDING, deactivated=DEACTIVATED
--   Issuers.engine_issuer_id      = issuer_id du moteur (ex. 'uir')
--   Issuers.public_key_id/_jwk    = clé publique Key Vault (rattachée au démarrage)
--   Credentials.credential_reference = id du VC (urn:uuid:...)
--   CredentialEvents.details      = empreinte SHA-256 du VC (à l'émission) ou motif
--
-- Accès de l'API : identité managée func-certichain-ct26
--   (db_datareader, db_datawriter, certichain_app_role), sans mot de passe.
--
-- Vérifier l'intégrité / la traçabilité :
SELECT e.event_type, e.new_status, e.actor_id, t.transaction_id, t.principal_name, t.commit_time
FROM dbo.CredentialEvents e
JOIN sys.database_ledger_transactions t ON t.transaction_id = e.ledger_start_transaction_id
ORDER BY e.event_time;
