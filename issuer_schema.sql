-- =====================================================================
-- CertiChain — Métadonnées émetteur / clé (Phase 2, Azure SQL)
-- =====================================================================
-- La Phase 2 lit les émetteurs de confiance et leurs clés PUBLIQUES ici.
-- AUCUNE clé privée n'est stockée (elle reste dans Azure Key Vault).
-- La gestion du cycle de vie et l'historique infalsifiable (ledger)
-- relèvent de la Phase 3.

IF OBJECT_ID('dbo.Issuer', 'U') IS NULL
CREATE TABLE dbo.Issuer (
    issuer_id       NVARCHAR(64)   NOT NULL PRIMARY KEY,
    name            NVARCHAR(256)  NOT NULL,
    identifier      NVARCHAR(256)  NOT NULL,   -- ex. domaine officiel
    status          NVARCHAR(32)   NOT NULL DEFAULT 'trusted',  -- trusted | suspended
    public_key_id   NVARCHAR(256)  NOT NULL,   -- kid / URL de la clé Key Vault
    public_jwk      NVARCHAR(MAX)  NOT NULL,   -- clé publique (JSON JWK EC P-256)
    created_at      DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME()
);

-- Exemple d'insertion (clé publique à récupérer depuis Key Vault) :
-- INSERT INTO dbo.Issuer (issuer_id, name, identifier, public_key_id, public_jwk)
-- VALUES ('uir', N'Université Internationale de Rabat', 'uir.ac.ma',
--         'certichain-issuer-key',
--         N'{"kty":"EC","crv":"P-256","x":"...","y":"...","kid":"certichain-issuer-key"}');
