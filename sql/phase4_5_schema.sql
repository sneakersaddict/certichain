-- CertiChain — Phases 4 et 5 : documents archivés et partages contrôlés (tables LEDGER)
-- Le PDF lui-même n'est JAMAIS dans la base : seulement sa référence Blob et son empreinte.
IF OBJECT_ID('dbo.Documents') IS NULL
CREATE TABLE dbo.Documents (
    document_id        UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    credential_id      UNIQUEIDENTIFIER NULL REFERENCES dbo.Credentials(credential_id),
    blob_reference     NVARCHAR(400)  NOT NULL,
    content_hash       CHAR(64)       NOT NULL,
    media_type         NVARCHAR(100)  NOT NULL,
    size_bytes         BIGINT         NOT NULL,
    original_name      NVARCHAR(200)  NULL,
    retention_metadata NVARCHAR(400)  NULL,
    status             NVARCHAR(20)   NOT NULL CHECK (status IN ('UPLOADED','LINKED')),
    uploaded_by        NVARCHAR(400)  NULL,
    created_at         DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME(),
    updated_at         DATETIME2      NULL
) WITH (SYSTEM_VERSIONING = ON, LEDGER = ON);
GO
IF OBJECT_ID('dbo.CredentialShares') IS NULL
CREATE TABLE dbo.CredentialShares (
    share_id          UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    credential_id     UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.Credentials(credential_id),
    token_hash        CHAR(64)       NOT NULL UNIQUE,      -- SHA-256 du jeton, jamais le jeton
    created_by        NVARCHAR(400)  NOT NULL,
    created_at        DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME(),
    expires_at        DATETIME2      NOT NULL,
    revoked           BIT            NOT NULL DEFAULT 0,
    revoked_at        DATETIME2      NULL,
    access_count      INT            NOT NULL DEFAULT 0,
    last_accessed_at  DATETIME2      NULL
) WITH (SYSTEM_VERSIONING = ON, LEDGER = ON);
GO
SELECT name, ledger_type_desc FROM sys.tables WHERE name IN ('Documents','CredentialShares');
SELECT c.name, t.name AS type FROM sys.columns c JOIN sys.types t ON t.user_type_id=c.user_type_id
 WHERE c.object_id = OBJECT_ID('dbo.Credentials') AND c.name IN ('credential_id','holder_reference','document_reference');
