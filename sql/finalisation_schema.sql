-- CertiChain — finalisation Parties 2 & 3 (concept §7.1, §9, §12)
-- Tables ledger ajoutées au schéma de Rihab : historique des clés, types autorisés, journal sécurité.
IF OBJECT_ID('dbo.IssuerKeys') IS NULL
CREATE TABLE dbo.IssuerKeys (
    key_id        NVARCHAR(400)    NOT NULL PRIMARY KEY,
    issuer_id     UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.Issuers(issuer_id),
    public_jwk    NVARCHAR(MAX)    NOT NULL,
    status        NVARCHAR(20)     NOT NULL CHECK (status IN ('ACTIVE','RETIRED','COMPROMISED')),
    activated_at  DATETIME2        NOT NULL DEFAULT SYSUTCDATETIME(),
    retired_at    DATETIME2        NULL
) WITH (SYSTEM_VERSIONING = ON, LEDGER = ON);
GO
IF OBJECT_ID('dbo.IssuerCredentialTypes') IS NULL
CREATE TABLE dbo.IssuerCredentialTypes (
    issuer_id       UNIQUEIDENTIFIER NOT NULL REFERENCES dbo.Issuers(issuer_id),
    credential_type NVARCHAR(100)    NOT NULL,
    CONSTRAINT PK_IssuerCredentialTypes PRIMARY KEY (issuer_id, credential_type)
) WITH (SYSTEM_VERSIONING = ON, LEDGER = ON);
GO
IF OBJECT_ID('dbo.SecurityEvents') IS NULL
CREATE TABLE dbo.SecurityEvents (
    event_id    BIGINT IDENTITY(1,1) NOT NULL,
    event_type  NVARCHAR(60)   NOT NULL,
    actor_id    NVARCHAR(400)  NULL,
    action      NVARCHAR(60)   NOT NULL,
    target      NVARCHAR(400)  NULL,
    details     NVARCHAR(2000) NULL,
    event_time  DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME()
) WITH (LEDGER = ON (APPEND_ONLY = ON));
GO
-- Types de diplômes que l'émetteur UIR est autorisé à délivrer
INSERT INTO dbo.IssuerCredentialTypes (issuer_id, credential_type)
SELECT i.issuer_id, t.v FROM dbo.Issuers i
CROSS JOIN (VALUES (N'Bachelor'),(N'Master'),(N'Doctorate'),(N'Certificate')) t(v)
WHERE i.engine_issuer_id = 'uir'
  AND NOT EXISTS (SELECT 1 FROM dbo.IssuerCredentialTypes x WHERE x.issuer_id = i.issuer_id AND x.credential_type = t.v);
GO
-- Comptes de démonstration (les comptes existants de Rihab n'ont pas d'e-mail)
DECLARE @u TABLE (name NVARCHAR(100), email NVARCHAR(200), role NVARCHAR(50));
INSERT INTO @u VALUES (N'Admin CertiChain', N'admin@uir.ac.ma', N'ADMINISTRATOR'),
                      (N'Service Scolarite UIR', N'scolarite@uir.ac.ma', N'UNIVERSITY_STAFF'),
                      (N'Etudiant Demo', N'etudiant@uir.ac.ma', N'STUDENT');
INSERT INTO dbo.Users (user_id, display_name, email, status, created_at)
SELECT NEWID(), d.name, d.email, N'ACTIVE', SYSUTCDATETIME() FROM @u d
WHERE NOT EXISTS (SELECT 1 FROM dbo.Users x WHERE x.email = d.email);
INSERT INTO dbo.UserRoles (user_id, role_id)
SELECT us.user_id, r.role_id FROM @u d
JOIN dbo.Users us ON us.email = d.email JOIN dbo.Roles r ON r.role_name = d.role
WHERE NOT EXISTS (SELECT 1 FROM dbo.UserRoles x WHERE x.user_id = us.user_id AND x.role_id = r.role_id);
GO
SELECT u.email, r.role_name FROM dbo.Users u JOIN dbo.UserRoles ur ON ur.user_id=u.user_id JOIN dbo.Roles r ON r.role_id=ur.role_id WHERE u.email IS NOT NULL;
SELECT i.engine_issuer_id, t.credential_type FROM dbo.IssuerCredentialTypes t JOIN dbo.Issuers i ON i.issuer_id=t.issuer_id;
SELECT name, ledger_type_desc FROM sys.tables WHERE name IN ('IssuerKeys','IssuerCredentialTypes','SecurityEvents');
