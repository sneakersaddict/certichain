# Partie 3 – première version de Rihab (archive)

Ces trois fichiers sont la version de `credential_engine/engine.py`, `status_store.py`
et `__init__.py` proposée par Rihab le 15 novembre (pull requests #3 à #8).

La version déployée sur Azure a ensuite déplacé le cycle de vie dans
`credential_engine/lifecycle.py` et `credential_engine/sql_ledger.py`, branchés sur
le schéma SQL Ledger de Rihab (tables Issuers, Credentials, IssuerEvents,
CredentialEvents, Users, Roles, UserRoles), sans modifier ses tables.

Ces fichiers sont gardés ici comme référence ; ils ne sont pas importés par l'API.
