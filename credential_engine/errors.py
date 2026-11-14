"""Erreurs du moteur de credentials CertiChain (Phase 2)."""


class CredentialEngineError(Exception):
    """Erreur générique du moteur."""


class CredentialStructureError(CredentialEngineError):
    """Le credential ne respecte pas la structure attendue (champs manquants, etc.)."""


class SigningError(CredentialEngineError):
    """Échec lors de l'opération de signature (local ou Key Vault)."""


class UnknownIssuerError(CredentialEngineError):
    """L'émetteur référencé est introuvable dans le registre de confiance."""
