"""
Store de statut des credentials (révocation).

Portée Phase 2 : le moteur doit pouvoir répondre « Revoked » lors de la
vérification. On fournit une interface + une implémentation en mémoire pour rendre
la démo et les tests autonomes.

La persistance réelle (événements d'émission/révocation, historique infalsifiable)
relève de la Phase 3 (trust registry & lifecycle, Azure SQL Ledger). Il suffira d'y
brancher une implémentation `SqlLedgerStatusStore` respectant cette même interface.
"""

from __future__ import annotations

import abc
from enum import Enum
from typing import Dict, Optional


class CredentialStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


class StatusStore(abc.ABC):
    @abc.abstractmethod
    def get_status(self, credential_id: str) -> CredentialStatus:
        ...

    @abc.abstractmethod
    def set_status(self, credential_id: str, status: CredentialStatus, reason: Optional[str] = None) -> None:
        ...


class InMemoryStatusStore(StatusStore):
    def __init__(self) -> None:
        self._status: Dict[str, CredentialStatus] = {}
        self._reasons: Dict[str, str] = {}

    def get_status(self, credential_id: str) -> CredentialStatus:
        # Par défaut : un credential inconnu du store est considéré actif
        # (il n'a jamais été révoqué). L'authenticité reste prouvée par la signature.
        return self._status.get(credential_id, CredentialStatus.ACTIVE)

    def set_status(self, credential_id: str, status: CredentialStatus, reason: Optional[str] = None) -> None:
        self._status[credential_id] = status
        if reason:
            self._reasons[credential_id] = reason

    def get_reason(self, credential_id: str) -> Optional[str]:
        return self._reasons.get(credential_id)
