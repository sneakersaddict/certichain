"""
Hachage SHA-256 (empreinte). Concept clé du projet : une empreinte de longueur
fixe qui change dès qu'un seul octet des données change -> détection d'altération.

Important (rappelé dans le concept) : une empreinte SEULE ne suffit pas, car
quiconque modifie le fichier peut recalculer une nouvelle empreinte. C'est pour
cela que l'empreinte est ensuite SIGNÉE par la clé privée de l'émetteur.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict

from .canonical import canonical_bytes


def sha256_bytes(data: bytes) -> bytes:
    """Empreinte SHA-256 brute (32 octets)."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Empreinte SHA-256 en hexadécimal (64 caractères)."""
    return hashlib.sha256(data).hexdigest()


def credential_digest(credential: Dict[str, Any]) -> bytes:
    """
    Empreinte SHA-256 (32 octets) de la forme canonique du credential, sans `proof`.
    C'est exactement l'empreinte qui sera signée puis vérifiée.
    """
    return sha256_bytes(canonical_bytes(credential))


def document_hash_hex(file_bytes: bytes) -> str:
    """Empreinte hexadécimale d'un document joint (ex. PDF original)."""
    return sha256_hex(file_bytes)
