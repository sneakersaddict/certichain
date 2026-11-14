"""
Canonicalisation déterministe d'un credential avant hachage/signature.

Pourquoi : pour que la signature soit vérifiable, l'émetteur et le vérificateur
doivent calculer EXACTEMENT les mêmes octets à partir du credential. On fige donc
une représentation canonique : clés triées (récursivement), séparateurs compacts,
UTF-8. C'est une canonicalisation de type JCS (RFC 8785 simplifiée) ; elle est
suffisante et honnête pour notre périmètre, mais ce n'est pas une suite de preuve
W3C certifiée (voir README, section « Conformité W3C »).

Règle clé : le champ `proof` n'est JAMAIS inclus dans les octets signés
(on ne peut pas signer la signature elle-même).
"""

from __future__ import annotations

import json
from typing import Any, Dict

PROOF_KEY = "proof"


def canonical_bytes(credential: Dict[str, Any]) -> bytes:
    """Retourne les octets canoniques d'un credential, sans le champ `proof`."""
    payload = {k: v for k, v in credential.items() if k != PROOF_KEY}
    return _dumps(payload)


def canonical_bytes_with_proof_config(
    credential: Dict[str, Any], proof_config: Dict[str, Any]
) -> bytes:
    """
    Variante : signe le credential + la configuration de preuve (sans proofValue).
    Rapproche le schéma des Data Integrity Proofs du W3C (le vérificateur relie la
    preuve à ses métadonnées). Non utilisée par défaut, fournie pour extension.
    """
    payload = {k: v for k, v in credential.items() if k != PROOF_KEY}
    payload["__proofConfig__"] = {
        k: v for k, v in proof_config.items() if k != "proofValue"
    }
    return _dumps(payload)


def _dumps(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
