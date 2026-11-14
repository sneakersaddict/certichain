"""Confiance émetteur : une signature valide d'une clé inconnue n'est pas acceptée."""
from credential_engine import (
    CredentialEngine, InMemoryIssuerRegistry, InMemoryStatusStore,
    LocalECDSASigner, VerificationStatus, issuer_registry,
)


def test_unknown_issuer_not_trusted(engine, subject):
    # Un émetteur « pirate » avec sa propre clé, absent du registre du vérificateur.
    rogue_signer = LocalECDSASigner.generate("rogue-key")
    rogue_registry = InMemoryIssuerRegistry()
    rogue_registry.register_from_signer("fake-univ", "Fake University", "fake.edu", rogue_signer)
    rogue_engine = CredentialEngine(rogue_signer, rogue_registry, "fake-univ", InMemoryStatusStore())

    forged = rogue_engine.issue_credential(subject)
    # Le credential est signé (valide en soi) mais l'émetteur est inconnu du vérificateur.
    assert engine.verify_credential(forged).status == VerificationStatus.ISSUER_NOT_TRUSTED


def test_suspended_issuer_not_trusted(engine, subject, signer):
    vc = engine.issue_credential(subject)
    # On suspend l'émetteur dans le registre.
    issuer = engine.registry.get_issuer("uir")
    issuer.status = issuer_registry.SUSPENDED
    assert engine.verify_credential(vc).status == VerificationStatus.ISSUER_NOT_TRUSTED
