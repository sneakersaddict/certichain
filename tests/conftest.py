import pytest
from credential_engine import (
    CredentialEngine, CredentialSubject, InMemoryIssuerRegistry,
    InMemoryStatusStore, LocalECDSASigner,
)


@pytest.fixture
def signer():
    return LocalECDSASigner.generate("test-key-1")


@pytest.fixture
def engine(signer):
    registry = InMemoryIssuerRegistry()
    registry.register_from_signer("uir", "Université Internationale de Rabat",
                                  "uir.ac.ma", signer)
    return CredentialEngine(signer, registry, "uir", InMemoryStatusStore())


@pytest.fixture
def subject():
    return CredentialSubject(
        holder_id="stu-001",
        full_name="Mona Azzaoui",
        credential_name="Licence en Génie Informatique",
        credential_type_label="Degree",
    )
