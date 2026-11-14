"""
Démonstration end-to-end du moteur de credentials (Phase 2), SANS Azure.

Lance tous les scénarios de la « Definition of Done » (concept §14) :
  1. Émettre un credential
  2. Vérifier un credential authentique        -> Valid
  3. Modifier le credential                     -> Invalid
  4. Émetteur inconnu                            -> Issuer Not Trusted
  5. Révoquer puis vérifier                      -> Revoked
  6. Credential expiré                           -> Expired

Usage :  python demo.py
"""

import copy
import json

import credential_engine as ce
from credential_engine import CredentialSubject


def line(title):
    print("\n" + "=" * 68 + f"\n{title}\n" + "=" * 68)


def main():
    # Moteur local (clé logicielle en mémoire, registre en mémoire)
    engine = ce.build_local_engine()

    subject = CredentialSubject(
        holder_id="stu-2026-001",
        full_name="Mona Azzaoui",
        credential_name="Licence en Génie Informatique",
        credential_type_label="Degree",
        extra={"mention": "Très bien", "promotion": "2026"},
    )

    line("1) ÉMISSION d'un credential")
    vc = engine.issue_credential(subject, expires_at="2032-01-01T00:00:00Z")
    print(json.dumps(vc, indent=2, ensure_ascii=False))

    line("2) VÉRIFICATION d'un credential authentique")
    print(json.dumps(engine.verify_credential(vc).to_dict(), indent=2, ensure_ascii=False))

    line("3) ALTÉRATION : on change le nom dans le credential")
    tampered = copy.deepcopy(vc)
    tampered["credentialSubject"]["name"] = "Quelqu'un d'autre"
    print("Résultat attendu : Invalid")
    print(json.dumps(engine.verify_credential(tampered).to_dict(), indent=2, ensure_ascii=False))

    line("4) ÉMETTEUR INCONNU : credential signé par une autre université")
    rogue = ce.build_local_engine(issuer_id="fake-univ", issuer_name="Fake University")
    forged = rogue.issue_credential(subject)
    print("Résultat attendu : Issuer Not Trusted")
    print(json.dumps(engine.verify_credential(forged).to_dict(), indent=2, ensure_ascii=False))

    line("5) RÉVOCATION puis vérification")
    engine.revoke_credential(vc["id"], "Diplôme annulé par l'administration")
    print("Résultat attendu : Revoked")
    print(json.dumps(engine.verify_credential(vc).to_dict(), indent=2, ensure_ascii=False))

    line("6) CREDENTIAL EXPIRÉ")
    expired = engine.issue_credential(subject, expires_at="2000-01-01T00:00:00Z")
    print("Résultat attendu : Expired")
    print(json.dumps(engine.verify_credential(expired).to_dict(), indent=2, ensure_ascii=False))

    print("\n" + "=" * 68)
    print("Démo terminée : tous les scénarios de la Definition of Done sont couverts.")
    print("=" * 68)


if __name__ == "__main__":
    main()
