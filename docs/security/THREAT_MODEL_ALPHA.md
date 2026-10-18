# REL — Modèle de menace alpha

**Statut : analyse initiale et engagements de tests, PAS une déclaration de sûreté.**  
Référence : [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md).

## Frontières

- Entrées PE non fiables : structures malformées, offsets trompeurs, tables géantes, fichiers changeants, symlinks, chemins inattendus.
- Entrées JSON non fiables : manifests incomplets, volontairement falsifiés ou excessivement volumineux.
- Dépendances extérieures : goblin, futur Ghidra/Java, toolchains, plugins, futures capacités IA.
- Actifs à protéger : machine hôte, CPU/RAM/disque, fichiers source, secrets/chemins privés, rapports et artefacts CI.

## Risques et mesures

| Risque | Situation vérifiée | Actions requises |
| --- | --- | --- |
| Lecture et course fichier | Ancien `metadata` puis `read` remplacé par une lecture bornée sur descripteur unique ([PR #17](https://github.com/ELITEAYOTO/REL/pull/17), [CI #39103698604](https://github.com/ELITEAYOTO/REL/actions/runs/39103698604) verified) ; pré-ouverture `symlink_metadata` non atomique | protéger races d'ouverture, modifications concurrentes de même taille, chemins spéciaux et RSS total ; voir [P15A_BOUNDED_INPUT](P15A_BOUNDED_INPUT.md) |
| Coût disproportionné | une petite entrée peut déclencher un parsing coûteux ; JSON borné à 16 MiB, instrument d'observation CPU/RSS validé en [CI #39104870706](https://github.com/ELITEAYOTO/REL/actions/runs/39104870706), pas de limite de mémoire/CPU du parseur | profils RSS/CPU représentatifs, budgets de structures/temps/mémoire ; [sortie bornée](P15A_BOUNDED_OUTPUT.md), [profilage](../P15_RESOURCE_PROFILING.md) |
| En-têtes PE hostiles | prévalidation allocation-free des offsets/tailles NT/COFF et ≤96 sections validée ([CI 39105600717](https://github.com/ELITEAYOTO/REL/actions/runs/39105600717), [fuzz 39105600726](https://github.com/ELITEAYOTO/REL/actions/runs/39105600726)) | ne couvre pas les tables d'import/export/TLS, les allocations dérivées et les fichiers non conformes ; voir [PE preflight](P15A_PE_PREFLIGHT.md) |
| PE directory declarations | preflight cap ajouté sur tailles déclarées des imports/exports et nombre annoncé d'exports (CI en attente) | limites non garanties par goblin pour toutes les allocations ; [contrôles et restrictions](P15A_DIRECTORY_BUDGETS.md) |
| Panic tiers | ancien F001 `goblin 0.9.3`, reproducer conservé | version 0.10.7 verrouillée et fuzz ; `catch_unwind` ≠ sandbox |
| Exécution | P1 ne lance aucun EXE soumis | préserver statique par défaut ; futures expériences dynamiques opt-in isolées |
| Faux résultats | tableau vide ou warning absent sans état de couverture | états d'extraction et diagnostics explicites |
| Rapport privé | sections/chaînes/chemins peuvent révéler infos | expurger secrets, pas d'embarquement automatique de binaires propriétaires |
| Chaîne logicielle | stable Cargo.lock ; fuzz nightly encore à figer | audit licences/advisories, SHA des actions, permissions minimales |

## Périmètre autorisé

**Alpha :** corpus légal et contrôlé, analyse statique seulement. Ne pas présenter REL comme un analyseur sécurisé de binaires adversariaux arbitraires. Un processus enfant limité n'est pas automatiquement une sandbox ; l'isolation Windows/Linux doit être spécifiée et testée avant une telle affirmation. Pas de contournement anti-cheat ni instrumentation de jeux protégés en ligne.

## Gates avant élargissement

Tests de fichiers changeants, symlinks, budgets structurels et RSS/CPU, corpus diversifié, fuzz plus long avec régressions minimisées, modèle d'isolation par OS, politique de confidentialités des sorties et revue de dépendances. Documenter les risques résiduels. Une CI verte est nécessaire mais non suffisante.
