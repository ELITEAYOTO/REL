# REL — Stratégie et portes de validation

**Référence de décision :** [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md). État des fonctionnalités = code + CI vérifiée sur `main`.

## Positionnement

Plateforme **générale de reverse engineering** ; valeur cible à démontrer : expliquer la transformation d'un programme compilé entre versions par constats traçables, indices, incertitudes et reproduction. Démarrer par API/CLI offline-first, UI ultérieure. Ne pas transformer cet axe de preuve en limitation du périmètre produit.

## Gates

| Gate | Livrable / borne de qualité | Statut 18/10/2026 |
| --- | --- | --- |
| P0 + P1 | `rel-contracts`, `rel-pe`, `rel-inspect`, PE v1, CI Windows/Linux | VALIDÉ dans le périmètre limité testé |
| P1.5-A | lecture bornée, budgets CPU/RAM/sortie, gestion des chemins et fichiers changeants, corpus légal et oracle | EN COURS |
| P1.5-B | fuzz prolongé + verrouillé, limites de worker, benchmarks variés, isolation selon OS | À POURSUIVRE, pas d'affirmation de sûreté globale |
| EX-01 | schéma indépendant, validateur et producteur réel `pe.dos_magic` borné | PILOTE PARTIEL VÉRIFIÉ, autres domaines non implémentés ([PR #51](https://github.com/ELITEAYOTO/REL/pull/51), [CI #39179499279](https://github.com/ELITEAYOTO/REL/actions/runs/39179499279)) |
| EX-02 | diff v1 de métadonnées PE, Rust CLI indépendant, cas ambigus et tests golden | PAS IMPLÉMENTÉ |
| P2 | adaptateur externe Ghidra headless Python | PAS IMPLÉMENTÉ |
| P3 | matching de fonctions et évaluation précision/rappel/abstention | PAS IMPLÉMENTÉ |
| P4+ | historique, capacités, essais comportementaux isolés, GUI | VISION |

**P3 ≠ EX-02 :** le diff de sections/imports ne mesure pas la similitude des fonctions. EX-02 est un pilote de valeur produit, pas une réécriture de Ghidra.

## Conditions pour engager EX-01/02

- CI Windows/Linux verte sur la base cible, provenance et échecs F001 conservés.
- Corpus contrôlé, légal, taille bornée ; pas de mode hostiles arbitraires déclaré sécurisé.
- V1 `binary-manifest.schema.json` conservé ; validation des entrées JSON et de versions strictes.
- Diagnostic `unknown/failed/partial` pour toute extraction incertaine ; jamais inférer une capacité absente d'une liste vide.
- Tests de symétrie A/B, casse de DLL, doublons de sections, ordinals non représentés, golden input et sortie reproductible.
- Rapport documentant ce qui **n'est pas** analysé, avec version/hash des producteurs.
- Une PR = une responsabilité cohérente et indépendante ; preuve réelle de CI avant promotion d'une gate.

## Différenciation à mesurer (hypothèses)

Sur 10–20 paires de builds de référence : comparer détections à changements connus, faux positifs, temps/RSS et cas d'abstention. Faire reproduire un rapport à trois évaluateurs techniques. Plus tard, mesurer précision/rappel du matching face à une vérité terrain et moteurs existants. Aucune innovation absolue, métrique ni sécurité garantie simplement parce que le code compile.

## Standards d'ingénierie

- Rust : fichier 350 lignes alerte / 500 exception ; fonction 50 / 80 ; complexité 10 / 15 (revue, pas découpage automatique).
- Pas de graphe dédié, agent IA, moteur de politiques, interface ou WASM sans cas d'usage et ADR.
- Procédure : hypothèse → tests/fixtures → PR → mesures → CI → CHANGELOG/ROADMAP/HANDOFF.
- Choix de licence encore ouvert ; GitHub public n'est pas équivalent à une licence de redistribution.
