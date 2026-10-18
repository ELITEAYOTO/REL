# ADR-0013 — Mission de REL, Evidence & Evolution et séquence

**Statut : ACCEPTÉ — décision de cadrage, pas preuve d'implémentation**  
**Date : 2026-10-18**  
**Base :** [RFC-0001](../rfc/RFC-0001-EVIDENCE-EVOLUTION.md), PR #13. Cette ADR complète D1–D11 ; elle n'annule aucune décision de modularité.

## Décision

REL reste une **plateforme générale de reverse engineering** de binaires autorisés : exploration de structures, fonctions, dépendances, comparaison entre versions, analyse approfondie, et plus tard essais comportementaux autorisés et isolés. **Evidence & Evolution** est notre méthode transversale pour expliquer *ce qui a changé, quels indices le montrent et ce qui demeure inconnu*. REL ne devient ni un simple scanner d'imports ni un produit uniquement de conformité.

Nous ne prétendons pas inventer la décompilation (Ghidra), le matching (BSim/BinDiff/Diaphora) ou les règles de capacités (capa). Différenciation produit **à mesurer**, pas unicité déclarée : un workflow longitudinal, rejouable, explicable, offline-first et automatisable en CI.

## Séquencement adopté

1. **P1.5-A, fiabilisation critique :** contrôles de lecture/ressources, chemins, comportement de fichier changeant, corpus PE diversifié, mesures, régression TLS F001. Alpha sur cibles de test contrôlées, sans prétention de sandbox.
2. **EX-01, contrat d'observation minimal expérimental :** sujet SHA-256, version/config d'extracteur, domaine couvert, état `complete|partial|unsupported|failed`, diagnostics et source. Conserver **binary-manifest v1.0.0 inchangé**.
3. **EX-02, diff PE métadonnées :** petite CLI+bibliothèque Rust autonome, compare deux manifestes versionnés et documente les limites, sur un corpus borné **avant P2 Ghidra**.
4. **P2 Ghidra externe :** adaptateur headless Python indépendant, fonctions/call graph, provenance et versions.
5. **P3 matching profond :** qualité mesurée face à vérité terrain, rapports d'incertitude ; étapes suivantes pour historique, classification, analyses comportementales autorisées, interface et éventuels plugins.

La **P1.5-B** (longues campagnes fuzz, isolation validée, corpus hostile et hardening continu) se poursuit et n'est *pas déclarée achevée* quand EX-01/02 commencent. Ces expériences ne doivent pas accepter des fichiers arbitrairement hostiles en faisant croire que le traitement est sûr.

## Frontières et garanties

- Rust pour moteurs possédés par REL, Python pour intégration Ghidra, Java/C++/C#/WASM seulement en cas de besoin mesuré.
- Monorepo modulaire, crates/CLI indépendants. **Aucune crate vide** destinée à satisfaire un diagramme.
- Sorties déterministes à entrées/versions/config égales (hors métadonnées volontairement non déterministes).
- Aucune exécution implicite d'EXE ; sécurité par budgets et isolation adaptée selon les menaces, jamais uniquement `catch_unwind`.
- **Absence d'import direct ≠ absence de capacité réseau** ; absence d'indice ≠ preuve d'impossibilité. Les conclusions négatives requièrent domaine précis et couverture complète.
- Séparer observation, hypothèse et comportement démontré ; une signature ne garantit pas la véracité ; pas de pourcentage de confiance non calibré.
- La licence de la source n'est pas encore sélectionnée ; décider après revue des dépendances et objectifs de contribution.
- Ghidra/BSim/BinDiff restent des moteurs externes / référentiels, pas des fonctionnalités prétendument construites.

## Alternatives écartées

Réinventer d'emblée un décompilateur, créer dix moteurs abstraits, bâtir une GUI avant les CLI, réduire REL à un audit de conformité, comparer des listes v1 sans exprimer leur couverture, modifier v1 silencieusement, ou attendre une garantie de sécurité absolue avant un prototype sur données contrôlées.

## Application et révision

Ce document autorise **l'ordre et les objectifs**, pas des changements de contrat ni la déclaration de modules « terminés ». Une future implementation d'EX-01/EX-02 devra avoir ses propres PR, tests golden, erreurs structurées, CI Windows/Linux et mesures, puis mise à jour de CHANGELOG/ROADMAP. Un changement de stack, de structure fondamentale ou de séquence requiert une nouvelle ADR appuyée par preuves, avec compatibilité/migration et plan de retour arrière.

Voir [gates](../governance/STRATEGY_AND_GATES.md), [contrat expérimental](../specs/OBSERVATION_ENVELOPE_DRAFT.md), [diff pilote](../specs/METADATA_DIFF_PILOT.md) et [menaces alpha](../security/THREAT_MODEL_ALPHA.md).
