# AGENTS.md — Contrat des agents de développement REL

REL est une plateforme Rust modulaire de reverse engineering **autorisé**, statique et offline-first à ce stade. Priorité : **défauts démontrés, sécurité, code fonctionnel et tests** ; pas de fonctionnalités ou documents spéculatifs.

## Début de session
1. Lire **`AGENTS.md` et `STATUS.md`** ; vérifier en direct `main`, PR, issues et CI. Aucun statut daté n'est une preuve live.
2. Lire uniquement le code, les contrats, tests, oracles et documents pertinents pour la tâche ; consulter [ROADMAP](ROADMAP.md), [décisions figées](docs/governance/DECISIONS_FIGEES.md), [qualité](docs/governance/CODE_QUALITY.md) et [ADR-0013](docs/adr/ADR-0013-vision-evidence-evolution.md) avant toute décision d'architecture.
3. Le [checkpoint historique](docs/archive/CURRENT_STATE.md) et les [anciennes passations](docs/archive/HANDOFF_NEXT_CHAT.md) sont **des archives**, jamais l'état courant.

## Priorités et exécution
- Ordre : **sécurité et exactitude** → tests et code utile → simplicité/maintenabilité → documentation proportionnée.
- **1 objectif cohérent = 1 PR à la fois**. Prouver le défaut ou le manque de couverture avant toute modification de production ; commencer par les tests ciblés, revoir le diff et les régressions.
- Aucun refactoring cosmétique, nouveau framework/module, suppression de fixture ou nouvelle dépendance sans besoin démontré. Noter les idées hors périmètre dans `STATUS.md`.
- Ne pas produire de fichiers de handoff, journaux ou rapports concurrents. Documenter les preuves importantes dans l'issue et le code existant ; créer un ADR **uniquement** pour une évolution architecturale ou contractuelle réellement justifiée.
- Actualiser la documentation quand changent un comportement observable, un contrat, une garantie ou limite de sécurité, ou un jalon significatif. Pas de quotas artificiels de lignes ni de ratios d'effort.
- Décision stratégique, licence #16 ou changement majeur non délégué : demander confirmation ; autres tâches ciblées : autonomie avec justification.

## Définition de terminé
- `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo test --locked --workspace --all-targets`, `cargo build --locked --release --workspace` ; tests de corruption pour toute entrée nouvelle.
- Exiger la CI Windows native **et** Ubuntu sur le HEAD final de PR ; fuzzing borné et oracles indépendants quand des chemins PE changent ; vérifier les journaux et artefacts.
- Squash uniquement si toutes les validations exigées réussissent ; ensuite **CI distincte sur le SHA exact de `main`**. Ne pas inventer de revue indépendante ou de réussite.
- Sorties déterministes ; aucune panique volontaire sur donnée non fiable, `unwrap()` seulement sur invariant prouvé/testé. Conserver les fixtures, SHA-256, provenance et reproductions historiques.
- `STATUS.md` : sections courtes, 3 lignes maximum chacune (sauf historique de 10 entrées maximum), une ligne d'historique par évolution significative. Commits `type(scope): résumé`.

## Invariants de sécurité et de compatibilité
- **`binary-manifest v1.0.0` immuable** sans ADR et migration explicites. Séparer `rel-contracts`, `rel-pe`, CLI et outils expérimentaux ; préserver ADR-0013 : P1.5 avant validation EX-01/EX-02, puis P2 Ghidra et P3 matching.
- Ne jamais exécuter, charger, injecter ou instrumenter les PE/DLL soumis à l'analyse statique ; seulement des binaires autorisés et contrôlés ; aucun contournement d'anti-cheat/DRM ni interaction avec la mémoire d'un jeu en direct dans REL. Toute étude dynamique future requiert autorisation explicite, isolation et décision dédiée.
- Ne pas faire confiance à Goblin ou à toute dépendance de parsing : preflight, tailles et structures contrôlées, tests négatifs et budgets explicites. **Les plafonds existants ne constituent pas une sandbox complète CPU/RAM/disk/process-tree**. Ne jamais affirmer que toutes les entrées hostiles sont entièrement bornées.
- Offline-first : aucun réseau par défaut. Aucun binaire tiers propriétaire ou non autorisé dans le dépôt ; droits de redistribution documentés. Aucune licence source définitive sans décision du propriétaire.
- Un delta de métadonnées n'est pas une preuve de comportement ; un match est une **hypothèse** avec confiance et références, les conclusions non démontrées sont **UNKNOWN**. Distinguer faits vérifiés, limites, hypothèses et prochaines validations.
