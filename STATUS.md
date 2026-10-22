# STATUS — REL

**Phase :** P1.5 (consolidation PE) ; pilotes EX-01 / EX-02 expérimentaux intégrés ; **P2 non engagé**.
**Mis à jour :** 2026-10-22, checkpoint de production après PR #167 : `main` `7769ec37eebb5b656b1bb644526b1ba5c834fa3a`, [CI post-fusion #39701091132](https://github.com/ELITEAYOTO/REL/actions/runs/39701091132) Windows/Ubuntu réussie, **15 artefacts**, **0 PR ouverte** au moment du contrôle. Snapshot daté : toujours revérifier GitHub en direct.

## Fonctionne
- P1 : inspection **statique** PE32/PE32+, CLI et manifeste `binary-manifest v1.0.0` préservé ; aucune entrée soumise n'est exécutée.
- EX-01 : trois domaines bornés, preuves source non UTF-8 (#150). EX-02 : `rel-diff` strict `0.1` et `--partial` `0.2` expérimentaux (#149), avertissements/UNKNOWN conservés.
- P1.5 : mesures natives (#153/#154), oracles PE compilés (#157–#159), classification debug EX-02 (#160), contrôles d'imports (#163–#167) : RVA non mappables délégués au backend (#166), RVA non nul/Size nul précontrôlé (#167) ; aucune garantie de sandbox.

## En cours
- #9 : corpus PE représentatif, provenance et droits ; limites CPU/RAM/process-tree encore incomplètes malgré les garde-fous existants.
- #8 : fuzz prolongé ; #14 : couverture EX-01 ; #68 : budgets/mesures EX-02 ; #69 : reproductibilité inter-CI et causes encore inconnues.

## Prochaine tâche
- #9 / PR #169 (candidate, non fusionnée) : défaut PE32 reproduit sur le second descripteur à frontière de section ; le précontrôle doit suivre les offsets bruts contigus que Goblin lit, tout en conservant la délégation du premier RVA non mappable. Test rouge `f5b0823` ; contrôler les CI finales, fuzzing borné, logs et compatibilité avant tout squash.
- Autres axes si plus probants : corpus PE licite et provenance (#9), mesures CPU/RAM comparables et budgets justifiables (#68), fuzz prolongé (#8), dérive de builds inter-CI non expliquée (#69). Une PR ciblée à la fois, CI Windows/Ubuntu puis `main`.

## Bloquants
- P1.5 non clos : corpus redistribuable représentatif, preuves de couverture et bornes de ressources/isolation non exhaustives. CI verte/fuzz sans crash ≠ sécurité globale.
- Licence [#16](https://github.com/ELITEAYOTO/REL/issues/16) : décision exclusivement réservée au propriétaire.

## Idées (non approuvées)
- Évaluer iced-x86/CFG, rel-store/rel-db, preuves signées, MCP et GUI **après** revue de l'architecture et des gates.
- Aucun module spéculatif ni transition P2 Ghidra sans décision et validations correspondantes.

## Historique (10 entrées maximum)
- 2026-10-22 · #167 : RVA d'import non nul et Size=0 précontrôlé, test rouge→vert ; CI `main` #39701091132 réussie (15 artefacts).
- 2026-10-22 · #166 : RVA d'import non mappable ≠ épuisement du plafond de balayage ; CI `main` #39698862674 réussie.
- 2026-10-22 · #165 : import table Size sous-déclaré : vérification bornée jusqu'au terminateur ; CI `main` #39695059523 réussie.
- 2026-10-21 · #164 : vérification des descripteurs successifs déclarés, test rouge→vert ; CI `main` #39690430010 réussie.
- 2026-10-21 · #163 : rejet du premier descripteur d'import non nul sans Name/FirstThunk, test rouge→vert ; CI `main` #39604236819 réussie.
- 2026-10-21 · #162 : prévalidation de l'analyseur Windows avant création d'overlays ; CI `main` #39600580152 réussie.
- 2026-10-21 · #160 : classification des données debug incluses dans sections EX-02 corrigée, test rouge→vert ; CI `main` #39593729097 réussie.
- 2026-10-21 · #159 : vrai import mixte nommé + ordinal d'une même DLL, oracle pefile ; CI `main` #39591156832 réussie.
- 2026-10-21 · #158 : vrai export NONAME/import par ordinal 42, oracle indépendant ; CI `main` #39588428498 réussie.
- 2026-10-21 · #157 : vrai PE32+ MSVC delay-load, oracle indépendant sans exécution ; CI `main` #39586084661 réussie.
