# STATUS — REL

**Phase :** P1.5 (consolidation PE) ; pilotes EX-01 / EX-02 expérimentaux intégrés ; **P2 non engagé**.
**Mis à jour :** 2026-10-22, checkpoint après #172 : `main` `f70a002b6271523f0d16b2d59e36c4e972437bf6`. [CI de PR #39710790824](https://github.com/ELITEAYOTO/REL/actions/runs/39710790824) Windows/Ubuntu réussie (15 artefacts) et [fuzz #39710790731](https://github.com/ELITEAYOTO/REL/actions/runs/39710790731) réussi. CI `push` sur ce SHA non récupérable au contrôle ; ceci n'est pas un statut GitHub live.

## Fonctionne
- P1 : inspection **statique** PE32/PE32+, CLI et manifeste `binary-manifest v1.0.0` préservé ; aucune entrée soumise n'est exécutée.
- EX-01 : trois domaines bornés, preuves source non UTF-8 (#150). EX-02 : `rel-diff` strict `0.1` et `--partial` `0.2` expérimentaux (#149), avertissements/UNKNOWN conservés.
- P1.5 : contrôles PE (#163–#172) intégrés : imports contigus, frontières et padding aligné, puis priorité d'ordre des sections (#172). Corpus représentatif et isolation globale encore incomplets.

## En cours
- #9 : corpus PE représentatif, provenance et droits ; limites CPU/RAM/process-tree encore incomplètes malgré les garde-fous existants.
- #8 : fuzz prolongé ; #14 : couverture EX-01 ; #68 : budgets/mesures EX-02 ; #69 : reproductibilité inter-CI et causes encore inconnues.

## Prochaine tâche
- #9 : après #172, évaluer la divergence de RVA pour sections atypiques sans généraliser Goblin, uniquement sur nouvelles preuves fail-first. En parallèle, corpus licite, bornes CPU/RAM/process-tree et fuzz long (#8/#9), sans affirmer la sécurité de tous les PE hostiles.
- Autres axes si plus probants : corpus PE licite et provenance (#9), mesures CPU/RAM comparables et budgets justifiables (#68), fuzz prolongé (#8), dérive de builds inter-CI non expliquée (#69). Une PR ciblée à la fois, CI Windows/Ubuntu puis `main`.

## Bloquants
- P1.5 non clos : corpus redistribuable représentatif, preuves de couverture et bornes de ressources/isolation non exhaustives. CI verte/fuzz sans crash ≠ sécurité globale.
- Licence [#16](https://github.com/ELITEAYOTO/REL/issues/16) : décision exclusivement réservée au propriétaire.

## Idées (non approuvées)
- Évaluer iced-x86/CFG, rel-store/rel-db, preuves signées, MCP et GUI **après** revue de l'architecture et des gates.
- Aucun module spéculatif ni transition P2 Ghidra sans décision et validations correspondantes.

## Historique (10 entrées maximum)
- 2026-10-22 · #172 : test PE32 rouge `e0fec9c7` → correction fusionnée `f70a002b` ; CI PR #39710790824 Windows/Ubuntu (15 artefacts) et fuzz #39710790731 réussis ; `push` main non confirmé.
- 2026-10-22 · #171 : RVA d'import dans padding aligné, test rouge→vert ; fusion `bca93dae`, CI finale PR #39709386568 (15 artefacts) et fuzz #39709386566 réussis.
- 2026-10-22 · #170 : premier descripteur à cheval sur la fin de section, test PE32 rouge, contrôle du premier octet RVA étendu avant parcours contigu ; preuves et CI détaillées dans PR.
- 2026-10-22 · #169 : descripteurs suivants contigus hors frontière de section désormais précontrôlés, CI de PR Windows/Ubuntu et fuzzing réussis ; CI `push` distincte non confirmée.
- 2026-10-22 · #167 : RVA d'import non nul et Size=0 précontrôlé, test rouge→vert ; CI `main` #39701091132 réussie (15 artefacts).
- 2026-10-22 · #166 : RVA d'import non mappable ≠ épuisement du plafond de balayage ; CI `main` #39698862674 réussie.
- 2026-10-22 · #165 : import table Size sous-déclaré : vérification bornée jusqu'au terminateur ; CI `main` #39695059523 réussie.
- 2026-10-21 · #164 : vérification des descripteurs successifs déclarés, test rouge→vert ; CI `main` #39690430010 réussie.
- 2026-10-21 · #163 : rejet du premier descripteur d'import non nul sans Name/FirstThunk, test rouge→vert ; CI `main` #39604236819 réussie.
- 2026-10-21 · #162 : prévalidation de l'analyseur Windows avant création d'overlays ; CI `main` #39600580152 réussie.
