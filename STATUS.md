# STATUS — REL

**Phase :** P1.5 (consolidation PE) ; pilotes EX-01 / EX-02 expérimentaux intégrés ; **P2 non engagé**.
**Mis à jour :** 2026-10-22, checkpoint daté sur `main` `e610eef0118c716c62edd5877a9c20a018a42297` après #170 ; CI finale de PR #39707761862 Windows/Ubuntu réussie (15 artefacts), fuzz #39707761859 réussi. `push` post-fusion non vérifié indépendamment ; état live à revérifier.

## Fonctionne
- P1 : inspection **statique** PE32/PE32+, CLI et manifeste `binary-manifest v1.0.0` préservé ; aucune entrée soumise n'est exécutée.
- EX-01 : trois domaines bornés, preuves source non UTF-8 (#150). EX-02 : `rel-diff` strict `0.1` et `--partial` `0.2` expérimentaux (#149), avertissements/UNKNOWN conservés.
- P1.5 : mesures/oracles (#153–#160), contrôles PE (#163–#170) : descripteurs contigus (#169), premier descripteur chevauchant la section (#170) ; garantie limitée aux cas contrôlés, aucune sandbox CPU/RAM.

## En cours
- #9 : corpus PE représentatif, provenance et droits ; limites CPU/RAM/process-tree encore incomplètes malgré les garde-fous existants.
- #8 : fuzz prolongé ; #14 : couverture EX-01 ; #68 : budgets/mesures EX-02 ; #69 : reproductibilité inter-CI et causes encore inconnues.

## Prochaine tâche
- #9 / PR #171 candidate : test rouge PE32 avec import à RVA dans le padding brut aligné alors que Goblin le lit ; garde ciblée sur ce mappage, puis CI Windows/Ubuntu, fuzzing et `push` exact avant clôture de l'incrément.
- Autres axes si plus probants : corpus PE licite et provenance (#9), mesures CPU/RAM comparables et budgets justifiables (#68), fuzz prolongé (#8), dérive de builds inter-CI non expliquée (#69). Une PR ciblée à la fois, CI Windows/Ubuntu puis `main`.

## Bloquants
- P1.5 non clos : corpus redistribuable représentatif, preuves de couverture et bornes de ressources/isolation non exhaustives. CI verte/fuzz sans crash ≠ sécurité globale.
- Licence [#16](https://github.com/ELITEAYOTO/REL/issues/16) : décision exclusivement réservée au propriétaire.

## Idées (non approuvées)
- Évaluer iced-x86/CFG, rel-store/rel-db, preuves signées, MCP et GUI **après** revue de l'architecture et des gates.
- Aucun module spéculatif ni transition P2 Ghidra sans décision et validations correspondantes.

## Historique (10 entrées maximum)
- 2026-10-22 · #171 (candidate) : RVA d'import dans le padding file-aligned accepté par Goblin, mauvaise complétude prouvée PE32 ; test `a246919e`, CI rouge #39708868057 ; fix et validation en cours.
- 2026-10-22 · #170 : premier descripteur à cheval sur la fin de section, test PE32 rouge, contrôle du premier octet RVA étendu avant parcours contigu ; preuves et CI détaillées dans PR.
- 2026-10-22 · #169 : descripteurs suivants contigus hors frontière de section désormais précontrôlés, CI de PR Windows/Ubuntu et fuzzing réussis ; CI `push` distincte non confirmée.
- 2026-10-22 · #167 : RVA d'import non nul et Size=0 précontrôlé, test rouge→vert ; CI `main` #39701091132 réussie (15 artefacts).
- 2026-10-22 · #166 : RVA d'import non mappable ≠ épuisement du plafond de balayage ; CI `main` #39698862674 réussie.
- 2026-10-22 · #165 : import table Size sous-déclaré : vérification bornée jusqu'au terminateur ; CI `main` #39695059523 réussie.
- 2026-10-21 · #164 : vérification des descripteurs successifs déclarés, test rouge→vert ; CI `main` #39690430010 réussie.
- 2026-10-21 · #163 : rejet du premier descripteur d'import non nul sans Name/FirstThunk, test rouge→vert ; CI `main` #39604236819 réussie.
- 2026-10-21 · #162 : prévalidation de l'analyseur Windows avant création d'overlays ; CI `main` #39600580152 réussie.
- 2026-10-21 · #160 : classification des données debug incluses dans sections EX-02 corrigée, test rouge→vert ; CI `main` #39593729097 réussie.
