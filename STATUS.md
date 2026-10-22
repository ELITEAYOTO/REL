# STATUS — REL

**Phase :** P1.5 (consolidation PE) ; pilotes EX-01 / EX-02 expérimentaux intégrés ; **P2 non engagé**.
**Mis à jour :** 2026-10-22, checkpoint `main` `bc3225a3eb9a16fac426fda01a34b5649e238407` après #174 ; [CI `push` exacte #39726036423](https://github.com/ELITEAYOTO/REL/actions/runs/39726036423) Windows/Ubuntu réussie et 15 artefacts vérifiés. Campagne isolée 300 s [#39727233949](https://github.com/ELITEAYOTO/REL/actions/runs/39727233949) réussie ; déclencheur temporaire restauré, ne pas confondre cette branche avec `main`.

## Fonctionne
- P1 : inspection **statique** PE32/PE32+, CLI et manifeste `binary-manifest v1.0.0` préservé ; aucune entrée soumise n'est exécutée.
- EX-01 : trois domaines bornés, preuves source non UTF-8 (#150). EX-02 : `rel-diff` strict `0.1` et `--partial` `0.2` expérimentaux (#149), avertissements/UNKNOWN conservés.
- P1.5 : contrôles PE (#163–#172), graines de fuzzing temporaires SHA-256 vérifiées (#174) : 13 entrées initiales et 1 campagne 300 s enregistrée ; ni corpus représentatif ni sandbox.

## En cours
- #9 : corpus PE représentatif, provenance et droits ; limites CPU/RAM/process-tree encore incomplètes malgré les garde-fous existants.
- #8 : répétition/comparabilité du fuzz prolongé et toute future minimisation de crash ; #14 couverture EX-01, #68 budgets EX-02, #69 reproductibilité inter-CI non clos.

## Prochaine tâche
- #8 : analyser/rejouer les campagnes 300 s dans des contextes comparables pour mesurer la couverture sans extrapolation ; conserver les reproductions positives/négatives de parser. #9 : corpus PE licite diversifié, limites CPU/RAM/process-tree encore ouvertes.
- Autres axes si plus probants : corpus PE licite et provenance (#9), mesures CPU/RAM comparables et budgets justifiables (#68), fuzz prolongé (#8), dérive de builds inter-CI non expliquée (#69). Une PR ciblée à la fois, CI Windows/Ubuntu puis `main`.

## Bloquants
- P1.5 non clos : corpus redistribuable représentatif, preuves de couverture et bornes de ressources/isolation non exhaustives. CI verte/fuzz sans crash ≠ sécurité globale.
- Licence [#16](https://github.com/ELITEAYOTO/REL/issues/16) : décision exclusivement réservée au propriétaire.

## Idées (non approuvées)
- Évaluer iced-x86/CFG, rel-store/rel-db, preuves signées, MCP et GUI **après** revue de l'architecture et des gates.
- Aucun module spéculatif ni transition P2 Ghidra sans décision et validations correspondantes.

## Historique (10 entrées maximum)
- 2026-10-22 · #8 : première vraie campagne 300 s sur 13 seeds après #174, run #39727233949 SUCCESS, 2 449 702 cas, `cov=2415`, RSS observé 656 Mio ; aucun crash signalé, workflow manuel restauré.
- 2026-10-22 · #174 : huit seeds PE bornés générés SHA-256, fusion `bc3225a3` ; CI `main` #39726036423 Windows/Ubuntu réussie, 15 artefacts.
- 2026-10-22 · #172 : test PE32 rouge `e0fec9c7` → correction fusionnée `f70a002b` ; CI PR #39710790824 Windows/Ubuntu (15 artefacts) et fuzz #39710790731 réussis ; `push` main non confirmé.
- 2026-10-22 · #171 : RVA d'import dans padding aligné, test rouge→vert ; fusion `bca93dae`, CI finale PR #39709386568 (15 artefacts) et fuzz #39709386566 réussis.
- 2026-10-22 · #170 : premier descripteur à cheval sur la fin de section, test PE32 rouge, contrôle du premier octet RVA étendu avant parcours contigu ; preuves et CI détaillées dans PR.
- 2026-10-22 · #169 : descripteurs suivants contigus hors frontière de section désormais précontrôlés, CI de PR Windows/Ubuntu et fuzzing réussis ; CI `push` distincte non confirmée.
- 2026-10-22 · #167 : RVA d'import non nul et Size=0 précontrôlé, test rouge→vert ; CI `main` #39701091132 réussie (15 artefacts).
- 2026-10-22 · #166 : RVA d'import non mappable ≠ épuisement du plafond de balayage ; CI `main` #39698862674 réussie.
- 2026-10-22 · #165 : import table Size sous-déclaré : vérification bornée jusqu'au terminateur ; CI `main` #39695059523 réussie.
- 2026-10-21 · #164 : vérification des descripteurs successifs déclarés, test rouge→vert ; CI `main` #39690430010 réussie.
