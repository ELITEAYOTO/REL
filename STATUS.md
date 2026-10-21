# STATUS — REL

**Phase :** P1.5 (consolidation PE) ; pilotes EX-01 / EX-02 expérimentaux intégrés ; **P2 non engagé**.
**Mis à jour :** 2026-10-21, après PR #160. Checkpoint daté : `main` `0b308d32ff09230848628b5b8f0ad94b9a640ca2`, [CI #39593729097](https://github.com/ELITEAYOTO/REL/actions/runs/39593729097) Windows/Ubuntu réussie (15 artefacts). Toujours revérifier GitHub en direct.

## Fonctionne
- P1 : inspection **statique** PE32/PE32+, CLI et manifeste `binary-manifest v1.0.0` préservé ; aucune entrée soumise n'est exécutée.
- EX-01 : trois domaines bornés, preuves source non UTF-8 (#150). EX-02 : `rel-diff` strict `0.1` et `--partial` `0.2` expérimentaux (#149), avertissements/UNKNOWN conservés.
- P1.5 : mesures natives (#153/#154), avertissements ordinals/delay-load (#143/#155), oracles PE compilés source MSVC delay-load/ordinal/mixte (#157–#159), classification du debug EX-02 corrigée (#160) ; aucune garantie de sandbox.

## En cours
- #9 : corpus PE représentatif, provenance et droits ; limites CPU/RAM/process-tree encore incomplètes malgré les garde-fous existants.
- #8 : fuzz prolongé ; #14 : couverture EX-01 ; #68 : budgets/mesures EX-02 ; #69 : reproductibilité inter-CI et causes encore inconnues.

## Prochaine tâche
- Priorité #9 : rechercher une **nouvelle** lacune démontrable de corpus PE licitement utilisable, d'oracle indépendant ou de limites de ressources ; éviter de refaire les preuves MSVC delay-load/ordinal/mixte (#157–#159).
- Selon valeur/risque : #69 (question nouvelle, ne pas répéter /Brepro déjà testé), #8 (campagne plus profonde), #68 (mesures comparables sur matériel stable). Une PR ciblée à la fois, CI Windows/Ubuntu + CI distincte sur `main`.

## Bloquants
- P1.5 non clos : corpus redistribuable représentatif, preuves de couverture et bornes de ressources/isolation non exhaustives. CI verte/fuzz sans crash ≠ sécurité globale.
- Licence [#16](https://github.com/ELITEAYOTO/REL/issues/16) : décision exclusivement réservée au propriétaire.

## Idées (non approuvées)
- Évaluer iced-x86/CFG, rel-store/rel-db, preuves signées, MCP et GUI **après** revue de l'architecture et des gates.
- Aucun module spéculatif ni transition P2 Ghidra sans décision et validations correspondantes.

## Historique (10 entrées maximum)
- 2026-10-21 · #160 : classification des données debug incluses dans sections EX-02 corrigée, test rouge→vert ; CI `main` #39593729097 réussie.
- 2026-10-21 · #159 : vrai import mixte nommé + ordinal d'une même DLL, oracle pefile ; CI `main` #39591156832 réussie.
- 2026-10-21 · #158 : vrai export NONAME/import par ordinal 42, oracle indépendant ; CI `main` #39588428498 réussie.
- 2026-10-21 · #157 : vrai PE32+ MSVC delay-load, oracle indépendant sans exécution ; CI `main` #39586084661 réussie.
- 2026-10-21 · #156 : checkpoint STATUS synchronisé après #155 ; CI `main` #39583464594 réussie.
- 2026-10-21 · #155 : avertissement explicite pour répertoire delay-import déclaré, test rouge→vert ; CI `main` #39582242085 réussie.
- 2026-10-21 · #154 : mesures natives sur 21 rejets PE contrôlés ; CI `main` #39578623197 réussie.
- 2026-10-21 · #153 : mesures CPU/RSS natives d'EX-02, sans plafond imposé ; CI `main` #39577213485 réussie.
- 2026-10-21 · #152 : copies transitoires réduites dans `rel-diff` ; CI `main` #39575103247 réussie.
- 2026-10-21 · #150 : test N2 croisé v1/EX-01 ; CI `main` #39559445380 réussie.
