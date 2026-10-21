# STATUS — REL

**Phase :** P1.5 (consolidation PE), avec pilotes expérimentaux EX-01 / EX-02 intégrés ; **P2 non engagé**.
**Mis à jour :** 2026-10-21, après PR #155. État daté, toujours revérifier SHA de `main`, PR et CI sur GitHub.

## Fonctionne
- P1 : inspection **statique** PE32/PE32+, manifeste `binary-manifest v1.0.0` et CLI.
- EX-01 : trois domaines bornés, preuves brutes non UTF-8 (#150) ; EX-02 : diff strict `0.1` et `--partial` `0.2` expérimentaux (#149), aucune preuve de comportement.
- Imports ordinaires, ordinals et couverture delay-load signalée (#143/#155) ; CI Windows/Ubuntu, mesures natives (#153/#154) et fuzzing court sans garantie de sandbox.

## En cours
- P1.5 #9 : diversité/provenance des PE, limites réelles de ressources et analyse statique.
- #8 : profondeur/acceptation du fuzz prolongé ; #14 et #68 : preuves expérimentales incomplètes.

## Prochaine tâche
- #9 : corpus PE diversifié avec droits établis et oracle indépendant ; en priorité de vrais imports différés, ordinals et variantes de compilateurs, sans redistribuer de binaires non autorisés.
- #8 / #68 : campagnes de fuzz plus profondes et comparaisons CPU/RSS sur matériel stable ; les plafonds de sortie et compteurs natifs sont déjà intégrés. Aucune entrée en P2 sans gate.

## Bloquants
- P1.5 : corpus représentatif légalement clarifié et isolation/ressources non entièrement démontrées.
- Licence [#16](https://github.com/ELITEAYOTO/REL/issues/16) : choix réservé au propriétaire.

## Idées (non approuvées)
- Évaluer iced-x86/CFG, rel-store/rel-db, preuves signées, MCP et GUI **après** revue de l'architecture.
- Pas de module spéculatif avant mesure du besoin et validation de la phase.

## Historique (10 entrées maximum)
- 2026-10-21 · #155 : avertissement explicite pour répertoire delay-import déclaré, test rouge→vert ; CI `main` #39582242085 réussie.
- 2026-10-21 · #154 : mesures natives sur 21 rejets PE contrôlés ; CI `main` #39578623197 réussie.
- 2026-10-21 · #153 : mesures CPU/RSS natives d'EX-02, sans plafond imposé ; CI `main` #39577213485 réussie.
- 2026-10-21 · #152 : copies transitoires réduites dans `rel-diff` ; CI `main` #39575103247 réussie.
- 2026-10-21 · #150 : test N2 croisé v1/EX-01, CI `main` #39559445380 Windows/Ubuntu réussie.
- 2026-10-21 · #149 : diff partiel explicite et schéma distinct intégrés ; CI post-fusion #39555891672 réussie.
- 2026-10-21 · #146 : régression de collision des dossiers de test Windows et allocation résistante aux conflits.
- 2026-10-21 · chore(governance): simplifier AGENTS, créer STATUS, archiver les anciennes passations (cette PR).
- 2026-10-21 · #144 : préflight rejette import non vide avec RVA nul ; CI nouvelle main #39549151670 réussie.
- 2026-10-21 · #143 : avertissement import par ordinal ; CI de nouvelle main #39546359432 réussie.
