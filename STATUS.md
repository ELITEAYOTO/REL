# STATUS — REL

**Phase :** P1.5 (consolidation PE), avec pilotes expérimentaux EX-01 / EX-02 intégrés ; **P2 non engagé**.
**Mis à jour :** 2026-10-21. État daté, toujours revérifier SHA de `main`, PR et CI sur GitHub.

## Fonctionne
- P1 : inspection **statique** PE32/PE32+, manifeste `binary-manifest v1.0.0` et CLI.
- EX-01 : trois domaines bornés et preuves d'octets sources, dont les noms de sections non UTF-8 via `section-headers` (#150).
- EX-02 : diff strict `0.1.0-experimental` et mode optionnel `--partial` en `0.2.0-experimental` (#149), sans preuve de comportement.
- CI Windows/Ubuntu, oracles et fuzzing court ; pas de garantie de sandbox ou de couverture globale.

## En cours
- P1.5 #9 : diversité/provenance des PE, limites réelles de ressources et analyse statique.
- #8 : profondeur/acceptation du fuzz prolongé ; #14 et #68 : preuves expérimentales incomplètes.

## Prochaine tâche
- #68 : auditer les mesures CPU/RSS et la mémoire transitoire de `rel-diff` ; plafond de sortie 16 Mio déjà implémenté, ne pas le refaire.
- #9 / #8 : poursuivre les preuves de corpus légal, ressources et fuzzing ; aucune entrée en P2 sans gate.

## Bloquants
- P1.5 : corpus représentatif légalement clarifié et isolation/ressources non entièrement démontrées.
- Licence [#16](https://github.com/ELITEAYOTO/REL/issues/16) : choix réservé au propriétaire.

## Idées (non approuvées)
- Évaluer iced-x86/CFG, rel-store/rel-db, preuves signées, MCP et GUI **après** revue de l'architecture.
- Pas de module spéculatif avant mesure du besoin et validation de la phase.

## Historique (10 entrées maximum)
- 2026-10-21 · #150 : test N2 croisé v1/EX-01, CI `main` #39559445380 Windows/Ubuntu réussie.
- 2026-10-21 · #149 : diff partiel explicite et schéma distinct intégrés ; CI post-fusion #39555891672 réussie.
- 2026-10-21 · #146 : régression de collision des dossiers de test Windows et allocation résistante aux conflits.
- 2026-10-21 · chore(governance): simplifier AGENTS, créer STATUS, archiver les anciennes passations (cette PR).
- 2026-10-21 · #144 : préflight rejette import non vide avec RVA nul ; CI nouvelle main #39549151670 réussie.
- 2026-10-21 · #143 : avertissement import par ordinal ; CI de nouvelle main #39546359432 réussie.
- 2026-10-21 · #142 : alignement des entrées TLS du fuzz long ; CI de nouvelle main #39545059294 réussie.
