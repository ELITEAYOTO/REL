# EX-01 — Enveloppe d'observations (brouillon)

**Statut : DESIGN EXPÉRIMENTAL, aucun code livré ; `binary-manifest` v1.0.0 inchangé.**  
Décision : [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md).

## But

Le v1 contient `imports: Vec<String>`, `exports: Vec<String>`, `warnings: Vec<String>`. Une liste vide ne renseigne pas à elle seule sur l'exhaustivité, la présence d'ordinals, les imports différés, les résolutions dynamiques ou l'échec silencieux de l'extraction.

## Petite enveloppe candidate, séparée de v1

- `subject` : identité SHA-256, taille, format du fichier d'origine.
- `producer` : composant et version, backend/version, configuration, identifiant reproductible d'exécution.
- `scope` : domaine exact (`pe.direct_import_table` par exemple), état `complete|partial|unsupported|failed`, limites et procédure.
- `observations[]` : prédicat, valeur source/normalisée, `present|absent_in_scope|indeterminate`, preuves et contexte.
- `evidence[]` : SHA du fichier, emplacement typé (offset de fichier vs RVA vs VA), longueur, méthode/version ; vérifier les bornes des plages.
- `diagnostics[]` : code machine stable, sévérité, étape, contexte utile ; erreur ≠ liste vide.
- Identifiants/ordres stables hors timestamp/chemins locaux, non déterminants dans le hash de contenu.

## Invariants

1. **Absent dans une table examinée intégralement** n'est pas **impossible dans le logiciel** ; aucune conclusion « pas de réseau » à partir d'imports absents.
2. Seul un domaine `complete` et précisément nommé peut établir `absent_in_scope` ; `failed`, `partial` et `unsupported` mènent à indéterminé.
3. Ne jamais inventer les ordinals, les imports retardés, les alias ni les offsets que v1 a perdus.
4. Conserver la forme brute après normalisation, par exemple DLL insensible à la casse selon règles de comparaison explicites.
5. Preuves de fichiers propriétaires : hashes/offsets validés plutôt que dump intégral ; ne pas divulguer des chemins/secrets privés.
6. Une signature authentifie éventuellement un rapport, pas ses conclusions ; un score de similarité n'est pas une probabilité de vérité.
7. Aucune nouvelle crate `rel-evidence` tant qu'un besoin réutilisable avec tests n'est pas démontré.

## Conditions d'acceptation

Schéma indépendant sous `contracts/experimental/` avec golden examples `present, absent_in_scope, partial, failed, unsupported`; tests JSON Schema invalides, champs incohérents, offset hors bornes, configurations/version, déterminisme et compatibilité v1. Une PR de contrat ne rend pas ce moteur fonctionnel tant qu'aucun extracteur ne peut produire ses observations fiables.
