# EX-02 — Première observation des ressources du comparateur expérimental

**Date :** 19 octobre 2026 — mesures issues d'une CI, non d'un banc de performance de référence.  
**Programme :** `rel-diff`, compilé en `--release` avec Rust `1.85.1`.  
**Reproductibilité :** `python scripts/profile_manifest_diff.py --binary target/release/rel-diff --samples 3 --warmup 1 --output rel-diff-profile.json` (Windows : `.exe`).  
**Source :** [run #39206969607](https://github.com/ELITEAYOTO/REL/actions/runs/39206969607), artefacts `rel-diff-resource-profile-ubuntu-latest` et `rel-diff-resource-profile-windows-latest`. Les chiffres ci-dessous ont été lus dans les **JSON des deux artefacts**, et non déduits de la réussite de la CI.

## Observations d'une exécution contrôlée

| Plateforme / scénario | Entrées JSON (octets, chacune) | Médiane temps écoulé (ms) | P95 indicatif (ms) | Maximum RSS échantillonné (octets) |
| --- | ---: | ---: | ---: | ---: |
| Ubuntu Linux — minimal, 1 import/côté | 318 | 2,4890 | 2,5157 | 212 992 |
| Ubuntu Linux — 8 000 imports/côté | 184 295 | 8,8853 | 8,8896 | 5 332 992 |
| Windows — minimal, 1 import/côté | 318 | 6,8707 | 6,9553 | 3 014 656 |
| Windows — 8 000 imports/côté | 184 295 | 20,7676 | 31,3555 | 6 569 984 |

**Méthode :** une passe d'échauffement suivie de **trois** invocations complètes d'un sous-processus, stdout redirigé vers un fichier temporaire, vérification de la version et des deux identités SHA-256 du rapport. Échantillonnage RSS/CPU nominal toutes les **2 ms** avec `psutil`; chrono monotone autour de l'exécution du sous-processus. Les observations RSS n'ont pas toutes une précision suffisante pour estimer un pic bref. Le « P95 » est calculé au rang le plus proche sur seulement trois résultats : il se confond avec le maximum observé, **ce n'est pas un quantile statistiquement robuste**. Une CPU échantillonnée à 0 ms ne démontre pas une consommation CPU nulle.

**Contexte constaté :** hôte Linux déclaré `Linux-6.17.0-1022-azure-x86_64-with-glibc2.39`, CPU rapporté `AMD EPYC 9V74 80-Core Processor` ; hôte Windows déclaré `Windows-2025Server-10.0.26100-SP0`. Les exécutables de référence ne sont pas identiques d'un OS à l'autre :
- Linux, empreinte SHA-256 du binaire : `c07540c09ff26a44c3801db59b3724db565be64e0bca1e12fb5116ad8ce2bda2`.
- Windows, empreinte SHA-256 du binaire : `4bba93233eb8d6a9babbfa8c6db3ac6af86a037fadee3c56e4510cea34f4810a`.

Le fichier JSON source contient le contexte d'environnement, la date exacte de capture, les empreintes de chacun des deux fichiers JSON d'entrée, les valeurs individuelles et les comptes d'échantillons. Les scénarios n'utilisent **aucun exécutable PE analysé**, uniquement des manifestes JSON artificiels. Aucune comparaison directe des vitesses entre OS ni seuil de performance contractuel n'est déductible ici.

**Évolution du protocole après cette capture historique :** le profileur comprend désormais un troisième scénario synthétique mélangeant imports, exports et sections (2 048 éléments de chaque catégorie par côté, noms de sections partiellement partagés et modifiés). Ses résultats doivent être consultés dans les nouveaux artefacts CI et ne sont **pas** représentés par les quatre valeurs historiques ci-dessus ; aucune mesure ultérieure ne leur est substituée sans lecture des artefacts correspondants. L'oracle CLI couvre aussi une sortie acceptée de plus de 15 Mio, distincte du rejet sans stdout d'un rapport dépassant 16 Mio.

## Limites et prochaines validations

- Le nouveau plafond de sortie JSON à 16 Mio est un **budget de rapport sérialisé**, pas un plafond de RSS, CPU, allocations temporaires ou temps d'analyse.
- Un corpus de **10–20 paires de builds PE autorisés** avec changements connus et contrôles indépendants reste requis pour l'acceptation EX-02 complète ; les deux fixtures PE synthétiques actuelles ne le remplacent pas.
- Répéter les mesures en contexte homogène et augmenter `--samples` pour examiner dispersion et variabilité. Analyser les rapports et les taux d'abstention, pas seulement les temps. Documenter chaque corpus, outil de compilation, droit d'analyse et vérité terrain.
- Surveiller toute régression majeure et, seulement avec des données représentatives, déterminer des budgets pertinents ; ne pas ajouter une contrainte CI aveugle basée sur ces quatre chiffres.

**Statut :** baseline synthétique documentée, aucune performance de production démontrée ; [issue #68](https://github.com/ELITEAYOTO/REL/issues/68) toujours partiellement ouverte.
