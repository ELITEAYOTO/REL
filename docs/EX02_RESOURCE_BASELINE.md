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

## Extension du protocole — PR #129 validée le 21 octobre 2026

Le profileur `scripts/profile_manifest_diff.py` mesure désormais la **taille exacte des octets de sortie JSON** (saut de ligne compris), l'empreinte SHA-256 des octets et l'identité de ces résultats entre répétitions de même entrée. Il conserve les observations de RSS échantillonné, CPU et durée avec la même provenance.

Un quatrième scénario synthétique `near-report-budget-8192` contient 8 192 imports artificiels différents de chaque côté, dotés d'un remplissage déterministe de 950 caractères. La condition d'acceptation vérifie **strictement plus de 15 Mio, au plus 16 Mio** de JSON sérialisé, sans dépasser 16 Mio par manifeste d'entrée. Ce cas vise la croissance mémoire du processus `rel-diff` juste sous son plafond de rapport, plutôt que de répéter le seul test de rejet déjà validé. Aucun de ces imports ne représente une table d'import PE réaliste.

Les sorties et observations individuelles ont été **lues dans les JSON des artefacts réels**, à la fois pour la [CI de PR #39515866730](https://github.com/ELITEAYOTO/REL/actions/runs/39515866730) sur la tête finale `8c5a4d555ad567e0bbc3d242466c5751b6b28920` et pour la [CI post-fusion #39516270775](https://github.com/ELITEAYOTO/REL/actions/runs/39516270775) sur le squash `58de047cfa04e2c744b562fcbb43499424c6ae93`. Les deux CI ont réussi sur Windows et Ubuntu, avec 15 artefacts publiés dans la CI post-fusion.

| CI et plateforme | Artefact GitHub ID | Rapport JSON (octets) | Temps médian (ms) | RSS maximal échantillonné (octets) |
| --- | ---: | ---: | ---: | ---: |
| PR Ubuntu | 12306928472 | 16 040 894 | 61,0518 | 68 575 232 |
| PR Windows | 12307354109 | 16 040 894 | 84,2736 | 54 239 232 |
| Nouveau `main` Ubuntu | 12308077727 | 16 040 894 | 76,2293 | 68 055 040 |
| Nouveau `main` Windows | 12307468814 | 16 040 894 | 93,1522 | 54 177 792 |

Les quatre artefacts confirment le même SHA-256 du **rapport JSON complet** : `3d15b30a27ecbefc84c77ef2ca20c66fd22841dd290b37d47fe7932cd0feb03b`. Les deux manifestes d'entrée du cas mesuraient chacun **7 971 111 octets**. Une passe d'échauffement puis **3** exécutions mesurées ont été utilisées par environnement.

Ces mesures sont dépendantes des runners et de l'échantillonnage RSS nominal à 2 ms : les maxima observés peuvent manquer des pics, et les écarts de temps entre OS ne sont pas comparables comme des classements de performance. Les imports longuement remplis sont volontairement artificiels et ne représentent pas un véritable corpus PE. Ce succès n'établit **ni plafond global de RAM/CPU**, ni sûreté des entrées arbitraires, ni validation complète d'EX-02. Voir [la preuve détaillée de l'issue #68](https://github.com/ELITEAYOTO/REL/issues/68#issuecomment-6304298115). L'issue #68 reste ouverte.


## Extension des observations natives — portée de la PR expérimentale

Le profileur EX-02 réutilise le suivi du **processus enfant direct** déjà
déployé pour `rel-inspect` : sous Linux, `wait4` fournit `ru_maxrss`
(converti de KiB en octets), et le CPU noyau+utilisateur ; sous Windows,
une copie du handle de création donne `PeakWorkingSetSize` et
`GetProcessTimes` après la fin du processus. Les valeurs individuelles
et maxima sont ajoutés aux mêmes artefacts JSON que les quatre scénarios
synthétiques ; les champs des autres OS restent à `null`.

Cette méthode répond au risque de **pics ratés par l'échantillonnage à 2 ms**,
mais le working set Windows et le RSS Linux n'ont pas des définitions
identiques. Les valeurs sont spécifiques au processus `rel-diff` suivi, pas
à ses descendants, et ne limitent ni la mémoire engagée, ni le CPU, ni
l'arborescence de processus. Les vieux artefacts ne portent pas ces
champs. L'intégration et les chiffres doivent être établis à partir des
CI sur le HEAD de PR puis du nouveau `main`, et consignés dans
[l'issue #68](https://github.com/ELITEAYOTO/REL/issues/68).
