# ADR-0014 — Empreinte binaire brute et reproductibilité contrôlée des builds PE

**Statut : PROPOSÉ — document présent sur `main` depuis [PR #62](https://github.com/ELITEAYOTO/REL/pull/62), sans adoption formelle de cette ADR**  
**Date : 2026-10-19**  
**Rattachement :** [ADR-0013](ADR-0013-vision-evidence-evolution.md), [audit #69](https://github.com/ELITEAYOTO/REL/issues/69), [protocole EX-02](../EX02_COMPILER_CORPUS.md).

## Contexte mesuré

Un corpus source contrôlé de quatre variantes PE, chacune compilée avec MSVC et Clang-cl (8 exécutables) a montré deux résultats distincts :

1. **Compilation normale répétée** : huit SHA-256 différents dans un même job Windows, avec exactement **deux octets divergents par PE**, localisés au moyen de `pefile` dans `IMAGE_FILE_HEADER.TimeDateStamp` et `IMAGE_DEBUG_DIRECTORY.TimeDateStamp`. Le reste des octets était identique dans l'échantillon observé. [CI et artefacts #39211513812](https://github.com/ELITEAYOTO/REL/actions/runs/39211513812).
2. **Compilation avec `/Brepro` au linker, en dossier séparé** : huit PE **strictement identiques octet à octet** lors de deux compilations dans le même job, puis mêmes huit SHA-256 dans deux jobs distincts avec source et versions déclarées identiques. [CI #39211753591](https://github.com/ELITEAYOTO/REL/actions/runs/39211753591), [CI #39211759051](https://github.com/ELITEAYOTO/REL/actions/runs/39211759051). Les CI ultérieures enregistrent en plus le linker, les versions de SDK et Visual C++, l'image runner et le SHA du script.

Ces observations sont **spécifiques** à huit petits programmes PE statiquement inspectés ; aucun PE n'a été exécuté.

## Décision proposée

1. **Conserver l'identité source brute :** `binary_sha256` reste l'empreinte SHA-256 de **tous les octets du fichier**, même lorsque seules des métadonnées d'horodatage changent. Une empreinte normalisée ne remplace jamais ce champ. Aucun changement de `binary-manifest v1.0.0`.
2. **Ne pas inférer de changement comportemental :** une différence de SHA-256 ou de timestamp, un changement de section ou un rapport EX-02 sans delta ne prouvent ni identité de code, ni différence fonctionnelle, ni équivalence de comportement.
3. **Isoler la reproductibilité de la comparaison :** le builder expérimental fournit un mode `repro` distinct qui passe `/Brepro`, en préservant les builds ordinaires et leur preuve brute. Ne pas activer un effacement automatique d'horodatages dans REL.
4. **Évaluer la reproductibilité avec une provenance explicite :** comparer les deux rapports de corpus uniquement si versions de schémas, SHA du source C, SHA du script de build, bannières des compilateurs et du linker, versions SDK/VC, image runner et flags de lien correspondent. Les entrées / sorties et SHA restent contrôlés.
5. **Limiter le garde-fou :** exiger l'identité bit-à-bit seulement sur deux reconstructions contrôlées en mode `brepro` dans un même job, pas sur tous les binaires de l'écosystème ; vérifier à nouveau à chaque évolution du toolchain. Un outil de comparaison JSON/ZIP permet un contrôle inter-jobs hors de la CI, sans valeur SHA codée en dur.
6. **Conserver les limites :** les observateurs de fichiers PE et la CI ne certifient ni sécurité face à des fichiers hostiles, ni exhaustivité du schéma public, ni reproductibilité sous tous les environnements, ni validité comportementale.

## Alternatives évaluées

- **Effacer les octets d'horodatage avant SHA-256 : refusé.** Cela détruirait la traçabilité des octets exacts, masquerait les écarts réels et confondrait fichier observé et représentation dérivée.
- **Fixer des empreintes PE absolues entre futures versions de toolchains : refusé.** Elles varient légitimement en cas d'évolution des compilateurs, options, bibliothèques ou SDK.
- **Exiger la reproductibilité du mode de compilation normal : refusé.** Contredit par les huit cas observés ; le mode `/Brepro` est explicitement facultatif et expérimental.
- **Faire de la reproductibilité une preuve d'équivalence comportementale : refusé.** Les garanties sont de nature différente.

## Conséquences et suivi

- Les deux modes de build ajoutent des validations au workflow Windows, donc du temps CI. Les binaires du corpus restent des **données non exécutées**.
- Le format de sortie EX-02 expérimental `0.1.0-experimental` et le contrat manifeste public v1 ne sont pas modifiés.
- Les travaux futurs peuvent offrir une **vue dérivée** des différences de métadonnées, explicitement étiquetée avec sa règle/version, mais doivent toujours conserver les octets et empreintes originales.
- La gate EX-02 complète (corpus de builds autorisés représentatif, couverture, benchmark, gestion des ambiguïtés) **reste ouverte** ; aucune transition vers la décompilation n'est revendiquée.

## Références techniques externes

- [LLVM — Deterministic builds with clang and lld](https://blog.llvm.org/2019/11/deterministic-builds-with-clang-and-lld.html) : discussion du paramètre `/Brepro` et des horodatages PE.
- [Microsoft — PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) : `IMAGE_DEBUG_TYPE_REPRO` et possibilité que des champs TimeDateStamp servent de valeurs dérivées du hash plutôt que de dates réelles.

**Condition d'adoption :** revue de cette ADR et de la portée réelle des preuves sur la PR #62, puis décision explicite lors d'une fusion validée, pas implicitement à sa création.
