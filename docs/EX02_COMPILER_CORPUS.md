# EX-02 — Corpus A/B PE compilé, vérifié indépendamment

**Statut : expérimental, dans la PR #62 ; gate EX-02 non validée.**
Ce corpus complète les deux anciens fichiers PE synthétiques et les manifestes JSON golden.
Il ne remplace **pas** 10–20 paires de logiciels réels, autorisés et représentatifs.

## Provenance et génération

Source unique sous contrôle de version :
`fixtures/probes/diff_version_probe.c`.
Build Windows : `scripts/build_windows_diff_pairs.cmd`.

- Compilation x64 MSVC `cl.exe`, optimisation `/O2 /MD`, avertissements `/W4 /WX`, variante `/DREL_DIFF_VARIANT=N`, édition des liens `/INCREMENTAL:NO`.
- Deuxième compilation de la même variante via LLVM `clang-cl.exe` avec les mêmes options ; aucune supposition de bit-for-bit reproductibilité entre compilateurs.
- Chaque compilation produit un exécutable PE destiné à **l'analyse statique uniquement**. La CI ne lance **jamais** ces fichiers.
- Le script de construction échoue si l'outillage ou une sortie manque ; les artefacts du contrôle enregistrent le hash SHA-256 de la source, des huit exécutables, le nom/la version des compilateurs et le SHA du commit GitHub.

| Variante | Import distinct recherché (source C) | Exports déclarés |
| --- | --- | --- |
| v1 | `KERNEL32!GetTickCount` | `rel_diff_transform` |
| v2 | `KERNEL32!GetTickCount64` | `rel_diff_transform`, `rel_diff_new_api` |
| v3 | `KERNEL32!GetComputerNameW` | `rel_diff_transform`, `rel_diff_other_api` |
| v4 | `KERNEL32!GetTickCount64` | `rel_diff_transform`, `rel_diff_new_api`, `rel_diff_other_api` |

Chaque variante existe en version **MSVC et Clang-cl**, soit **8 exécutables distincts**.
Les 16 paires choisies sont les six combinaisons non ordonnées de quatre variantes au sein de chaque compilateur (12 paires), plus quatre comparaisons MSVC/Clang-cl pour une même variante. Ce sont **16 comparaisons sélectionnées sur 8 builds**, pas 16 projets ni 16 versions indépendantes d'un logiciel.

## Oracle et critères vérifiés

Script indépendant : `scripts/check_windows_diff_pairs.py`.

1. `pefile` lit statiquement le PE, confirme `x86_64`, les en-têtes, la liste des imports directs, les exports nommés et les champs de chaque section (nom, offset fichier, taille brute, RVA).
2. L'oracle vérifie que le seul des trois symboles d'API tracés attendu pour chaque variante est importé et que les exports correspondent exactement aux noms déclarés dans le code source. Il compare ensuite **tous** les imports/exports/sections observés avec les manifestes `rel-inspect`, et vérifie les SHA-256 réels des octets lus.
3. Pour chaque paire : l'oracle calcule indépendamment depuis `pefile` les deltas attendus, exécute le vrai `rel-diff`, valide la sortie contre `contracts/experimental/manifest-diff.schema.json` et compare les flags de taille/architecture, les listes d'imports/exports, les sections et le signal limité de casse des DLL.
4. Il répète chaque paire dans le sens inverse et vérifie les huit comparaisons A/A. Une section au nom répété impose une abstention plutôt qu'un appariement spéculatif.
5. La CI produit `rel-ex02-compiler-pairs.json`, sauvegardé par `actions/upload-artifact` sous le nom `rel-ex02-compiler-pairs-windows`. Le JSON conserve la provenance et la liste des ajouts/suppressions observés.

Le contrôle peut montrer qu'un changement **de source** induit certains changements de **métadonnées PE**. Il ne peut pas démontrer l'équivalence binaire, fonctionnelle ou comportementale entre builds.

**Reproduction Windows** (avec MSVC, Clang-cl, pefile, jsonschema et binaires REL compilés en release) :

```cmd
call scripts\build_windows_diff_pairs.cmd
python scripts\check_windows_diff_pairs.py --inspector target\release\rel-inspect.exe --diff target\release\rel-diff.exe --corpus corpus-pairs --output rel-ex02-compiler-pairs.json
```

Les tests Linux continuent à couvrir les oracles Rust et JSON indépendants ainsi que la chaîne `rel-inspect` / `rel-diff` sur les deux PE synthétiques suivis en Git. La compilation native du corpus C dépend du toolchain Windows, donc n'est pas annoncée comme testée par la CI Linux.

## Première exécution vérifiée

Le workflow [#39209103249](https://github.com/ELITEAYOTO/REL/actions/runs/39209103249), au commit [`36419af`](https://github.com/ELITEAYOTO/REL/commit/36419af32cc5a52e80a84db21db5ab425bb485bf), a réussi sur Windows et Linux. La CI Windows a exécuté le builder et l'oracle ; Ubuntu exécute les autres tests, mais **pas** le builder MSVC/Clang-cl. Le contenu de l'artefact `rel-ex02-compiler-pairs-windows` a été relu :

- **8 PE x64** compilés depuis `fixtures/probes/diff_version_probe.c`, empreinte de source `5fa642567cd392572364cecd542d3b3cfa57623c430902e5499190d3621515cf`.
- Compilateurs : **MSVC 19.51.36260 x64** et **Clang-cl 20.1.8**.
- **16 paires A/B** testées dans les deux sens, plus 8 vérifications A/A : tous les deltas rapportés correspondent aux listes PE observées indépendamment par `pefile`.
- Sur les 16 paires : 10 ont un delta d'imports directs, 12 un delta d'exports nommés et 4 des changements de métadonnées de sections. Les groupes peuvent se recouvrir ; ces comptes ne sont **pas** des taux de précision sur logiciel réel.
- L'API `GetComputerNameW` de la variante v3 remplace un autre import ; pour certaines paires, des métadonnées de sections changent aussi. Trois comparaisons entre compilateurs de même variante ne montrent aucune modification de sections alors que l'autre en montre une : la notion de delta est limitée au **contrat de métadonnées observables**.
- Aucun PE généré n'a été exécuté. Le SHA de chaque PE figure dans l'artefact pour rendre la vérification de cette exécution reproductible.

Ces preuves s'appliquent à **ce commit de la PR et ce job Windows**, non aux futurs exécutables compilés avec d'autres versions d'outils.

### Limite de reproductibilité binaire observée entre CI

Comparaison des artefacts Windows [#39209103249](https://github.com/ELITEAYOTO/REL/actions/runs/39209103249) et [#39209894303](https://github.com/ELITEAYOTO/REL/actions/runs/39209894303) : les **huit builds ont changé de SHA-256**, alors que les tailles enregistrées de chacun sont restées identiques, les sources C avaient le même SHA et les versions de compilateur affichées sont identiques (MSVC 19.51.36260 et Clang-cl 20.1.8). Le corpus n'est donc **pas bit-à-bit reproductible entre ces deux jobs** dans sa configuration actuelle. Ce constat ne localise **pas** la cause (horodatage, linker, SDK, environnement, etc.). Chaque oracle de CI reste valide pour les octets de **son propre job**, sans attribuer à un changement de comportement une variation de hash. Diagnostic à mener dans [l'issue #69](https://github.com/ELITEAYOTO/REL/issues/69) avant de figer des hashes inter-jobs.

## Limites et prochaines étapes

- Deux compilateurs sur le même environnement Windows et une **seule source C** paramétrée n'établissent pas la diversité réelle des programmes commerciaux/open source, des options de compilation, ni des différents changements entre releases.
- Plusieurs builds peuvent produire des deltas de métadonnées nuls malgré des SHA-256 binaires différents. Ce n'est ni un bug ni une preuve que leur code exécute la même chose.
- Le parseur `pefile` constitue un contrôle **indépendant de Goblin**, mais il n'est pas une vérité universelle sur tous les PE malformés.
- Environnement compilateur/SDK Windows variable dans le temps : conserver les versions et SHA des artefacts, **pas** des hashes binaires constants dans le code source.
- Validation complète d'EX-02 encore ouverte : corpus de 10–20 paires de *builds logiciels autorisés distincts*, couverture ordinals/retardés, temps et RSS représentatifs, revue des cas `ambiguous` et du contrat numérique.

Voir [spécification EX-02](specs/METADATA_DIFF_PILOT.md), [issue #15](https://github.com/ELITEAYOTO/REL/issues/15), [CI de la PR #62](https://github.com/ELITEAYOTO/REL/pull/62/checks).
