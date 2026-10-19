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

### Diagnostic des deux horodatages et expérimentation `/Brepro` (19 octobre 2026)

Les résultats de deux recompilations du **même** corpus, dans un seul job Windows [#39211513812](https://github.com/ELITEAYOTO/REL/actions/runs/39211513812), ont été extraits de l'artefact `rel-ex02-repeat-build-windows` :

| Mode de compilation | PE identiques entre deux compilations | Nature des octets différents |
| --- | ---: | --- |
| Normal : `/INCREMENTAL:NO` | **0 / 8** | **Exactement deux octets par fichier** : un octet du champ COFF `TimeDateStamp`, un octet du champ `IMAGE_DEBUG_DIRECTORY.TimeDateStamp` |
| Expérimental : `/INCREMENTAL:NO /Brepro` | **8 / 8** | Aucun octet différent entre les deux compilations |

Les catégories de changements proviennent des **offsets exacts** des structures PE lus par `pefile`, et non simplement d'une supposition sur la section `.rdata`. Les deux horodatages étaient modifiés pour chaque variante normale ; le reste des octets était identique dans cette expérience. Cela localise la source *immédiate* des SHA divergents dans **ce corpus**. Cela ne prouve rien pour tous les fichiers PE ni pour tout code exécutable.

Pour isoler l'effet du paramètre de lien, le constructeur `scripts/build_windows_diff_pairs.cmd` dispose désormais d'un mode optionnel `repro` qui crée **un répertoire distinct** `corpus-pairs-repro` sans modifier les sorties du mode normal. Les deux outils MSVC et Clang-cl compilent les quatre mêmes variantes, et l'éditeur de liens reçoit `/Brepro`. Les PE produits restent des **données statiques**, jamais exécutées. Le résultat de [#39211753591](https://github.com/ELITEAYOTO/REL/actions/runs/39211753591), artefact `rel-ex02-brepro-experiment-windows`, donne **8/8 SHA identiques** entre deux builds de ce mode. L'oracle indépendant conserve aussi 8 cas / 16 paires A/B valides.

**Contrôle entre deux jobs CI distincts :** les artefacts `rel-ex02-brepro-experiment-windows` de [#39211753591](https://github.com/ELITEAYOTO/REL/actions/runs/39211753591) et [#39211759051](https://github.com/ELITEAYOTO/REL/actions/runs/39211759051) ont été téléchargés et comparés. **Les huit SHA-256 bruts coïncident entre les deux jobs**, avec la même empreinte de source C `5fa642567cd392572364cecd542d3b3cfa57623c430902e5499190d3621515cf` et les mêmes bannières MSVC `19.51.36260` / Clang-cl `20.1.8`. Cette observation **n'est pas** une garantie éternelle de builds reproductibles sur de futurs compilateurs, SDK ou runners.

Références externes : [LLVM, *Deterministic builds with clang and lld*](https://blog.llvm.org/2019/11/deterministic-builds-with-clang-and-lld.html) explique l'usage de `/Brepro` sur Windows ; [Microsoft, PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) décrit les entrées `IMAGE_DEBUG_TYPE_REPRO` et précise que certains champs d'horodatage peuvent contenir des éléments dérivés de hashes plutôt qu'une date réelle.

**Garde-fou CI ajouté :** Le comparateur rejette également les contradictions **internes à un rapport** : deux cas ayant un même SHA-256 brut doivent partager taille et nombres d'imports/exports ; une paire entre ces octets identiques ne peut déclarer d'ajouts/retraits ni un statut de sections `changed` (l'ambiguïté de noms reste possible). Des tests négatifs couvrent ces violations. Cette cohérence documentaire ne prouve pas l'authenticité de l'artefact.

Le comparateur d'artefacts recoupe également les effectifs d'imports et d'exports de chaque binaire avec les listes d'ajouts/retraits des 16 paires. Pour un diff exact d'ensembles, effectif droit = effectif gauche + ajouts - retraits ; les ajouts ne peuvent dépasser l'effectif droit ni les retraits l'effectif gauche. Des tests négatifs couvrent les preuves impossibles ainsi qu'un échange équilibré valide. Cette vérification de cohérence ne remplace pas l'oracle `pefile` sur les octets réels.

Les outils de lecture du comparateur exigent à présent des fichiers ordinaires pour les rapports JSON et les ZIP téléchargés. Sous Unix, l'ouverture de la feuille est non bloquante et sans suivi des symlinks ; une nouvelle vérification du descripteur refuse aussi un changement d'identité observé entre le précontrôle et l'ouverture. Le ZIP compressé a une limite de 32 Mio et le membre JSON décompressé garde la limite de 2 Mio ; les cas FIFO JSON/ZIP sont testés avec une limite de temps de processus. **Ce n'est pas une protection atomique des répertoires ancêtres ni une sandbox de système de fichiers hostile.**

**Garde-fou CI historique :** `scripts/compare_ex02_corpus_runs.py` accepte deux rapports JSON (ou deux ZIP d'artefacts téléchargés) et vérifie le même schéma, la source, les bannières des compilateurs, les flags de lien et les huit identités PE. Son mode `--require-identical` s'applique **uniquement au mode `brepro`**, pour éviter d'imposer au mode normal une promesse qu'il ne remplit pas. La CI teste la commande sur deux compilations `/Brepro` dans un seul job, sans hardcoder de SHA de PE entre futures versions d'outils. Les validations du dernier commit doivent toujours être consultées avant d'affirmer que ce nouveau garde-fou est vert.

### Vérification de provenance complète sur deux jobs de même commit

L'outil Windows **capture maintenant les versions SDK/Visual C++ dans le shell initialisé par `VsDevCmd`**, les conserve sous forme de fichiers texte ne contenant ni chemin absolu ni secret, puis les inclut dans la preuve publiée. Il relève aussi le linker, le SHA-256 du script de compilation et la version de l'image du runner GitHub. Le comparateur de rapports refuse de rapprocher des builds qui divergent sur ces champs.

Deux artefacts téléchargés de [CI #39213276412](https://github.com/ELITEAYOTO/REL/actions/runs/39213276412) et [CI #39213281869](https://github.com/ELITEAYOTO/REL/actions/runs/39213281869), provenant du même commit, contiennent exactement les mêmes valeurs :
- Linker : `Microsoft (R) Incremental Linker Version 14.51.36260.0`.
- Windows SDK : `10.0.26100.0` ; Visual C++ tools : `14.51.36231`.
- Image GitHub : `win25-vs2026` / `20261007.264.1`.
- SHA du script de compilation : `d76f9f3124899f17d64d0a1b28c69e1d5061424d4aa9151f6831b7526fb8bf89`.
- SHA de la source C : `5fa642567cd392572364cecd542d3b3cfa57623c430902e5499190d3621515cf`.
- **Huit SHA de PE identiques sur huit**, dans le mode expérimental `brepro`, entre ces deux jobs.

Le premier prototype de collecte interrogeait les variables SDK dans le script Python exécuté lors d'une étape CI différente : elles étaient alors absentes. Ce problème de traçabilité a été corrigé en enregistrant les versions **au moment de la compilation**, là où l'environnement est effectivement présent. Même cette provenance enrichie ne fige pas l'ensemble des dépendances système ; éviter toute affirmation de reproductibilité universelle.

## Limites et prochaines étapes

- Deux compilateurs sur le même environnement Windows et une **seule source C** paramétrée n'établissent pas la diversité réelle des programmes commerciaux/open source, des options de compilation, ni des différents changements entre releases.
- Plusieurs builds peuvent produire des deltas de métadonnées nuls malgré des SHA-256 binaires différents. Ce n'est ni un bug ni une preuve que leur code exécute la même chose.
- Le parseur `pefile` constitue un contrôle **indépendant de Goblin**, mais il n'est pas une vérité universelle sur tous les PE malformés.
- Environnement compilateur/SDK Windows variable dans le temps : conserver les versions et SHA des artefacts, **pas** des hashes binaires constants dans le code source.
- Validation complète d'EX-02 encore ouverte : corpus de 10–20 paires de *builds logiciels autorisés distincts*, couverture ordinals/retardés, temps et RSS représentatifs, revue des cas `ambiguous` et du contrat numérique.

Voir [spécification EX-02](specs/METADATA_DIFF_PILOT.md), [issue #15](https://github.com/ELITEAYOTO/REL/issues/15), [CI de la PR #62](https://github.com/ELITEAYOTO/REL/pull/62/checks).
