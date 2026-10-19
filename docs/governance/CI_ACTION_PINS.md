# CI — Épinglage des actions GitHub

**État : décision d'hygiène CI en attente d'acceptation dans la PR dédiée**  
**Vérifié le : 2026-10-19**  
**Suivi : [issue #72](https://github.com/ELITEAYOTO/REL/issues/72)**

## Objectif et périmètre

Réduire les variations silencieuses des actions utilisées pour générer les preuves de tests et les artefacts de REL. Les fichiers `.github/workflows/ci.yml` et `.github/workflows/fuzz.yml` utilisaient précédemment des références de version majeure **mutables**. Ce changement épingle les mêmes familles d'actions sur les **objets commit résolus au moment de la vérification**. Il ne prétend ni démontrer une compromission passée ni rendre l'ensemble de la CI bit-à-bit reproductible.

| Action GitHub | Ref résolue depuis le dépôt officiel | Commit épinglé |
| --- | --- | --- |
| [actions/checkout](https://github.com/actions/checkout) | `refs/tags/v4` | `11d5960a326750d5838078e36cf38b85af677262` |
| [actions/setup-python](https://github.com/actions/setup-python) | `refs/tags/v5` | `a26af69be951a213d495a4c3e4e4022e16d87065` |
| [actions/upload-artifact](https://github.com/actions/upload-artifact) | `refs/tags/v4` | `ea165f8d65b6e75b540449e92b4886f43607fa02` |

**Méthode de vérification :** interrogation des points d'API GitHub `/repos/<owner>/<repo>/git/ref/tags/<major>`. Chacun a retourné un objet `type=commit` et le SHA intégral indiqué, sans supposer le contenu d'une version future. Les commentaires `# v4` / `# v5` dans le workflow sont **informatifs** : seul le commit complet détermine les octets de l'action.

## Limites

- Le workflow utilise toujours des versions de runners et SDK hébergées par GitHub (`ubuntu-latest`, `windows-latest`) : leurs images changent. Les outils de développement Rust, Microsoft, Python et les packages système ne sont pas entièrement immobilisés.
- `jsonschema>=4,<5` et ses dépendances transitives restent non verrouillés. Il s'agit d'un **point ouvert de l'issue #72** à traiter dans une étape séparée, avec une méthode d'actualisation et une vérification Windows/Linux. `pefile` et `psutil` ont une version directe précise, pas un lock complet des transitives.
- L'épinglage d'une action sur un commit ne constitue ni audit de sécurité de son code, ni protection contre toutes les dépendances qu'elle exécute.
- Le job de fuzzing nocturne utilise `nightly`, une autre source de variabilité ; ne pas prétendre que l'exercice reproduit exactement les mêmes octets de campagne.
- La PR EX-02 [#62](https://github.com/ELITEAYOTO/REL/pull/62) modifie également `ci.yml`, mais reste **en brouillon**. Après une fusion de cet épinglage sur `main`, **vérifier le net diff et les références réellement utilisées** avant une éventuelle fusion de #62.

## Politique de maintenance

Lorsqu'un changement de version d'action est justifié : consulter le dépôt éditeur, vérifier l'objet tag/release, documenter le commit complet et la raison du changement, appliquer en PR isolée, faire passer les CI Linux et Windows **sur le dernier commit**, puis les CI de `main` après fusion. Si le job fuzzing s'exécute à cause du changement de son propre workflow, vérifier son résultat sans confondre un crash fuzz de bibliothèque et une erreur du pinning.

**Critère de sortie du changement présent :** aucun `uses: actions/...@v4` / `@v5` mutable ne reste dans ces deux workflows, et les tests réellement déclenchés par GitHub Actions se terminent avec succès. Ne pas clôturer l'issue #72 tant que les contraintes Python ne sont pas évaluées.
