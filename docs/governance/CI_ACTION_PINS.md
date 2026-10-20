# CI — Épinglage des actions GitHub

**Décision : conserver les actions first-party sur des SHA de commit immuables, avec mise à jour contrôlée.**
**Révision proposée le 2026-10-20 : versions Node.js 24 sur la branche candidate, validation CI requise avant fusion.**
Suivi : [issue #72](https://github.com/ELITEAYOTO/REL/issues/72).

## Références proposées, vérifiées sur les dépôts officiels

| Action | Référence officielle contrôlée | Commit SHA épinglé dans les workflows | Runtime déclaré |
| --- | --- | --- | --- |
| [actions/checkout](https://github.com/actions/checkout) | `refs/tags/v6` | `d23441a48e516b6c34aea4fa41551a30e30af803` | `node24` |
| [actions/setup-python](https://github.com/actions/setup-python) | `refs/tags/v6` | `ece7cb06caefa5fff74198d8649806c4678c61a1` | `node24` |
| [actions/upload-artifact](https://github.com/actions/upload-artifact) | `refs/tags/v6` | `b7c566a772e6b6bfb58ed0dc250532a479d7789f` | `node24` |

**Méthode :** résolution de `/repos/actions/<action>/git/ref/tags/v6` via l'API publique GitHub, puis lecture de `action.yml` à chaque SHA exact (et documentation amont). Les commentaires `# v6` sont descriptifs ; seuls les 40 caractères hexadécimaux pilotent l'exécution. Ne jamais remplacer ces valeurs par des versions devinées.

La documentation officielle des actions v6 demande un runner >= `2.327.1`. Le journal du CI REL [#39394195143](https://github.com/ELITEAYOTO/REL/actions/runs/39394195143) et la campagne fuzz [#39395365353](https://github.com/ELITEAYOTO/REL/actions/runs/39395365353) ont tous deux enregistré `2.337.0`. Cette observation n'est pas une garantie sur les futurs runners. `checkout@v6` stocke différemment ses informations d'authentification et les usages Git authentifiés dans une action Docker demandent un runner >= `2.329.0` ; REL n'effectue pas cette opération Docker dans ses workflows contrôlés.

**Portée du changement :** `ci.yml`, `fuzz.yml` et `fuzz-long.yml` utilisent désormais les trois SHA ci-dessus. Une vérification standard-library (`python scripts/check_ci_action_pins.py --self-test` et `python scripts/check_ci_action_pins.py`) échoue si une action `actions/*` inconnue, flottante ou différente des SHA explicitement revus apparaît dans l'un de ces fichiers. Le workflow manuel `fuzz-long.yml` n'est PAS exécuté uniquement du fait de cette modification ; sa compatibilité runtime complète n'est pas prouvée sans lancement volontaire. Aucun changement des noms d'artefacts, paramètres ni permissions du workflow n'est intentionnel.

## Historique immuable et limites de la décision

- [PR #73](https://github.com/ELITEAYOTO/REL/pull/73) avait introduit les SHA initiaux : `checkout@11d5960a326750d5838078e36cf38b85af677262` (`v4`), `setup-python@a26af69be951a213d495a4c3e4e4022e16d87065` (`v5`) et `upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02` (`v4`). Les journaux REL [CI #39395365157](https://github.com/ELITEAYOTO/REL/actions/runs/39395365157) signalaient une exécution forcée Node.js 24 de ces anciennes actions Node.js 20.
- La pile JSON Schema reste épinglée en versions dans [ci-jsonschema-requirements.txt](../../scripts/ci-jsonschema-requirements.txt) : `jsonschema==4.26.0`, `attrs==26.1.0`, `jsonschema-specifications==2025.9.1`, `referencing==0.37.0`, `rpds-py==2026.9.1`, `typing-extensions==4.16.0`. Ce ne sont pas des hashes de wheels ni un environnement hermétique.
- Les images `windows-latest`/`ubuntu-latest`, les SDK, les installations APT et la disponibilité de la nightly fuzz peuvent dériver dans le temps ; les SHAs des actions ne contrôlent pas cela.
- Un pin ne constitue pas un audit de sécurité du code de l'action et ne garantit pas une production de preuves identiques octet à octet. La CI de PR sur SHA final et une CI distincte post-squash de `main` restent obligatoires.
- `fuzz-long.yml` est volontairement à déclenchement manuel. Aucun fuzz prolongé redondant n'est déclenché dans cette PR.

## Politique de maintenance

Pour chaque mise à jour, vérifier le tag et l'objet Git `commit` dans le dépôt éditeur, lire `action.yml` et les notes de migration, vérifier les versions de runner requises, puis changer les SHA des workflows, la table de ce document et le validateur en **une PR dédiée**. Enregistrer la CI exacte Windows et Ubuntu, le bounded fuzz lorsque `fuzz.yml` change, les noms/tailles des artefacts et la CI post-fusion. Ne clôturer l'issue #72 qu'après vérification de ses critères complets ; la vérification des hashes de packages et l'environnement hosted restent des limites indépendantes.
