# REL — Modèle de menace alpha

**Statut : analyse initiale et engagements de tests, PAS une déclaration de sûreté.**  
Référence : [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md).

## Frontières

- Entrées PE non fiables : structures malformées, offsets trompeurs, tables géantes, fichiers changeants, symlinks, chemins inattendus.
- Entrées JSON non fiables : manifests incomplets, volontairement falsifiés ou excessivement volumineux.
- Dépendances extérieures : goblin, futur Ghidra/Java, toolchains, plugins, futures capacités IA.
- Actifs à protéger : machine hôte, CPU/RAM/disque, fichiers source, secrets/chemins privés, rapports et artefacts CI.

## Risques et mesures

| Risque | Situation vérifiée | Actions requises |
| --- | --- | --- |
| Lecture et course fichier | Ancien `metadata` puis `read` remplacé par une lecture bornée sur descripteur unique ([PR #17](https://github.com/ELITEAYOTO/REL/pull/17), [CI #39103698604](https://github.com/ELITEAYOTO/REL/actions/runs/39103698604) verified) ; pré-ouverture `symlink_metadata` non atomique | protéger races d'ouverture, modifications concurrentes de même taille, chemins spéciaux et RSS total ; voir [P15A_BOUNDED_INPUT](P15A_BOUNDED_INPUT.md) |
| Coût disproportionné | une petite entrée peut déclencher un parsing coûteux ; JSON borné à 16 MiB, instrument d'observation CPU/RSS validé en [CI #39104870706](https://github.com/ELITEAYOTO/REL/actions/runs/39104870706), pas de limite de mémoire/CPU du parseur | profils RSS/CPU représentatifs, budgets de structures/temps/mémoire ; [sortie bornée](P15A_BOUNDED_OUTPUT.md), [profilage](../P15_RESOURCE_PROFILING.md) |
| En-têtes PE hostiles | prévalidation allocation-free des offsets/tailles NT/COFF et ≤96 sections validée ([CI 39105600717](https://github.com/ELITEAYOTO/REL/actions/runs/39105600717), [fuzz 39105600726](https://github.com/ELITEAYOTO/REL/actions/runs/39105600726)) | ne couvre pas les tables d'import/export/TLS, les allocations dérivées et les fichiers non conformes ; voir [PE preflight](P15A_PE_PREFLIGHT.md) |
| PE directory declarations | preflight cap ajouté sur tailles déclarées des imports/exports et nombre annoncé d'exports ([CI 39106804688](https://github.com/ELITEAYOTO/REL/actions/runs/39106804688), [libFuzzer 39106804686](https://github.com/ELITEAYOTO/REL/actions/runs/39106804686) réussis sur le corpus contrôlé) | limites non garanties par goblin pour toutes les allocations ; [contrôles et restrictions](P15A_DIRECTORY_BUDGETS.md) |
| Panic tiers | ancien F001 `goblin 0.9.3`, reproducer conservé | version 0.10.7 verrouillée et fuzz ; `catch_unwind` ≠ sandbox |
| Exécution | P1 ne lance aucun EXE soumis | préserver statique par défaut ; futures expériences dynamiques opt-in isolées |
| Faux résultats | tableau vide ou warning absent sans état de couverture | états d'extraction et diagnostics explicites |
| Rapport privé | sections/chaînes/chemins peuvent révéler infos | expurger secrets, pas d'embarquement automatique de binaires propriétaires |
| Chaîne logicielle | stable Cargo.lock ; fuzz nightly encore à figer | audit licences/advisories, SHA des actions, permissions minimales |

## Périmètre autorisé

**Alpha :** corpus légal et contrôlé, analyse statique seulement. Ne pas présenter REL comme un analyseur sécurisé de binaires adversariaux arbitraires. Un processus enfant limité n'est pas automatiquement une sandbox ; l'isolation Windows/Linux doit être spécifiée et testée avant une telle affirmation. Pas de contournement anti-cheat ni instrumentation de jeux protégés en ligne.

## Gates avant élargissement

Tests de fichiers changeants, symlinks, budgets structurels et RSS/CPU, corpus diversifié, fuzz plus long avec régressions minimisées, modèle d'isolation par OS, politique de confidentialités des sorties et revue de dépendances. Documenter les risques résiduels. Une CI verte est nécessaire mais non suffisante.


## Raw-section range preflight (PR CI verified)

The PE preflight is being extended to reject non-empty section raw ranges extending past the input bytes. This can stop some malformed section layouts before goblin but does **not** validate all PE structure semantics, cap parser CPU/RSS, eliminate races in file acquisition, or create a sandbox. [Windows/Linux CI #39108469504](https://github.com/ELITEAYOTO/REL/actions/runs/39108469504) and [fuzz #39108469495](https://github.com/ELITEAYOTO/REL/actions/runs/39108469495) passed controlled tests; compatibility on broader legal corpora remains pending; see [P15A_PE_PREFLIGHT](P15A_PE_PREFLIGHT.md).

## P1.5-A Unix input-open follow-up (PR CI verified)

A targeted Unix-only change requests kernel `O_NOFOLLOW` for the final input path component at open time and `O_NONBLOCK` to avoid blocked opening of a swapped FIFO; it retains the single-descriptor regular-file and size checks. No cross-platform or hostile-filesystem guarantee: Windows and ancestor symlinks, concurrent same-length modifications, devices and CPU/RSS/worker isolation remain open. Read [bounded input policy](P15A_BOUNDED_INPUT.md); [PR #24 CI #39109205165](https://github.com/ELITEAYOTO/REL/actions/runs/39109205165) succeeded Windows/Linux in the narrow described scope; post-merge verification and all remaining risks still apply.

## Windows final-component reparse-point guard (PR CI verified)

The CLI now proposes opening the final Windows input component with `FILE_FLAG_OPEN_REPARSE_POINT` and rejecting reparse-point attributes from the opened handle. This narrows the path preflight/open race for the *leaf* only; ancestor junction/reparse paths, other devices, hard links, content changes, resource limits and sandboxing remain open. A dedicated Windows CI step actually created a symbolic link and verified that the opened-handle policy rejected it, as recorded in [CI Windows/Linux #39146000935](https://github.com/ELITEAYOTO/REL/actions/runs/39146000935). Local developers without symlink privileges can still skip only that regression; hosted Windows CI explicitly fails instead of skipping. See [bounded input policy](P15A_BOUNDED_INPUT.md).

## Windows input read-sharing (PR CI verified)

A small P1.5-A increment asks Windows to share only read access while REL holds its file input descriptor, so ordinary conflicting writer/delete opens fail rather than silently mutating bytes during analysis. This is a compatibility tradeoff on live files and is not a hostile-file sandbox, kernel-verified coherent snapshot, guarantee against memory-mapped writes or CPU/RAM limit. Controlled Windows/Linux CI and regressions passed [Windows/Linux CI #39146872882](https://github.com/ELITEAYOTO/REL/actions/runs/39146872882), but no snapshot or hostile-file guarantee is implied; see [bounded input](P15A_BOUNDED_INPUT.md).

## P1.5-A opt-in direct-child watchdog (PR CI verified)

The Python wrapper scripts/run_bounded_inspection.py launches REL as one direct child, kills it when wall-clock time exceeds the configured limit, and kills when a polled RSS observation exceeds a threshold. It withholds stdout until a successful exit and bounds the returned JSON bytes. This is **not** a strict OS RAM or CPU budget: fast transient spikes can be missed; child descendants and temp disk usage remain uncontrolled; the native REL CLI still runs without a worker boundary unless explicitly launched through the wrapper. The narrow watchdog and test suite passed [Windows/Linux PR CI #39147845060](https://github.com/ELITEAYOTO/REL/actions/runs/39147845060); no native memory isolation claim. See [supervisor v0](P15A_SUPERVISOR_V0.md).


## Linux native per-process address-space option (scoped PR CI verified)

The optional Python supervisor may install `RLIMIT_AS` in the Linux analyzer child before exec. This limits that process's virtual address space (including reserved mappings), not its physical memory/RSS or aggregate descendant memory. Windows mode and direct `rel-inspect` remain unchanged. Under-memory behavior can lead to ordinary parse/launch errors; reporting it as confirmed RSS exhaustion would be misleading. Installation and denied-allocation tests passed [Windows/Linux PR CI #39149771201](https://github.com/ELITEAYOTO/REL/actions/runs/39149771201). Final PR head and post-merge validation must still be checked before marking integrated. [Supervisor scope](P15A_SUPERVISOR_V0.md).

## Native Windows Job Object watchdog (PR CI verified)

The optional Windows watchdog proposes a Job Object with job-wide committed-memory limit and kill-on-last-handle-close, applied to the analyzer created suspended before it can execute. This is not an RSS bound, CPU-time limit or arbitrary hostile-code sandbox. Child job membership, memory allocation denial, and descendant cleanup were demonstrated by [Windows/Linux PR CI #39151722498](https://github.com/ELITEAYOTO/REL/actions/runs/39151722498). This does not establish complete hostile-process containment. Ancestor job policies, handle duplication and descendants that can break away under other policies remain possible risks. Read [supervisor V0](P15A_SUPERVISOR_V0.md) and keep issue #9 open.


## Linux RLIMIT_CPU option (PR CI verified)

The separate opt-in watchdog now requests a Linux **per-process** CPU-time soft/hard `RLIMIT_CPU` before executing the REL analyzer. The kernel can signal/stop a busy process, unlike sampled CPU metrics, but the limit does not cap wall time, multiple descendants' total CPU, memory, disk output or malicious-process behavior. Direct `rel-inspect` and Windows remain unchanged. Kernel-observed CPU limits, SIGXCPU termination, manifest compatibility and both CI platforms were verified on [Windows/Linux CI #39152737826](https://github.com/ELITEAYOTO/REL/actions/runs/39152737826). See [supervisor V0](P15A_SUPERVISOR_V0.md) and issue #9.

## Unix ancestor path traversal candidate

The Unix controlled-input reader now proposes descriptor-relative component walking with `openat` and `O_NOFOLLOW` on every ancestor and the final component. This reduces the risk of silently following an ancestor symlink introduced after path preflight; tests cover a static ancestor link, a preflight-to-open replacement and ordinary nested input. It is **not** proof of atomic filesystem snapshots, trusted-root containment, race-free renames/mount topology, hard-link safety or arbitrary hostile-filesystem isolation. Windows ancestor reparse points remain unaddressed. See [bounded input](P15A_BOUNDED_INPUT.md). Validation is pending CI on the candidate branch.
