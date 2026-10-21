# EX-02 — Pilote expérimental de diff des manifestes PE

**Statut : pilote partiel intégré : mode strict [PR #62](https://github.com/ELITEAYOTO/REL/pull/62) (`0.1.0-experimental`) et mode explicitement partiel [PR #149](https://github.com/ELITEAYOTO/REL/pull/149) (`0.2.0-experimental`) ; [CI `main` #39555891672](https://github.com/ELITEAYOTO/REL/actions/runs/39555891672) Windows/Ubuntu réussie. Gate EX-02 complète NON VALIDÉE.**  
Décision et gates : [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md), [STRATEGY_AND_GATES](../governance/STRATEGY_AND_GATES.md).

## Contrat

Entrées implémentées : deux manifestes JSON PE `binary-manifest` v1.0.0 contrôlés. `rel-diff LEFT RIGHT` demeure strict : tout avertissement d'extraction provoque un rejet sans rapport. `rel-diff --partial LEFT RIGHT` est opt-in et retourne un rapport distinct `0.2.0-experimental` contenant `observed` (l'ancien diff `0.1.0-experimental`) et `coverage` (warnings originaux triés, `partial` si présents, `unknown` sinon, `negative_behavior_conclusions=false`). Aucun état ne prétend une couverture complète du PE. Pas de sortie texte, Ghidra, CFG, fonction identifiée, émulation, verdict de sécurité ou conclusion de changement de comportement.

Diff sur format, architecture, taille, sections, imports directs *tels qu'observés*, exports nommés. Statuts `added, removed, changed, unchanged, ambiguous, incomparable` décrivent le rapport entre observations, pas entre capacités exécutées.

## Cas difficiles

- Une section PE peut partager son nom avec une autre : ne pas appari­er aveuglément par nom. Si impossible à différencier, `ambiguous`.
- Imports v1 = chaînes ; normalisation de casse DLL explicitée et original conservé ; ordinals/retardés/dynamiques non reconstructibles.
- Exports v1 = noms ; ordinals perdus. Ne pas prétendre comparer ce qui n'a pas été enregistré.
- Couverture v1 inconnue : le diff des chaînes reste descriptif, et une `suppression` observée d'une chaîne ne démontre pas l'absence de capacité réseau.
- JSON invalide, versions incompatibles, tailles excessives et doublons : rejet sans rapport partiel. Les warnings d'extraction restent bloquants en mode strict ; seul `--partial` conserve ces diagnostics comme observations incertaines.
- Normalisation déterministe sans effacer les preuves et l'ordre physique pertinent.

## Tests d'acceptation

1. A vs A → zéro delta sémantique ; A vs B inverse correctement les ajout/retrait de B vs A.
2. Ordre JSON des imports/exports ne change pas un diff sémantique ; casse des DLL testée.
3. Golden contrôlés : import ajouté/retiré, export modifié, architecture incompatible, taille/section changée.
4. Dupliquer les noms de sections provoque ambiguïté documentée, pas de faux appariement.
5. Manifestes v1 malformés, champs obligatoires manquants et versions inconnues rejetés proprement.
6. Répétitions avec mêmes données/config donnent résultat reproductible ; benchmarks temps/RSS.
7. Valider Windows/Linux CI ; tester sur 10–20 paires de builds autorisés lorsque possibles ; enregistrer l'oracle de chaque changement.

Une nouvelle crate+CLI Rust n'est créée qu'au moment de la PR d'implémentation, indépendante du parseur et de Ghidra. La sortie ne modifie **jamais** le schéma manifeste v1.

## Périmètre du pilote expérimental intégré (historique PR #62)

Le prototype Rust `rel-diff` compare les champs `size_bytes`, `arch`, les chaînes exactes des imports/exports, ainsi que les sections appariées uniquement par nom exact unique. Les noms de sections dupliqués provoquent une abstention `ambiguous`, sans delta partiel. Un booléen expérimental signale le cas global où seule la casse ASCII du préfixe DLL change, sans supprimer les chaînes d'origine. La sortie est contractée séparément par `contracts/experimental/manifest-diff.schema.json` en `0.1.0-experimental`; elle ne transforme pas le manifeste public v1.

La PR comporte des tests Rust et un oracle indépendant du binaire release validant les sorties par JSON Schema sur Windows/Linux, dont l'issue doit être vérifiée sur le **dernier** commit avant promotion. Les fixtures de cet oracle sont synthétiques et utilisent des empreintes de forme valide, sans attestation d'octets PE réels. Ce n'est pas une validation complète des paires compilées autorisées, de l'exactitude d'extraction, du temps/RSS, de l'atomicité des lectures ou de la sécurité d'entrées hostiles.

## Consolidation de l'audit (contrôlée, gate toujours ouverte)

- [#67](https://github.com/ELITEAYOTO/REL/issues/67) : le schéma public v1 accepte les entiers non négatifs sans borne supérieure ainsi que les écritures mathématiquement intégrales telles que `1.0`. Le lecteur expérimental `rel-diff` accepte uniquement les littéraux JSON entiers entre `0` et `18446744073709551615` pour `size_bytes`, `sections[].offset`, `sections[].size` et `sections[].virtual_address` (ou `null` pour cette dernière valeur). L'oracle indépendant vérifie les bornes `0` et `u64::MAX`, le rejet sans sortie partielle de `2^64` et `1.0` des deux côtés de la comparaison, et les entiers négatifs. Cette couverture documente une **restriction du consommateur expérimental**, pas une modification du contrat public ni une validation exhaustive de tous les manifestes v1.
- [#68](https://github.com/ELITEAYOTO/REL/issues/68) : sérialisation JSON de la sortie dans un tampon borné à 16 Mio, incluant le saut de ligne final, **avant** la première écriture sur stdout. Une sortie calculée trop grande échoue sans JSON partiel. Aucun plafonnement global du CPU, de la mémoire des structures intermédiaires ou des erreurs d'écriture de stdout n'est revendiqué.
- Des mesures répétées et contextualisées (temps écoulé, CPU échantillonné, RSS échantillonné) sont prévues par `scripts/profile_manifest_diff.py` sur deux scénarios synthétiques, publiées en artefacts de CI Windows/Linux. Ce sont des observations limitées par l'échantillonnage, pas des benchmarks représentatifs de binaires réels ou une garantie de plafond mémoire.

## Corpus PE réellement compilé (pilotage partiel, sans promotion de la gate)

La CI Windows construit désormais, **sans les exécuter**, quatre variantes de `fixtures/probes/diff_version_probe.c` à l'aide de MSVC et de Clang-cl : huit exécutables PE au total, donnant lieu à seize comparaisons A/B (douze entre variantes d'un même compilateur et quatre entre compilateurs sur une variante identique). Pour chaque binaire, `pefile` vérifie les structures PE indépendamment de Goblin et les recoupe avec les manifestes `rel-inspect`. Les sorties `rel-diff` sont validées contre le schéma expérimental, avec chaque direction A/B, A/A et preuve de provenance compilateur/source/octets.

Le premier artefact Windows contrôlé ([CI #39209103249](https://github.com/ELITEAYOTO/REL/actions/runs/39209103249)) confirme huit builds, seize paires et des différences indépendamment observées d'imports/exports/sections. Voir [protocole et limites du corpus](../EX02_COMPILER_CORPUS.md). **Seize paires d'un même petit source C ne constituent pas seize projets indépendants**, ni un corpus représentatif de builds autorisés de logiciels réels. Les performances et la précision du produit sur un éventail plus large de binaires restent à établir.

## Audit #69 — Compilations identiques et horodatages PE

La comparaison de deux compilations successives dans le même job Windows a identifié **exactement deux octets différents par PE normal**, appartenant exclusivement au `COFF TimeDateStamp` et à un `IMAGE_DEBUG_DIRECTORY.TimeDateStamp` (`8/8` binaires affectés). Cette localisation est contrôlée par des offsets `pefile` explicites. Une expérience isolée `/INCREMENTAL:NO /Brepro` a produit `8/8` fichiers byte-à-byte identiques dans le même job, et les huit SHA ont aussi coïncidé dans deux jobs distincts à source/bannières compilateurs déclarées identiques. Voir [preuve et limites](../EX02_COMPILER_CORPUS.md) et [issue #69](https://github.com/ELITEAYOTO/REL/issues/69).

Le comparateur indépendant `scripts/compare_ex02_corpus_runs.py` refuse les comparaisons de provenance incompatible ; le mode strict `--require-identical` est réservé aux builds `brepro`. Il ne modifie **aucun** octet ni empreinte SHA-256 originale et ne revendique ni équivalence fonctionnelle ni garantie de reproductibilité sous une autre configuration SDK/runner. Ces diagnostics ne clôturent pas la gate EX-02 globale.

**Critères toujours ouverts :** corpus représentatif de 10–20 paires autorisées avec oracles de vérité terrain, benchmarks répétés CPU/RSS/temps sur cas complexes (#68), couverture typée par domaine au-delà des warnings opaques v1, ordinals structurels, collisions et limites réelles du consommateur. Le `--partial` ne clôture pas EX-02. Ne pas cocher le jalon EX-02 sur `main` pour cette PR seule.
