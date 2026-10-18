# RFC-0001 — REL Evidence & Evolution Engine

**Status:** ADOPTÉ POUR LA VISION PRODUIT, avec amendements [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md) ; les modules envisagés restent NON IMPLÉMENTÉS.  
**Date:** 2026-10-18  
**Nature:** cadrage produit/architecture, aucun changement de contrat ou de roadmap accepté par ce document.  
**Repository:** https://github.com/ELITEAYOTO/REL  
**Baseline examinée:** branche main au merge de la PR #10, commit 2ee47efca4668da1016041bf377ad517c8da488b.

> **Décision du 18/10/2026 :** la direction générale et la séquence expérimentale sont acceptées via [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md). Les exemples de ce document restent des **propositions**, pas des contrats ou fonctionnalités livrées. En cas de divergence, ADR-0013, ROADMAP, AGENTS et DECISIONS_FIGEES priment. Ne jamais confondre vision et code testé.

## 1. Résumé exécutif

REL doit viser une plateforme **offline-first, modulaire et vérifiable**, spécialisée dans l'analyse de binaires autorisés et l'explication des changements d'une version à l'autre.

La proposition de différenciation n'est **ni** un décompilateur maison, **ni** le premier moteur de diff de fonctions, **ni** le premier détecteur de capacités. Tous ces domaines disposent déjà d'outils sérieux.

La proposition à tester est la combinaison suivante :

1. Observations statiques **factuelles**, bornées et rejouables.
2. Comparaisons structurelles, puis sémantiques, entre versions.
3. Chaîne de preuves explicite reliant **constat → extracteur → emplacement/artefact → règle/hypothèse**.
4. Expression obligatoire des inconnues, des erreurs de couverture et des limites.
5. Contrats et CLI exploitables indépendamment dans des pipelines CI.
6. Évolution optionnelle vers des moteurs externes (Ghidra/BSim), sans réécriture spéculative.

**Phrase-produit cible (hypothèse):** « REL explique ce qui a changé dans un logiciel compilé, pourquoi il le pense et quelles conclusions restent impossibles à établir. »

## 2. État observé et ce qui N'EXISTE PAS

### Vérifié dans le dépôt

- Workspace Cargo Rust : rel-contracts, rel-pe et l'exécutable rel-inspect.
- PE32/PE32+, sections, imports, exports, taille, SHA-256, manifest JSON v1.0.0.
- Analyse statique de bytes ; aucune exécution implicite d'EXE/DLL soumis.
- CI Rust Windows/Linux : format, Clippy, tests, build, smoke, oracle pefile Windows.
- Mutations déterministes, première campagne libFuzzer, régression F001 conservée.
- F001 : panic historique de goblin 0.9.3 ; adaptation vers goblin =0.10.7 validée dans les conditions de CI citées dans docs/findings/F001_GOBLIN_TLS_PANIC.md.

### Non implémenté

- Moteur de diff des deux manifestes, IR sémantique profonde, extraction CFG, décompilation.
- Moteur de conclusions/capacités, graphes de preuves, calibration de confiance.
- Agent IA, interface desktop/web, interface Ghidra, policy engine, attestation signée.
- Garantie de sûreté sur des fichiers hostiles arbitraires.

### Limites immédiates vérifiables par inspection du code

- rel-inspect lit le fichier complet en mémoire après un contrôle de taille 512 MiB.
- Les exports/imports du contrat v1 sont des chaînes ; les imports ne portent pas explicitement la modalité (direct/delay/ordinal), et les sections ont une description minimale.
- Le code observé du parseur initialise warnings à [] ; absence de warning ne signifie pas inspection exhaustive.
- Le CLI contrôle taille et non-écrasement, mais les races entre stat, lecture et chemins/links, les quotas de temps et l'isolation de processus restent à démontrer.
- Deux fixtures synthétiques, l'exécutable Windows de REL et les régressions ne constituent pas un corpus représentatif.
- Dépôt sans fichier LICENSE : public ne signifie pas automatiquement librement redistribuable.

## 3. Leçons de l'écosystème (ne pas revendiquer de fausse nouveauté)

| Référence | Fonction existante | Bonne décision REL |
| --- | --- | --- |
| Ghidra + BSim | analyse/décompilation, similarité de fonctions | adaptateur externe, pas de clone |
| Google BinDiff | matching de CFG/callgraph et diff binaire | benchmark et concurrence, pas revendication de nouveauté |
| Diaphora | diff open source de programmes via IDA | étudier les compromis et la qualité des matches |
| Mandiant capa | règles de capacités + indices explicables | ne pas présenter des capacités statiques comme certitudes comportementales |
| LIEF | abstractions communes PE, ELF, Mach-O | ne généraliser les formats qu'avec besoin, corpus et tests |
| in-toto/SLSA/Sigstore | provenance et attestations signables | réutiliser les standards, distinguer intégrité et vérité d'un rapport |

**Hypothèse de différenciation à vérifier** par prototypes et retours d'utilisateurs : le flux d'audit longitudinal, hors-ligne, avec états d'incertitude et preuves adressables, serait plus simple à intégrer/rejouer que l'assemblage manuel d'outils spécialisés. Ceci n'est pas une affirmation d'unicité sur le marché.

Sources à consulter lors de la décision : https://github.com/google/bindiff ; https://github.com/NationalSecurityAgency/ghidra ; https://github.com/joxeankoret/diaphora ; https://github.com/mandiant/capa ; https://lief.re/doc/stable/api/binary_abstraction/index.html ; https://github.com/in-toto/attestation ; https://slsa.dev ; https://docs.sigstore.dev .

## 4. Invariant critique : ne jamais transformer « absent dans l'observation » en « impossible »

**Interdit** : « aucune importation ws2_32, donc aucune capacité réseau possible ».

Contre-exemples : résolution dynamique d'API, bibliothèques chargées ultérieurement, appels système, interpréteur embarqué, code fourni à l'exécution, binaire packé, extraction partielle, branche non découverte.

**Interdit** : « aucune section WX, donc ce code ne peut pas s'auto-modifier » ou « pas de CreateRemoteThread importé, donc aucune injection possible ».

### Taxonomie recommandée pour les observations (proposition, PAS le schéma v1)

- OBSERVED_PRESENT : indice positif vu dans une zone effectivement examinée.
- OBSERVED_ABSENT_IN_SCOPE : aucun indice correspondant dans le **périmètre défini et complètement parcouru**.
- INDETERMINATE : extraction insuffisante, ambiguë, packée, inconnue ou heuristique non concluante.
- EXTRACTION_FAILED : la source/zone n'a pu être analysée correctement.
- NOT_APPLICABLE : assertion ne s'applique pas au format/artefact.
- Les conclusions de haut niveau sont séparées des observations et peuvent être HYPOTHESIS, SUPPORTED, CONTRADICTED ou UNKNOWN, **sans** signifier une preuve formelle du comportement.

Une observation d'absence peut être défendable pour « aucune entrée X dans la table d'imports directe PE parcourue intégralement », pas pour « le logiciel ne peut jamais faire X ». **Toujours préciser scope + méthode + état de couverture.**

## 5. Contrats : préserver manifest v1.0.0, ajouter des enveloppes expérimentales

NE PAS modifier silencieusement binary-manifest.schema.json v1.0.0 ni le sens des champs existants.

Les structures ci-dessous illustrent un contrat séparé, proposé pour expérimentation ; les noms et types ne sont pas ratifiés.

~~~json
{
  "schema_version": "0.1.0-experimental",
  "subject": {
    "sha256": "sha256-du-fichier-source",
    "size_bytes": 12345,
    "format": "PE"
  },
  "producer": {
    "name": "rel-pe",
    "version": "version-de-l-outil",
    "backend": "goblin",
    "backend_version": "version-verrouillee"
  },
  "scope": {
    "domain": "pe.direct_import_table",
    "state": "complete",
    "limits": ["static_only", "no_dynamic_resolution"]
  },
  "observations": [
    {
      "id": "obs-0001",
      "predicate": "pe.direct_import",
      "subject": "KERNEL32.dll!CreateFileW",
      "state": "OBSERVED_PRESENT",
      "evidence": [
        {"kind": "file_range", "offset": 2048, "length": 16}
      ]
    }
  ],
  "diagnostics": []
}
~~~

La plage d'octets ci-dessus est **un exemple de schéma**, pas un offset observé dans un vrai échantillon. Un format final exigera validation des offsets, tailles et hachages ; un import peut être indirect, ordinal, incomplet ou ambigu.

### Exigences de modélisation

- Séparer **FileArtifact**, **Observation**, **ExtractorRun**, **Finding**, **Comparison** et éventuellement **Attestation**.
- SHA-256 du fichier comme identité d'artefact ; pas d'identité de fonction universelle basée sur l'adresse.
- Conserver original + normalisé lorsqu'une casse, un chemin ou un nom peut être transformé.
- Règles d'égalité explicites pour DLL (casse), exports par nom/ordinal, sections potentiellement dupliquées.
- Les propriétés de code/instruction doivent indiquer adresse virtuelle, RVA et offset fichier séparément ; ne pas interchanger ces espaces.
- État et portée de couverture obligatoires pour les assertions négatives.
- Échecs d'extraction et dépassements de quota doivent produire des diagnostics machine-lisibles et ne jamais être interprétés comme listes vides.
- Sorties déterministes quand la même entrée, le même outil et la même configuration sont rejoués ; trier les ensembles sémantiques sans détruire l'ordre physique utile.
- Compatibilité de schéma testée avec fixtures golden et migrations explicites ; traiter la canonicalisation avant toute signature cryptographique.
- Ne jamais inscrire automatiquement le contenu intégral de binaires propriétaires dans les rapports ; limiter les extraits et prévoir la redaction des chemins/secrets.

### Confiance et sécurité

- « Confidence = 92 % » est interdit tant que la calibration n'est pas empiriquement validée sur une vérité terrain indépendante.
- Les scores de similarité ne sont pas des probabilités de véracité.
- Une signature prouve l'intégrité et éventuellement la provenance d'un rapport signé, **pas l'exactitude de ses conclusions**.
- Une attestation in-toto éventuelle doit déclarer clairement son predicate personnalisé, son subject SHA-256 et les limites de l'analyse.

## 6. Architecture cible : modules optionnels, frontières nettes

### Existe actuellement

~~~text
rel-contracts  <--  rel-pe
     ^                 ^
     +------ rel-inspect
~~~

### Extensions proposées, seulement par lots justifiés

~~~text
                         [formats / backends]
                          rel-pe (EXISTANT)
                          rel-elf (FUTUR / optionnel)
                          rel-macho (FUTUR / optionnel)
                                  |
                                  v
                   rel-contracts / observation contracts
                              |       |
                         rel-diff   rel-evidence
                              \       /
                               v     v
                              rel-policy
                                  |
                        CLIs / optional adapters
                                  |
                     CI, reports, optional UI

       Ghidra headless / BSim --> isolated Python adapter
                                     |
                             function schema/observations
~~~

Ce dessin représente des **frontières logiques**, pas une obligation de créer autant de crates tout de suite. Éviter une multiplication artificielle de packages : créer un module indépendant seulement lorsqu'une responsabilité stable, des tests et un usage concret l'exigent.

### Responsabilités pressenties

| Composant | Implémentation souhaitée | Dépendances/interdits |
| --- | --- | --- |
| rel-contracts | Rust, existant | aucun CLI ou backend spécifique |
| rel-pe | Rust, existant | parse untrusted bytes, ne lance rien |
| rel-inspect | Rust CLI, existant | orchestration seulement |
| rel-diff | Rust library + CLI, candidat | compare manifestes/observations sans appeler Ghidra |
| rel-evidence | Rust library, candidat | preuves et provenance ; aucun modèle IA requis |
| rel-policy | Rust library + CLI, candidat tardif | règles explicites, UNKNOWN explicite |
| rel-ghidra-adapter | Python CLI séparé, P2 déjà prévu | contrôle processus, versions, ressources ; aucun side effect implicite |
| rel-wasm | cible compilation, hypothèse | après découplage IO, confidentialité locale vérifiée |
| rel-ui | TypeScript/Tauri ou web, hypothèse | consommateurs de contrats, pas de logique d'analyse cachée |

Ne pas ouvrir une dizaine de crates vides. « Une nouvelle crate = une frontière testable démontrée » est le critère.

## 7. Première proposition de valeur testable : diff **de manifestes**, sans décompilation

**Question produit :** « Qu'est-ce qui a changé entre deux artefacts, selon les champs que REL sait réellement extraire ? »

### MVP borné

- Entrée : deux manifestes v1.0.0 strictement validés, chacun associé à son SHA-256 de source.
- Sortie : JSON diff versionné séparément, plus rapport textuel optionnel.
- Delta : format/architecture, taille, sections, imports directs observés, exports nommés observés.
- Ordre stable, sorties identiques à entrées identiques ; chemins de fichiers optionnels et non déterminants.
- Distinguer ADDED / REMOVED / CHANGED / AMBIGUOUS / UNCOMPARABLE / UNCHANGED.
- Exclure tout verdict « dangereux », « aucun réseau », « changement fonctionnel certain ».
- Éviter le matching naïf de sections quand noms dupliqués ou structure ambiguë ; marquer AMBIGUOUS plutôt qu'inventer.
- Aucune capacité de fonction, CFG ou décompilation prétendue.

### Conditions de validation

1. Même manifeste comparé à lui-même → zéro changement sémantique.
2. Inversion A/B → symétrie cohérente ADDED/REMOVED.
3. Ordre des ensembles d'imports/export indépendant de l'ordre d'entrée, selon règles documentées.
4. Imports différents mais simples variations de casse DLL → résultat conforme aux règles de normalisation spécifiées et testées.
5. Champs obligatoires manquants, schema incompatible, imports ambiguës → erreurs/incomparables explicites, sans panic.
6. Jeu golden volontairement modifié (ajout/suppression import/export, taille de section) avec sorties attendues.
7. Binaires sources réels sous licence vérifiée + oracle indépendant lorsque disponible.
8. CI Windows/Linux, tests de propriété/mutation ciblés, allocation et temps mesurés.
9. Le contrat de sortie ne modifie pas le manifest v1, sauf ADR et migration documentés.

**Décision de séquencement à arbitrer :** le ROADMAP actuel pose P2 Ghidra avant P3 matcher. Un **prototype indépendant de diff-métadonnées** peut être expérimenté avant P2 seulement après accord explicite du mainteneur ; il ne doit pas rebaptiser silencieusement la roadmap ni annoncer P3 complet.

## 8. Au-delà du MVP : comparaison de fonctions avec preuves, pas score magique

Évaluer en priorité les moteurs existants (Ghidra/BSim/BinDiff) selon licences, besoins, stabilité de sortie, vitesse et exactitude. Approche candidate :

1. Extraction externe contrôlée de fonctions/CFG via Ghidra.
2. Normalisation prudente (adresses, relocation, symboles, sections) avec traces de transformations.
3. Matching par empreintes multiples : bytes, CFG, références, voisinage d'appels et contexte.
4. Résultat **match candidat / match confirmé par oracle / ambigu / inconnu**, pas « même fonction » sur un score arbitraire.
5. Comparer compilations connues du même source avec toolchains et optimisations variables.
6. Mesurer precision@k, rappel sur vérité terrain, faux appariements, abstentions, RAM/temps, reproductibilité.
7. Conserver la provenance complète de l'outil externe, ses erreurs, version et configuration.

**Différenciation candidate** : suivre l'histoire d'une fonction / capacité sur plusieurs versions, avec une chaîne d'indices traçables et recalculables. Aucune affirmation qu'un tel flux serait inédit sans étude comparative et validation utilisateur.

## 9. Sécurité de traitement des entrées et isolation

P1.5 doit rester prioritaire sur les modules futurs :

- Corpus autorisé, multi-compilateurs, PE32/PE32+, DLL/EXE, imports ordinaux/différés, TLS, certificats, données de ressources, fichiers tronqués/packés et overlays.
- Limites au niveau lecture, structures, temps CPU, taille RSS, nombre d'imports/sections, profondeur des ressources, graphe et sorties.
- Séparer taille d'entrée et coût de parsing : un petit fichier malformé peut causer un travail disproportionné.
- Tests de races stat/read, liens symboliques, fichiers changeants, répertoires, sortie et overwrite.
- Privilégier un processus worker isolé avec limites OS lorsque l'analyse de fichiers adversariaux entre dans le périmètre ; catch_unwind ne couvre ni OOM ni abort.
- Établir quel niveau d'isolation est réaliste sous Windows et Linux ; ne pas appeler « sandbox » un simple processus enfant.
- Fuzz : toolchain/lock spécifiques figés, campagnes longues distinctes de smoke, crash minimisé et régression persistée.
- Mesures de peak RSS et temps sur corpus représentatif, pas uniquement padding 2 KiB / 1 MiB / 4 MiB.
- Créer une threat model (entrées, exécution d'outils externes, secrets locaux, artefacts CI, sorties et frontières de confiance).
- Pas d'exécution d'un fichier importé par défaut ; runtime éventuel isolé, opt-in, sur cibles autorisées.

### Non-objectifs explicites

Pas de bypass anti-cheat, pas de manipulation de jeux en ligne protégés, pas d'exécution silencieuse de PE, pas d'orchestrateur distant non nécessaire, pas d'inférence par LLM présentée comme preuve, pas de « certification sécurité » fondée uniquement sur l'analyse statique.

## 10. IA, graphe et interface : intégrer plus tard, avec un rôle précis

**IA = narrateur/aide à l'exploration**, jamais source de vérité primaire. Elle peut expliquer un Finding dont les IDs d'observations sont connus, proposer des pistes, suggérer une comparaison, et doit répondre UNKNOWN en l'absence d'indices suffisants. Toute affirmation doit renvoyer à l'ID, au SHA, à l'extracteur, à son périmètre et à une méthodologie.

**Graphe** : commencer par un petit modèle de relations (artifact → extraction → observation → finding → diff). Ne pas imposer de base de données graphe avant les mesures. SQLite/JSONL peuvent suffire au prototype ; choix définitif après ADR et benchmarks.

**WebAssembly** : expérience intéressante pour l'analyse locale sans upload, mais ne pas prétendre « zéro fuite » sans vérifier réseau, telemetry, chargement des scripts, extensions navigateur et politique de confidentialité. Pas avant robustesse/contrats portables.

## 11. Plan de livraison par gates (proposé, sans réécriture automatique du ROADMAP)

| Gate | Travail | Critère d'acceptation observable |
| --- | --- | --- |
| A — Fiabilité | Finir P1.5, #9/#11/#12 | corpus licencié, limites mesurées, campagnes fuzz traçables, RSS/temps, CI verte |
| B — Diff statique pilote | schema de comparaison séparé, prototype rel-diff | golden bidirectionnels, validation stricte, tests Windows/Linux, aucune prétention de CFG |
| C — Evidence contract | RFC puis ADR pour observations structurées | modèle versionné, couverture/erreurs explicites, replay déterministe, compat v1 |
| D — Analyse profonde | adaptateur Ghidra indépendant (P2) | version verrouillée, limites, erreurs, samples source connu, benchmark |
| E — Matching de fonctions | vérités terrain et matching multi-signaux | faux matches/recall/abstentions mesurés vs références |
| F — Politique/attestation | moteur déclaratif optionnel | claims bornés, UNKNOWN, vérification signature et policy distinctes |
| G — UI/WASM/formats | POC motivé par utilisateurs | tests d'acceptation, compatibilité, confidentialité, métriques réelles |

Ne jamais déclarer gate COMPLETED seulement parce que le code compile. Chaque gate exige PR, commit/runs CI, artefacts et limites documentées.

## 12. Gouvernance et anti-monolithe

- Lire AGENTS.md, ROADMAP.md, DECISIONS_FIGEES.md, CODE_QUALITY.md et les tests avant toute modification.
- Les seuils existants priment : Rust soft 350 / hard 500 lignes par fichier ; fonctions 50 / 80 ; complexité 10 / 15 ; exceptions documentées, **pas de découpages artificiels**.
- Une PR = une responsabilité claire + tests + preuve + documentation. Pas de refactoring cosmétique multi-crates.
- Créer ADR avant modification des dépendances structurelles, contrats publics, stack, sécurité ou ordre des milestones déjà figés.
- CI à renforcer progressivement : toolchains et packages reproductibles, SHA actions tiers, audit/advisories/SBOM, droits minimaux, tests de compat, artefacts versionnés.
- Choisir une licence source avec revue des dépendances et des fixtures avant d'appeler REL un projet « open source » redistribuable.
- Les résultats devront séparer VERIFIED, DESIGN, HYPOTHESIS, UNKNOWN et maintainer claim.

## 13. Expériences à réaliser AVANT de multiplier les fonctionnalités

| Hypothèse | Expérience falsifiable | Signal de décision |
| --- | --- | --- |
| Un diff simple apporte une valeur immédiate | 10 à 20 paires de builds autorisés avec modifications attendues | taux d'écarts correctement rapportés, erreurs, demandes utilisateurs |
| Les métadonnées sont suffisantes pour une alerte utile | introduire 3 changements contrôlés et 3 recompilations sans changement source | faux positifs de l'alerte séparés du diff brut |
| Les preuves rendent l'audit plus facile | demander à 3 utilisateurs techniques de reproduire une conclusion | temps de reproduction, erreurs, explications introuvables |
| Une couche multi-format est nécessaire tôt | prototypes PE puis ELF connus, mêmes questions analytiques | duplication réelle et divergences sémantiques constatées |
| Une couche graphe dédiée serait rentable | stocker N extractions/observations dans fichiers puis SQLite | temps des requêtes longitudinales et coûts opérationnels |
| WASM améliorerait l'adoption | test de confidentialité et performance sur fichiers autorisés | taille bundle, latence, RAM et limites navigateur |

## 14. Choix suspendus au mainteneur

1. **Destination produit** : bibliothèque/CLI pour experts et CI d'abord, ou application interactive grand public plus tard ? Recommandation : CLI et CI d'abord, interface en second.
2. **Séquence** : accepter ou non un petit diff de manifestes avant l'adaptateur P2, avec ADR de replanification si nécessaire.
3. **Licence** : Apache-2.0/MIT dual, Apache-2.0 seul ou autres selon stratégie et droits de contribution ; ne pas décider sans accord.
4. **Niveau de menace** : fichiers hostiles arbitraires ou corpus autorisés/corpus propres en premier. Recommandation : déclarer alpha et renforcer les frontières avant tout label de sécurité.
5. **Promesse** : ne pas utiliser le mot « preuve » pour une inférence heuristique ; « evidence-backed finding » serait une désignation plus juste.

**Une RFC acceptée ne doit pas requalifier P1.5 comme terminée.** L'ordre de priorité immédiat reste robustesse, corpus, limites et reproductibilité.

## 15. Références techniques à conserver dans l'historique des décisions

- Microsoft PE/COFF : https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- goblin versions/fixes PE : https://docs.rs/crate/goblin/latest/source/CHANGELOG.md
- BinDiff matching : https://github.com/google/bindiff/blob/main/docs/concepts.md
- Ghidra/BSim : https://github.com/NationalSecurityAgency/ghidra
- Diaphora : https://github.com/joxeankoret/diaphora
- capa : https://github.com/mandiant/capa
- LIEF formats : https://lief.re/doc/stable/api/binary_abstraction/index.html
- in-toto : https://github.com/in-toto/attestation
- SLSA provenance : https://github.com/slsa-framework/slsa/blob/main/spec/build-provenance.md
- Sigstore attestations : https://docs.sigstore.dev/cosign/verifying/attestation/
- GitHub licences : https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository

---

**Decision record:** This is an architecture and product research proposal only. The next step is to review it, choose a narrow acceptance experiment, and create a dedicated implementation ADR/issue/PR. No claims of implemented functionality, production safety, unique invention or measured market superiority arise from this document.


## 16. Décision et amendements approuvés (18/10/2026)

1. **REL reste une plateforme de reverse engineering complète** ; Evidence & Evolution est son approche de vérification, non une réduction à un scanner d'imports ou à la conformité.
2. **Ordre formalisé** : durcissement critique P1.5-A, EX-01 contrat minimal de couverture/provenance, EX-02 diff de métadonnées PE **avant P2 Ghidra**, puis P3 matching de fonctions. La robustesse P1.5-B continue, sans blocage inutile d'expériences sur corpus contrôlé.
3. **Manifest v1.0.0 inchangé**. Les enrichissements d'observations, diagnostics et états sont expérimentaux, versionnés séparément et conditionnés à des tests.
4. Pas de multiplication artificielle de crates ni d'UI, de graphe, de moteur IA ou de WASM sans preuve de besoin.
5. Entrées hostiles arbitraires : pas de prétention de sûreté sans budgets, isolation OS testée et corpus représentatif.
6. Les affirmations négatives exigent un domaine et une couverture vérifiés ; absence d'import ≠ impossibilité de comportement.
7. La licence de la source reste à définir après inventaire de dépendances et stratégie de contributions.

Documents normatifs : [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md), [gates](../governance/STRATEGY_AND_GATES.md), [EX-01](../specs/OBSERVATION_ENVELOPE_DRAFT.md), [EX-02](../specs/METADATA_DIFF_PILOT.md), [modèle de menace](../security/THREAT_MODEL_ALPHA.md).
