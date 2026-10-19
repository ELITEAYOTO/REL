# EX-01 — Enveloppe d'observations (brouillon)

**Statut : PILOTE PARTIEL — contrat + premier producteur statique `pe.dos_magic` vérifiés ; EX-01 global non terminé, `binary-manifest` v1.0.0 inchangé.**  
Décision : [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md).

## But

Le v1 contient `imports: Vec<String>`, `exports: Vec<String>`, `warnings: Vec<String>`. Une liste vide ne renseigne pas à elle seule sur l'exhaustivité, la présence d'ordinals, les imports différés, les résolutions dynamiques ou l'échec silencieux de l'extraction.

## Petite enveloppe candidate, séparée de v1

- `subject` : identité SHA-256, taille, format du fichier d'origine.
- `producer` : composant et version, backend/version, configuration, identifiant reproductible d'exécution.
- `scope` : domaine exact (`pe.direct_import_table` par exemple), état `complete|partial|unsupported|failed`, limites et procédure.
- `observations[]` : prédicat, valeur source/normalisée, `present|absent_in_scope|indeterminate`, preuves et contexte.
- `evidence[]` : SHA du fichier, emplacement typé (offset de fichier vs RVA vs VA), longueur, méthode/version ; vérifier les bornes des plages.
- `diagnostics[]` : code machine stable, sévérité, étape, contexte utile ; erreur ≠ liste vide.
- Identifiants/ordres stables hors timestamp/chemins locaux, non déterminants dans le hash de contenu.

## Invariants

1. **Absent dans une table examinée intégralement** n'est pas **impossible dans le logiciel** ; aucune conclusion « pas de réseau » à partir d'imports absents.
2. Seul un domaine `complete` et précisément nommé peut établir `absent_in_scope` ; `failed`, `partial` et `unsupported` mènent à indéterminé.
3. Ne jamais inventer les ordinals, les imports retardés, les alias ni les offsets que v1 a perdus.
4. Conserver la forme brute après normalisation, par exemple DLL insensible à la casse selon règles de comparaison explicites.
5. Preuves de fichiers propriétaires : hashes/offsets validés plutôt que dump intégral ; ne pas divulguer des chemins/secrets privés.
6. Une signature authentifie éventuellement un rapport, pas ses conclusions ; un score de similarité n'est pas une probabilité de vérité.
7. Aucune nouvelle crate `rel-evidence` tant qu'un besoin réutilisable avec tests n'est pas démontré.

## Conditions d'acceptation

Schéma indépendant sous `contracts/experimental/` avec golden examples `present, absent_in_scope, partial, failed, unsupported`; tests JSON Schema invalides, champs incohérents, offset hors bornes, configurations/version, déterminisme et compatibilité v1. Une PR de contrat ne rend pas ce moteur fonctionnel tant qu'aucun extracteur ne peut produire ses observations fiables.

## First contract-only prototype (PR #49 merged; scoped Windows/Linux CI verified)

[PR #49](https://github.com/ELITEAYOTO/REL/pull/49) merged at `bbbec20`; [post-merge main CI #39176279141](https://github.com/ELITEAYOTO/REL/actions/runs/39176279141) passed on Windows/Linux. This validates schema and semantic test coverage, **not** any producer's factual correctness.

The separate `contracts/experimental/observation-envelope.schema.json` uses
`0.1.0-experimental`. Its validator is
`scripts/validate_observation_envelope.py`. Five synthetic/controlled
examples in `fixtures/experimental/observation/` exercise present,
absent-in-scope, partial, failed and unsupported; this is **not** a
real extractor or production evidence source. `pe.dos_magic` is used
instead of inventing detailed import offsets from v1.

Cross-field checks reject file-offset ranges beyond subject size; evidence
whose subject hash differs; dangling or duplicated IDs; present claims
without raw+normalized values or referenced evidence; absence unless
scope is complete; and failure states without diagnostic records.
RVA and VA are explicitly **not** compared to `size_bytes`, because
virtual address spaces cannot be bounded by file length alone.
These checks establish report *well-formedness*, not proof that its
producer observed the alleged bytes. No wall clock, local input path,
proprietary binary dump or potentially meaningless confidence percentage
is included by default.

Next work: derive reproducible run IDs from producer configuration,
create an actual extraction consumer with deliberate coverage rules,
test evaluator/producer correspondence, evaluate mixed/overlapping
domains and ordinal/delay-import information without reconstructing
facts lost by v1. Preserve critical P1.5-A work and issue #9.

## First true controlled producer — PR #51 merged, scoped Windows/Linux CI verified

[PR #51](https://github.com/ELITEAYOTO/REL/pull/51) merged as `10f38c8`; [final Windows/Linux post-merge CI #39179499279](https://github.com/ELITEAYOTO/REL/actions/runs/39179499279) passed, including actual producer smoke tests. This is evidence of the tested scope, not broad reverse-engineering maturity.

`tools/rel-observe` implements the deliberately narrow domain
`pe.dos_magic`: it reads up to 2 MiB from an ordinary controlled file,
checks that MZ and the minimal PE signature exist, and compares bytes
[0,2) to `MZ` and `NE`. `present` and `absent_in_scope` therefore
refer **only** to those two predicates at those bytes, not PE behavior.
Actual file SHA-256, byte length and offset-backed evidence are emitted
from the same buffer. The run-ID preimage is fully documented in the
[tool README](../../tools/rel-observe/README.md) and checked with an
independent Python implementation. Output is validated against the
previously shipped experimental schema and semantic checks. The main
`rel-inspect` v1 manifest is not changed.

The CLI refuses inputs outside the scope; it does not claim an extraction
`failed` report for every IO error, a coherent filesystem snapshot,
complete PE correctness, or security against hostile inputs. Longer-term
EX-01 still needs comprehensive coverage domains, diagnostics from real
extraction errors and policy decisions for incomplete extraction.

## Candidate: COFF Machine scope and partial semantics (CI pending)

The experimental `rel-observe coff-machine` command extracts the two-byte
COFF Machine field at file offset `e_lfanew + 4`, only after validating
the MZ and four-byte PE signature. This produces one positive
`pe.coff_machine.value` observation, with a raw little-endian 16-bit hex
code, cautiously normalized to `x86`/`x86_64` for two recognized codes.
Other codes remain uninterpreted hex. Exact file-offset evidence and
subject identity are extracted from the same bounded byte buffer.

A completely or partially missing Machine field produces scope
`partial`, an `indeterminate` observation with null values, no
decisive evidence, and `COFF_MACHINE_TRUNCATED` warning. This is a real
non-complete output case. Invalid/truncated MZ/PE signature framing still
fails without any report. Python independently recomputes `e_lfanew`,
Machine values, hashes and domain-specific run IDs; Rust tests cover both
fixture architectures and the truncation boundary.

This evidence says nothing about whether instructions at runtime are
executable or compatible, what imported APIs mean, or whether an
arbitrary hostile binary can be analyzed safely. Overall EX-01 and
P1.5-A remain incomplete; no change to manifest v1.0.0.
