# EX-02 — Prototype de diff des manifestes PE (brouillon de spécification)

**Statut : pilote partiel implémenté sur la PR #62 en brouillon ; non fusionné, gate EX-02 NON VALIDÉE.**  
Décision et gates : [ADR-0013](../adr/ADR-0013-vision-evidence-evolution.md), [STRATEGY_AND_GATES](../governance/STRATEGY_AND_GATES.md).

## Contrat

Entrées : exactement deux manifestes JSON PE `binary-manifest` v1.0.0 validés strictement, plus leur enveloppe de couverture expérimentale si disponible. Sortie : JSON diff versionné séparément et texte optionnel. **Aucun** Ghidra, CFG, fonction identifiée, émulation, verdict de sécurité ou conclusion de changement de comportement.

Diff sur format, architecture, taille, sections, imports directs *tels qu'observés*, exports nommés. Statuts `added, removed, changed, unchanged, ambiguous, incomparable` décrivent le rapport entre observations, pas entre capacités exécutées.

## Cas difficiles

- Une section PE peut partager son nom avec une autre : ne pas appari­er aveuglément par nom. Si impossible à différencier, `ambiguous`.
- Imports v1 = chaînes ; normalisation de casse DLL explicitée et original conservé ; ordinals/retardés/dynamiques non reconstructibles.
- Exports v1 = noms ; ordinals perdus. Ne pas prétendre comparer ce qui n'a pas été enregistré.
- Couverture v1 inconnue : le diff des chaînes reste descriptif, et une `suppression` observée d'une chaîne ne démontre pas l'absence de capacité réseau.
- JSON invalide, versions incompatibles, tailles excessives, doublons et erreurs d'extraction : rejet ou `incomparable`, jamais fallback silencieux à une liste vide.
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

## Avancement du pilote isolé (PR #62, non fusionnée)

Le prototype Rust `rel-diff` compare les champs `size_bytes`, `arch`, les chaînes exactes des imports/exports, ainsi que les sections appariées uniquement par nom exact unique. Les noms de sections dupliqués provoquent une abstention `ambiguous`, sans delta partiel. Un booléen expérimental signale le cas global où seule la casse ASCII du préfixe DLL change, sans supprimer les chaînes d'origine. La sortie est contractée séparément par `contracts/experimental/manifest-diff.schema.json` en `0.1.0-experimental`; elle ne transforme pas le manifeste public v1.

La PR comporte des tests Rust et un oracle indépendant du binaire release validant les sorties par JSON Schema sur Windows/Linux, dont l'issue doit être vérifiée sur le **dernier** commit avant promotion. Les fixtures de cet oracle sont synthétiques et utilisent des empreintes de forme valide, sans attestation d'octets PE réels. Ce n'est pas une validation complète des paires compilées autorisées, de l'exactitude d'extraction, du temps/RSS, de l'atomicité des lectures ou de la sécurité d'entrées hostiles.

**Critères toujours ouverts :** corpus représentatif de 10–20 paires autorisées avec oracles de vérité terrain, benchmarks répétés temps/RSS, décisions sur couverture incomplète et ordinals non représentés, revue des collisions et adéquation complète au schéma public. Ne pas cocher le jalon EX-02 sur `main` pour cette PR seule.
