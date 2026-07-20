# Talent report v3 contract

Status: frozen for parallel implementation

Implementation: `community_os/report_contract.py`

Executable example: `config/contracts/talent-report-v3.synthetic.json`

## Purpose

`talent-report-v3` is the only data boundary between reconciliation/aggregation and the interactive talent report. It contains aggregate START-owned operational evidence. It contains no person records, direct identifiers, profile URLs, contact details, partner outcomes, hiring claims, investment claims, or introduction tracking.

The HTML renderer and PDF renderer must consume the same validated `TalentReportContract`. They must not read raw Luma, Devpost, or track-preference records.

## Publication lifecycle

`metadata.publication_state` is one of:

- `draft`: incomplete or exploratory aggregate output.
- `review_ready`: all intended sections exist, but operator approval is pending.
- `published`: safe to render and distribute.

A `published` contract is rejected if `privacy.state` is `blocked` or any required readiness item is not `ready`.

`metadata.synthetic` is explicit. Synthetic data must never be presented as observed event data.

## Privacy model

The contract is aggregate-only:

```json
{
  "value": 15,
  "privacy": "published",
  "reason": null
}
```

Every count uses the same three-key object. A count is valid only when:

- a published value is a non-negative integer;
- a published value is either `0` or at least `privacy.minimum_count`;
- `privacy.minimum_count` is at least `5`;
- a withheld cell has `value: null` and a non-empty reason;
- a published cell has `reason: null`.

Publishing zero is safe because it confirms absence rather than exposing a small non-zero group. Values from `1` through `k - 1` are rejected, not rounded.

`privacy.state` is:

- `safe`: no cells are withheld;
- `withheld_cells`: at least one cell is withheld;
- `blocked`: the report cannot be published.

The loader rejects email addresses and URL-like strings in every string field. Exact-key validation rejects undeclared PII or outcome structures. This is a final publication boundary, not a replacement for upstream minimization and consent controls.

## Sections

### Metadata

Required fields:

- contract version, fixed to `talent-report-v3`;
- report title;
- event key, name, and date;
- generation timestamp;
- synthetic flag;
- publication state.

### Attendance funnel

`attendance_funnel` is measured in `people`. Each stage has a stable key, label, unique positive order, and privacy-safe count. Published stages must be non-increasing in stage order.

Typical stages are approved, checked in, and submitted. The contract does not prescribe labels, so a later event can add a START-owned stage without changing the schema.

### Participant journey

`journey` contains nodes and directed links for a volume-adjusted path exhibit. The journey declares one unit, and every node and link must repeat that exact unit. Links must reference existing nodes, cannot self-link, and cannot exceed either endpoint when all affected counts are published.

This prevents mixing people, teams, and projects in one visual flow. Links must move forward in node order, and the sum of published incoming or outgoing links cannot exceed the published count of their endpoint node. Non-synthetic reports additionally accept only one of the two closed, reviewed topologies: the public application outcome funnel, or the operator's approved-attendee team/solo path. Every link must equal its target node count, and each published binary partition must reconcile to its source. A new observed-event topology therefore requires a versioned contract change and privacy review; arbitrary aliases cannot bypass complementary suppression.

### Team/submission matrix

`team_submission_matrix` is measured in `teams`. It declares row and column keys and exactly one cell for every row-column pair. Missing, duplicate, and out-of-axis cells are rejected.

The expected use is track by submission state. Unsafe cells are withheld rather than omitted, preserving a stable rectangular layout.

### Builder-signal intersections

`builder_signal_intersections` is measured in `people`. It declares the available signal keys, then publishes unique, non-empty signal combinations with safe counts. It supports an UpSet-style exhibit without exposing a participant-level signal table.

Signals should be facts already owned or explicitly supplied to START, for example GitHub supplied, portfolio supplied, or prior project supplied. Semantic quality labels belong upstream and must not introduce person-level narrative.

### Track/domain heatmap

`track_domain_heatmap` is measured in `projects`. Like the team matrix, every declared track-domain pair must have exactly one cell. Small non-zero cells are represented as withheld cells.

### Composition

`composition` is a single-unit categorical distribution. Categories have stable keys, display labels, and safe counts. A renderer may use a waffle, dot field, or compact bars without changing the contract.

### Artifact completeness

`artifact_completeness` summarizes START-owned submission artifacts, for example a demo, repository, or presentation. Each item contains present and eligible counts plus `complete`, `partial`, or `missing` status.

When both counts are published:

- present cannot exceed eligible;
- `complete` requires equality;
- `partial` requires present to be lower than eligible;
- `missing` requires present to be zero.

### Readiness

Each readiness item has a stable component key, state, required flag, and operator-facing note. States are `ready`, `pending`, `blocked`, or `off`.

Deferred integrations such as Coresignal remain visible as optional `off` items. They do not block publication unless deliberately marked required.

### Source notes

Source notes describe aggregate pipeline provenance and readiness. Allowed states are `received`, `validated`, `pending`, and `not_enabled`. Notes must not include local paths, URLs, emails, filenames containing person names, or raw row content.

## Determinism and immutability

The loader returns frozen dataclasses and tuples only. Unordered collections are sorted by stable keys or signatures. Funnel and journey nodes are sorted by explicit order. Matrix and heatmap cells are sorted by their axes.

The same semantic JSON therefore produces the same in-memory contract regardless of the order of unordered input arrays.

## Strict loading

Use:

```python
from community_os.report_contract import load_report_contract

report = load_report_contract("config/contracts/talent-report-v3.synthetic.json")
```

The loader fails closed on malformed JSON, missing or extra keys, invalid types, duplicate keys, unsafe counts, mixed journey units, broken node references, incomplete matrices, inconsistent privacy state, and unresolved publication gates.

Do not catch `ReportContractError` and continue rendering. Surface it to the operator as a blocking validation result.

## Explicit exclusions

Version 3 has no contract fields for:

- partner introductions or follow-up;
- interviews or diligence;
- hires, investments, or downstream commercial outcomes;
- participant names, emails, phone numbers, social links, biographies, or free-form profiles;
- Coresignal enrichment.

Adding one of these is a new privacy and product decision and requires a new versioned contract, not an ad hoc renderer field.
