# Talent intelligence v1 contract

Implementation: `community_os/talent_intelligence_contract.py`

Executable synthetic example: `config/contracts/talent-intelligence-v1.synthetic.json`

## Purpose

`talent-intelligence-v1` is the aggregate-only boundary shared by the VC and company talent briefs. It is separate from the frozen event-operations contract, `talent-report-v3`.

The contract contains no person records, names, contact details, profile URLs, employer names, source filenames, named achievements, or partner outcomes. The same validated object must feed both audience renderers.

## Cohort and selection

The primary denominator is all valid applicants. The ordered participation funnel is measured only in people and starts with a `valid_applicants` stage equal to that denominator.

Selection outcomes separately reconcile to all valid applicants. Every outcome carries a reason evidence state:

- `observed`: the source directly records the outcome;
- `operator_reviewed`: an authorized operator reviewed the reason;
- `unknown`: the source does not prove why the outcome occurred.

The current exports do not prove that every non-admitted applicant was excluded by capacity. The synthetic fixture therefore includes an explicit `not_accepted_reason_unknown` population.

## Talent dimensions

Each dimension declares whether it is:

- `exclusive`: published item counts reconcile to `known_count` unless a cell is withheld;
- `overlapping`: an applicant may appear in multiple items, so shares do not sum to 100 percent.

Every item includes a stable key, label, privacy-safe count, definition, and one or more evidence-source keys. The v1 fixture covers:

- professional identity;
- seniority;
- functional role;
- employer pedigree;
- builder evidence;
- capabilities;
- domains.

Employer pedigree is category-based and depends on an editable reviewed taxonomy. Forwardable reports do not publish employer names.

## Intersections and themes

An intersection references at least two dimension-item keys. Its published count cannot exceed any component population. A published intersection cannot reference a withheld component.

Qualitative themes are aggregate statements with a count, confidence, review state, and evidence sources. Small or distinctive themes remain withheld.

## Coverage, readiness, and gates

Evidence coverage reports eligible and covered populations separately from talent distributions. Missing enrichment never becomes negative talent evidence.

The `gated_talent_appendix` feature must exist and must remain `disabled`. The loader rejects any v1 contract that enables it.

Live professional-profile enrichment remains off until the documented transparency notice has been sent and the release owner explicitly approves the run.

## Rendering

```python
from community_os.render import render_report
from community_os.talent_intelligence_contract import load_talent_intelligence_contract

contract = load_talent_intelligence_contract(
    "config/contracts/talent-intelligence-v1.synthetic.json"
)
vc_html = render_report(contract, audience="vc")
company_html = render_report(contract, audience="company")
```

Or build both HTML files and optional PDFs:

```bash
python3 -m community_os.talent_briefs \
  config/contracts/talent-intelligence-v1.synthetic.json \
  output/talent-intelligence \
  --pdf
```

The renderer requires an explicit `vc` or `company` audience. This prevents accidental production of a compromised generic report.

## Failure behavior

The loader fails closed on malformed JSON, missing or extra keys, invalid types, unsafe counts, PII-like text, contradictory privacy state, broken funnel ordering, unreconciled selection outcomes, unreconciled exclusive dimensions, unknown intersection components, intersection counts above component populations, impossible coverage, enabled appendix generation, and unresolved required publication gates.
