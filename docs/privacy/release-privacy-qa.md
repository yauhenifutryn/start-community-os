# Release and privacy QA gate

Current verdict: `Blocked` until live notice, source, provider, processing, and rights-reconciliation approvals are recorded. Fixture verification may run now; live enrichment, public deployment, publication, and analytics may not.

The machine release states are exactly `Blocked`, `Needs review`, and `Safe to publish`. `Safe to publish` means the local staging gate passed. It is not a legal-compliance conclusion and does not prove that deployment occurred.

## Required evidence before `Safe to publish`

- Four source schemas and SHA-256 hashes validated in protected storage and exactly matched to the approval bundle before enrichment unlocks.
- Reviewed corrections, identity links/quarantines, team links, and semantic cases resolved.
- The exact-key `controlled-release-v1` bundle is stored in protected storage and is within its processing/retention windows.
- `privacy_operations` identifies every source, purpose, accountable owner, absolute retention deadline, and exact allowed uses.
- Operator views, exports, reviews, stage requests/completions, and release requests/completions are recorded with distinct HMAC-pseudonymous colleague codes and no raw email.
- Notice version/time and objection, exclusion, suppression, and deletion status are reconciled.
- Every `excluded_subject_refs` value is a known, unique applicant pseudonym; the protected exclusion evidence contains only count and set hash; excluded people are absent from reconciliation, enrichment, classification, operator export, aggregate denominators, HTML, and PDF.
- GitHub and public-page source authorization, terms version, purpose, scope, owner, and bounded retention are recorded.
- Coresignal is either `null` and locked, or has verified access and the release owner's separate post-notice approval record. The managed token must not appear in the bundle or logs.
- Semantic processing is either `null` and locked, or has a complete OpenAI processor approval record, an approved managed key, verified EU project settings, approved retention/no-training mode, and the exact three-field allowlist. The key, prompts, and responses must not appear in logs.
- The independent retention cleanup has run successfully; expired or crash-orphaned GitHub/public-page/Coresignal/classification cache and stage payloads are absent, and the pseudonymous cleanup audit exists.
- Expired raw source uploads and all local derivatives are physically deleted by the independent cleanup. Pseudonymous audit history and backups are covered by additional deployment-specific retention/deletion automation.
- Protected report artifacts exist under `<root>/protected/release/`; HTML/PDF counts, denominators, privacy state, coverage, and limitations reconcile.
- Public nonzero cells meet the minimum-cell and complementary-suppression rules.
- the release owner's publication approval is after report generation, its `report_sha256` exactly matches the protected HTML, and its `artifact_set_sha256` binds the exact protected HTML/PDF share pair.
- `<root>/public-staging/` contains only `index.html`, `partner-talent-brief.pdf`, and `publication-manifest.json`; the manifest says `aggregate_only`, `Safe to publish`, and `analytics_enabled: false`.
- No raw export, direct identifier, profile URL, protected path, operator state, QA report, or raw enrichment payload appears in public staging.
- If analytics is prepared, `<root>/deployment-staging/` contains only `vercel.json`, `index.html`, `partner-talent-brief.pdf`, and `publication-manifest.json`; it binds the exact public staging hashes, fixed CSP, EU origin, event/property allowlists, and confirmed IP-capture-disabled setting.
- The hosted deployment contains only deployment staging; hosted artifact hashes match the final manifest and are captured in an external publication receipt.

## Verification commands

```bash
python3 -m unittest discover -q
python3 -m compileall -q community_os tests
git diff --check
python3 -m community_os privacy-cleanup --root /srv/start-community/operator-data
```

For fixture-only controlled-release coverage, run:

```bash
python3 -m unittest -q tests.test_controlled_release tests.test_publication_staging tests.test_postpublication_analytics
```

Browser verification must cover desktop, 390 px mobile, no JavaScript, keyboard focus, reduced motion, console/network requests, all three cohorts, metric and overlap inspection, operator drag/drop and review controls, and protected export authorization. PDF verification must render every A4 page to images and inspect for blank pages, clipping, overlap, broken glyphs, privacy/count drift, and hidden interactive-only evidence.

The release reviewer must additionally inspect `protected/privacy-operations.json`, `protected/privacy-cleanup-audit.jsonl`, `protected/operator-access-audit.jsonl`, `protected/enrichment-manifest.json`, the protected report hashes, `public-staging/publication-manifest.json`, and, when enabled, `deployment-staging/publication-manifest.json` plus `protected/analytics-publication.json`. The one falsifying observation is any participant, artifact, stage, analytics property, or surface that is present despite an unresolved rights request, expired retention, missing approval, privacy mismatch, or non-allowlisted public file.
