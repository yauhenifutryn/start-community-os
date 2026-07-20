# Controlled post-approval release runbook

Status: operational readiness guidance, not a legal-compliance determination.

The accountable operator owner is `privacy_lead`. the release owner is the separate processing, Coresignal, and publication approval authority. The protected operator must remain behind the authenticated proxy described in `deploy/operator/README.md`.

## Machine-enforced boundaries

- The controlled release loads one exact-key `controlled-release-v2` approval bundle against one explicit strict event definition. Missing, extra, expired, or inconsistent records fail closed before provider transport is created.
- The nested `event-approval-v2` binds the event-definition hash, configured adapters and mapping hashes, exact uploaded-source hashes, policy/taxonomy versions, and current exclusion set. A changed file, mapping, event definition, or exclusion set requires a new approval.
- GitHub and applicant-public-page approvals are independent bound records. GitHub is required; public pages may be explicit `null`. Coresignal remains locked while `coresignal` is `null`, requires its own post-notice approval plus a managed token before any call, and remains a separate internal evaluation rather than a partner-release input.
- Semantic classification remains locked while `semantic_processor` is `null` or `OPENAI_API_KEY` is absent. A key never substitutes for processor approval.
- `privacy_operations` records source-specific allowed uses, notice details, rights status, accountable owner, an absolute retention deadline, and a time-bounded processing approval.
- `excluded_subject_refs` may contain only exact, known `pid:v1` pseudonyms from the approved applicant population. Malformed, duplicate, or unknown references fail closed. A valid set is removed before reconciliation, enrichment, classification, aggregates, operator exports, HTML, and PDF; only its count and deterministic set hash enter audit evidence.
- The aggregate and report stages write the reviewable release to `<root>/protected/release/`. Nothing in that directory is public.
- Sharing requires a `publication_approval` bound to the current event-approval SHA-256, the protected HTML SHA-256, and one deterministic SHA-256 over the exact two-artifact HTML/PDF allowlist. Only those two approved aggregate artifacts are copied to `<root>/public-staging/`, with analytics disabled.
- `public-staging` is a staging boundary, not evidence that deployment or publication occurred.
- Analytics is absent from "Run approved release" and from analytics-free `public-staging`. PostHog requires a separate release-owner action bound to the exact staged report and manifest. The action machine-verifies `anonymize_ips=true` and the public-key binding through the EU project-settings API, binds the protected receipt hash, creates a distinct `deployment-staging` directory, and never deploys.

## Approval bundle

Store the bundle at `<root>/protected/controlled-release-approval.json`, mode `0600`, or pass a protected path with `--approval-bundle`. It must contain exactly these top-level keys:

```json
{
  "bundle_version": "controlled-release-v2",
  "generated_at": "2026-07-13T12:00:00Z",
  "event_approval": {
    "version": "event-approval-v2",
    "event_key": "openai-hackathon-2026",
    "event_definition_sha256": "<event definition SHA-256>",
    "policy_profile": "aggregate-partner-v1",
    "taxonomy_version": "semantic-taxonomy-v1",
    "metric_registry_version": "partner-metrics-v1",
    "sources": {
      "applications": {
        "adapter_id": "luma-csv-v2",
        "mapping_sha256": "<approved mapping SHA-256>",
        "source_sha256": "<approved source SHA-256>"
      },
      "attendance": {
        "adapter_id": "luma-supplement-csv-v1",
        "mapping_sha256": "<approved mapping SHA-256>",
        "source_sha256": "<approved source SHA-256>"
      },
      "preferences": {
        "adapter_id": "track-preferences-xlsx-v1",
        "mapping_sha256": "<approved mapping SHA-256>",
        "source_sha256": "<approved source SHA-256>"
      },
      "submissions": {
        "adapter_id": "devpost-final-xlsx-v1",
        "mapping_sha256": "<approved mapping SHA-256>",
        "source_sha256": "<approved source SHA-256>"
      }
    },
    "excluded_subject_refs": [],
    "actor_code": "release_owner",
    "approved_at": "2026-07-13T10:00:00Z"
  },
  "public_sources": {
    "github": {},
    "public_pages": {}
  },
  "coresignal": null,
  "semantic_processor": null,
  "privacy_operations": {
    "accountable_owner": "privacy_lead",
    "approval": {
      "actor_code": "release_owner",
      "approved_at": "2026-07-13T10:00:00Z",
      "expires_at": "2026-08-12T10:00:00Z"
    },
    "allowed_uses": {
      "applications": ["aggregate"],
      "attendance": ["aggregate"],
      "preferences": ["aggregate"],
      "submissions": ["aggregate"],
      "github": ["classify"],
      "public_pages": ["classify"],
      "coresignal": ["classify"],
      "classification": ["aggregate"],
      "partner_report": ["publish"]
    },
    "excluded_subject_refs": [],
    "notice_sent_at": "2026-07-13T08:00:00Z",
    "notice_version": "notice_v2",
    "retention_deadline": "2026-10-11T12:00:00Z",
    "rights": {
      "deletion_status": "not_requested",
      "exclusion_status": "included",
      "objection_status": "none",
      "reconciled": true,
      "suppression_status": "not_requested"
    }
  },
  "publication_approval": null
}
```

The event approval example shows the current START source preset. For another supported event, its `sources` keys must exactly match the strict event definition. The application computes the observed source hashes from protected uploads and rejects caller-selected adapters, mappings, paths, or hashes. Required sources cannot be `null`; only an optional source may bind `source_sha256` as `null` when the event definition and observed state agree.

The empty `github` and `public_pages` objects above are placeholders, not valid approvals. GitHub must include every field accepted by `PublicSourceGate`. `public_pages` may instead be explicit `null`. A configured gate contains notice version/time, four rights-reconciliation booleans, source authorization confirmation, terms version, exact source scope, purpose code, retention days, owner, approval ID, and approval time. Use `applicant_supplied_github` with at most 30 days and `applicant_supplied_public_pages` with at most 14 days. `purpose_code` is `aggregate_talent_evidence`; owner is `privacy_lead`. The approval must be after the notice and not in the future.

If a separate internal Coresignal evaluation is approved, replace `null` with the exact `CoresignalGate` record: notice version/time, four reconciliation booleans, verified access, terms version, `applicant_supplied_linkedin` source scope, retention days, and the release owner's approval ID/time. Record it only after the notice and qualified review of access, terms, purpose, region, and retention. The release action still rejects Coresignal as a partner-report input.

If semantic processing is approved, replace `semantic_processor` with one exact reviewed record and provide `OPENAI_API_KEY` through the managed secret store. Two postures are accepted: `eu` with verified `zero_retention`, or `global` with acknowledged `default_abuse_monitoring_30d`. The production transport maps those records only to `https://eu.api.openai.com/v1/responses` or `https://api.openai.com/v1/responses`; it does not accept caller-supplied hosts. `store: false` is sent on every request, but it does not prove Zero Data Retention or project residency. Successful access through `eu.api.openai.com` is route-connectivity evidence only unless Europe is exposed and selected in the project data-residency control.

```json
"semantic_processor": {
  "provider": "openai_responses",
  "purpose": "talent_classification",
  "dpa_version": "2026-01-01",
  "terms_version": "2026-01-01",
  "retention_mode": "default_abuse_monitoring_30d",
  "region": "global",
  "security_profile": "project_scoped_store_false_minimized_v1",
  "field_allowlist": ["evidence_refs", "signals", "subject_ref"],
  "approved_by": "start_privacy_owner",
  "approved_at": "<timezone-aware timestamp>"
}
```

The global example records the current non-resident posture honestly. It does not authorize identifiers, URLs, free text, raw evidence, additional input fields, individual decision-making, or publication of person-level output. Record any owner decision to proceed without another participant message in the protected readiness evidence; do not rewrite the notice history or claim that the notice explicitly named OpenAI processing.

## Controlled action

1. Prepare the strict event definition. On first launch without `--event-config`, the authenticated setup screen creates `<root>/event-definition.json` from registered START profiles, then stops before the release runtime starts. Restart once to reuse that file. Advanced deployments may instead pass `--event-config <managed event-definition.json>`.
2. Upload and validate the configured protected sources. Bind the exact event definition, adapters, mapping hashes, observed source hashes, policy/taxonomy versions, and current exclusion set in `event_approval`; a mismatched or truncated same-schema population blocks before enrichment unlocks. Resolve corrections, identity cases, team links, and classification reviews.
3. Record the notice, rights reconciliation, source authorization, semantic-processor approval, retention, and time-bounded processing approval in the protected bundle. Keep Coresignal `null` unless the release owner has separately approved a separate internal evaluation.
4. Start the protected operator using the command in `deploy/operator/README.md`, then click "Run approved release".
5. The action physically removes expired GitHub, public-page, Coresignal, and classification cache/stage payloads, then runs or resumes only incomplete stages. If enrichment creates new semantic review cases, it stops before aggregation; resolve those cases and run the action again. With reviews resolved and no publication approval, it generates `<root>/protected/release/` and stops at "Needs review".
6. Inspect the protected HTML/PDF, resolve any remaining review cases, and run privacy/parity QA. Record the SHA-256 of `talent-brief.real.html`, the current event-approval SHA-256, and the deterministic artifact-set SHA-256 for exactly `talent-brief.real.html` and `talent-brief.real.pdf`. Protected aggregates remain internal evidence and are not included in the share set.
7. As the authenticated release owner, click "Approve and stage partner share". The operator verifies the sealed semantic candidate, writes the exact event-and-artifact-bound record below to the protected bundle with `approved_at` at or after report generation, reloads the approval-bound operations, and runs only the local `publish` stage. Manual JSON editing is no longer part of the routine operator workflow.

```json
"publication_approval": {
  "actor_code": "release_owner",
  "approved_at": "2026-07-13T12:30:00Z",
  "artifact_set_sha256": "<64 lowercase hex characters>",
  "event_approval_sha256": "<64 lowercase hex characters>",
  "report_sha256": "<64 lowercase hex characters>"
}
```

8. Publication becomes "Safe to publish" only when all release evidence passes. The operator copies neutral `index.html`, `partner-talent-brief.pdf`, and `publication-manifest.json` to `<root>/public-staging/`. This base staging is analytics-free and is not yet the hosted bundle.
9. If hosted measurement is approved, create or select a PostHog EU project and disable IP capture under Settings > Project > General. Export a short-lived personal key restricted to this project with only `Project: Read` as `POSTHOG_PERSONAL_API_KEY`, plus the numeric `POSTHOG_PROJECT_ID`; organization-wide access is not required. As the authenticated release owner, enter the public project key and click "Prepare analytics bundle". The operator requires the live project response to return `anonymize_ips=true` and the same public key, persists a protected receipt hash, and binds it into `<root>/deployment-staging/` with `vercel.json`, hash-pinned CSP, analytics-enabled `index.html`, neutral PDF, and the new manifest. It records only five aggregate interaction events with a per-page-load identity and no person profile, autocapture, storage, replay, URL, referrer, free text, or participant property. This step does not publish or deploy. Revoke the short-lived settings key after preparation.
10. The PDF may be sent directly to partners. To host the interactive dashboard on Vercel, deploy only the four exact files in `deployment-staging` to a preview first, then verify the hosted hashes, CSP and other response headers, PDF download, privacy/count parity, and PostHog event/property allowlist. Promote only that verified preview and create an external receipt. Do not deploy the operator root, `protected/release`, `public-staging`, uploads, aggregates, caches, stage outputs, QA report, analytics audit, or other protected files.

## Independent retention cleanup

Run this from a private scheduler whether or not a release approval exists:

```bash
python3 -m community_os privacy-cleanup \
  --root /srv/start-community/operator-data \
  --event-config /srv/start-community/operator-data/event-definition.json
```

The command physically deletes expired GitHub, public-page, Coresignal, and classification cache entries and stage envelopes. It also purges `protected/raw-evidence` records at their maximum 24-hour TTL and leaves only minimized deletion receipts. Crash-orphaned cache, stage, and raw-evidence temporary files are deleted because their retention cannot be proven. A malformed retained envelope is deleted for the same reason. Raw evidence is also deleted immediately when its provider authorization is revoked or the subject-exclusion set changes. When a raw source reaches its inventory deadline, the source upload, raw evidence, derived stages, caches, private preview, review bindings, and public staging are deleted and its validated source slot is cleared. When committed stage data or temporary raw evidence expires, dependent classification, aggregate, report, publication, analytics, and public staging state is invalidated before reuse. It appends only deletion counts, a reason code, and run time to `protected/privacy-cleanup-audit.jsonl`; it does not include participant identifiers.

Temporary raw-evidence records use a maximum 24-hour TTL. Classification caches and stage outputs use a maximum 30-day TTL. Raw sources and their derivatives use the absolute bundle deadline. Pseudonymous audit history and backups still require separately configured and tested lifecycle deletion. Schedule the command at least daily, alert on nonzero exit, and protect its output. The command and operator mutations share a filesystem lock, so every production replica must mount the same protected root for mutual exclusion.
