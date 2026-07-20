# Product architecture

START Community OS is a reusable, local-first event intelligence product. It turns registered event exports into a private reviewed evidence store, deterministic cohort aggregates, a self-contained partner dashboard, and a composed landscape PDF. The current event is a validation case, not a code-path special case.

## System boundaries

1. Registered adapters ingest application, attendance, preference, and submission exports into protected local state.
2. Reconciliation creates one event population and explicit unresolved identity cases.
3. Optional provider stages create protected evidence only after their separate gates are approved.
4. Human-reviewed facts are the sole input to deterministic semantic aggregation.
5. The report projection applies denominators, unknown states, and privacy thresholds before rendering.
6. The local operator controls upload, review, approved runs, preview, approval, and export.
7. Publication staging copies only `index.html`, neutral `partner-talent-brief.pdf`, and a hash-bound `publication-manifest.json`, with analytics disabled.
8. An optional release-owner action derives a separate `deployment-staging` bundle with `vercel.json`, a hash-pinned CSP, and a fixed aggregate-only PostHog event allowlist. It never deploys.

The HTML and PDF share claims and evidence bindings but have different layouts. HTML interactions operate only on embedded aggregate state. The PDF is static, landscape, and complete without interaction.

## Cross-dimensional aggregate

The overlap exhibit is a deterministic aggregate over three reviewed application signals: Founder or co-founder evidence, Technical function, and Shipped-product evidence. Every applicant belongs to exactly one of the eight mutually exclusive rows defined by the three yes or not-recorded states. Those eight row counts must sum to the full denominator, and each published signal total must be independently rederived from the rows that contain it. The three signal totals overlap, so they must not be added together as percentages of a whole.

The student-stage overlay is separate and non-additive. It answers one extra reviewed question without turning the primary chart into a four-signal partition whose small cells could breach the privacy threshold. In every row and overlay, signal not recorded means only that the reviewed evidence did not support that positive label. It is never a negative talent assessment. If any exact row is nonzero but below the configured minimum, the complete exact partition is withheld because the other rows and marginals could otherwise reveal it.

## Privacy boundaries

Raw exports, normalized person records, identity links, provider responses, review packets, credentials, semantic facts, QA detail, and real-event generated artifacts stay under protected local storage and outside Git. Public outputs contain aggregate values only, suppress groups below the configured threshold, and describe unavailable or conflicting evidence as unknown rather than negative.

The partner dashboard has no person browser or person-level payload. Its approved base staging has no external runtime, analytics, browser storage, or provider connection. Optional deployment staging uses no external SDK, cookies, local or session storage, session replay, autocapture, stable viewer identity, URLs, referrers, or participant properties. It sends only allowlisted aggregate interaction events to the PostHog EU endpoint with a per-page-load random identifier and person-profile processing disabled. Project-level IP capture must be disabled separately. Coresignal is not part of the current partner release. A future Coresignal overlay requires explicit notice or consent, a small canary, representative reviewed coverage, and a separate release decision. The software does not claim legal compliance.

## Approval and invalidation

Provider authorization, semantic-review attestation, semantic release, and publication are distinct gates. Each approval binds exact hashes. Changed sources, reviewed facts, cohort totals, presentation copy, HTML, PDF, or QA invalidate downstream release state without rerunning completed paid enrichment.

Retention is also hash and deadline bound. The local cleanup path removes expired source uploads and derivatives, transient provider evidence, caches, review bindings, previews, and staging, then invalidates downstream approvals. Operator audit history, Privacy Operations records, external audit sinks, and backups need a separate deployment retention schedule because the local cleanup intentionally does not delete them. The executable schedule and its remaining deployment responsibility are listed in `docs/OPERATOR_GUIDE.md` and `docs/privacy/data-processing-retention-matrix.md`.

## Deployment separation

The operator remains local or on a separately authenticated private container. It is never included in a static bundle. Analytics-free `public-staging` is the host-independent content set. The separately derived `deployment-staging` adds a verified Vercel response-header wrapper and PostHog interaction wiring. This repository never publishes, deploys, creates a hosting project, or writes a provider project ID automatically. Eligible Codex Sites deployments include built-in unique visitors and page views, but this repository has not verified custom response headers, PDF delivery, or its PostHog interaction contract there; Vercel provides the currently tested path for those controls. Optional PostHog adds only the fixed report-interaction events. Analytics preparation is local, explicit, separately invalidated, and never part of report generation or publication approval.

## Commercial extension points

- New registered source adapters for other event platforms.
- Longitudinal event comparisons using the same versioned metric registry.
- Consent-based, targeted professional-context overlays.
- Partner-specific editorial presentation choices that reference the same approved aggregate facts without changing cohort values.
- Private CRM export after an independently approved person-level workflow.
- Post-event outcome instrumentation collected prospectively, never inferred retroactively.
