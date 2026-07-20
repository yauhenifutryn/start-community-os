# Protected operator deployment contract

This is not a public static service. Deploy it only after the identity, storage, scheduler, and incident controls below are configured and tested.

## Runtime boundary

- TLS terminates at an authenticated identity proxy.
- The proxy overwrites, rather than forwards, `X-Operator-Email` and `X-Operator-Proxy-Secret`.
- `OPERATOR_PROXY_SECRET` comes from a managed secret store and is shared only with the proxy.
- `OPERATOR_ALLOWED_EMAILS` is the exact comma-separated colleague allowlist.
- `OPERATOR_RELEASE_OWNER_EMAILS` is the subset allowed to seal an exact share bundle.
- `OPERATOR_PSEUDONYM_SECRET` is a managed, stable secret of at least 16 bytes. Rotating it changes deterministic pseudonyms and requires a controlled migration.
- `GITHUB_TOKEN`, `CORESIGNAL_API_TOKEN`, and `OPENAI_API_KEY` come from the secret store. Coresignal still cannot run without its separate bundle gate and explicit release-owner approval. OpenAI cannot run without the separate processor approval record.
- The operator data root is an encrypted persistent volume with least-privilege access, backups, restore tests, and a documented key owner.
- Network policy permits only required provider/API egress and blocks metadata/private ranges.
- Access, stage, review, export, publication, and deletion events enter a protected append-only audit sink.
- Rate limiting and request concurrency limits are enforced at the proxy. The application itself permits only one concurrent state-changing request per process.

The proxy must not expose `<root>/protected/`, `<root>/operator-state.json`, `<root>/pipeline-state.json`, `<root>/public-staging/`, or `<root>/deployment-staging/` as static directories. Public hosting receives a separate copy of the verified deployment bundle only after deployment review.

## Approval and storage layout

The default approval path is:

```text
<root>/protected/controlled-release-approval.json
```

The exact-key `controlled-release-v2` bundle contains an `event-approval-v2` record bound to the event-definition hash, adapter and mapping hashes, exact source hashes, and exclusion set. It also contains `privacy_operations`, separate GitHub/public-page gates, optional Coresignal approval, optional semantic-processor approval, and an optional share approval bound to the event approval, HTML, and exact HTML/PDF artifact-set hashes. Keep both the bundle and event definition mode `0600`. See `docs/privacy/controlled-release-runbook.md` for fields and the two-pass approval procedure.

Important paths:

```text
<root>/event-definition.json             strict event definition created by first-run setup
<root>/protected/uploads/                 raw event inputs configured by that definition
<root>/protected/cache/                   provider caches
<root>/protected/stages/                  raw enrichment and derived stage envelopes
<root>/protected/release/                 private HTML/PDF/aggregate preview
<root>/protected/privacy-operations.json  derived inventory and release state
<root>/protected/privacy-cleanup-audit.jsonl
<root>/protected/operator-access-audit.jsonl  pseudonymous colleague access/action log
<root>/public-staging/                     analytics-free host-independent allowlist
<root>/deployment-staging/                 optional Vercel-ready analytics bundle
```

`protected/release` is never the public web root. After exact approval, `public-staging` is the exact three-file static bundle: `index.html`, `partner-talent-brief.pdf`, and `publication-manifest.json`. The manifest keeps analytics disabled. After a separate release-owner action, `deployment-staging` is the exact four-file deployment bundle: `vercel.json`, `index.html`, `partner-talent-brief.pdf`, and `publication-manifest.json`. Protected aggregates remain internal evidence and are not part of the teammate or partner share.

## Launch

```bash
export OPERATOR_PROXY_SECRET='<managed secret>'
export OPERATOR_ALLOWED_EMAILS='colleague1@example.org,colleague2@example.org'
export OPERATOR_RELEASE_OWNER_EMAILS='release-owner@example.org'
export OPERATOR_PSEUDONYM_SECRET='<managed stable secret, at least 16 bytes>'
export GITHUB_TOKEN='<optional managed token>'
export CORESIGNAL_API_TOKEN='<only after separate approval>'
export OPENAI_API_KEY='<only after processor approval>'

python3 -m community_os release-operator \
  --root /srv/start-community/operator-data \
  --host 0.0.0.0 \
  --port 8766 \
  --approval-bundle /srv/start-community/operator-data/protected/controlled-release-approval.json
```

Health check: `GET /health`. All other routes require authenticated proxy headers. The app also enforces CSRF for state-changing requests, restrictive file modes, upload size/schema checks, source hash revalidation, protected export allowlists, and a mutation lock. It derives a stable HMAC actor code from the authenticated colleague email and appends only code-valued view, export, upload, review, stage, and release events to `operator-access-audit.jsonl`; raw emails are not stored in that log.

On the first launch, the authenticated setup screen creates `<root>/event-definition.json` from registered START source and report profiles, then asks for one restart. Later launches reuse it automatically. Supplying `--event-config /managed/path/event-definition.json` remains available for an externally managed definition.

"Run approved release" runs privacy cleanup first, resumes failed or incomplete permitted stages, writes the preview under `protected/release`, and stops before publication. The authenticated release owner then uses "Generate QA and approve exact candidate" to regenerate semantic QA, seal the exact reviewed aggregate and report candidate, and regenerate only local HTML/PDF output. A separate "Approve and stage partner share" action binds the current event approval, HTML, PDF, and artifact-set SHA-256 values, then runs only the local publication stage. That action may create `public-staging`; it does not deploy, call a provider, or enable analytics. A later "Prepare analytics bundle" action requires a PostHog EU public project key plus local `POSTHOG_PERSONAL_API_KEY` and `POSTHOG_PROJECT_ID` values. It reads the live project settings, requires `anonymize_ips=true`, verifies the public-key binding, writes a protected hash receipt, and only then creates `deployment-staging`. It still does not deploy. Self-attestation is not sufficient.

## Required independent cleanup schedule

Run at least daily, even when no release is planned:

```bash
python3 -m community_os privacy-cleanup \
  --root /srv/start-community/operator-data \
  --event-config /srv/start-community/operator-data/event-definition.json
```

This command requires no approval bundle. It physically deletes expired GitHub/public-page/Coresignal/classification cache entries and protected stage files. When a raw source reaches its inventory deadline, it also deletes that upload, clears the source slot, removes all derived stages, caches, private previews and review bindings, withdraws public staging, and appends a count-only audit record. Alert on any nonzero exit and on a missed schedule. Cleanup and operator mutations share `<root>/.operator-mutation.lock`; all replicas must use the same protected root.

Classification caches and stage envelopes use a maximum 30-day TTL. Raw uploads and their derivatives use the approval-bundle inventory deadline and are now covered by the same deletion command. Configure and test separate storage-lifecycle deletion for pseudonymous audit history and backups using `docs/privacy/data-processing-retention-matrix.md`.

## Operator and dashboard deployment remain separate

1. Run the stateful operator only on a private container or application platform behind the authenticated proxy. Codex Sites and other static hosts are not valid operator targets.
2. Treat `public-staging` and `deployment-staging` as allowlisted build artifacts, not evidence that anything was shared or deployed.
3. The three-file `public-staging` content is host-independent and analytics-free. The four-file `deployment-staging` adds the verified Vercel security wrapper and privacy-minimized PostHog interaction wiring.
4. After exact human share approval, create a Vercel preview from only `deployment-staging`. Never deploy the operator root. The PDF may instead be sent directly to partners.
5. Verify preview HTML, PDF, manifest and `vercel.json` hashes; actual response headers; PDF download; responsive interaction; and the exact PostHog event/property allowlist. Record a receipt outside the public bundle.
6. Promote only the verified preview after explicit action-time approval. Vercel Web Analytics is a separate project-level option and is not silently added by this bundle.

The image and configuration here are readiness scaffolding. The operator service is unsuitable for Codex Sites or any public static host. Use a private container or application platform with an authenticated identity proxy, encrypted protected volume, allowlisting, managed secrets, daily cleanup, backup/restore, rate limits, an append-only audit sink, and an incident process. Do not deploy the operator until those controls are configured and verified. Do not deploy the aggregate dashboard until its exact current share approval is recorded.
