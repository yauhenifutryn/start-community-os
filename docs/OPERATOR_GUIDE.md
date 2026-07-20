# Operator guide

## Install

Requirements are Python 3.11 or newer and standard command-line tools. Runtime Python code uses the standard library. PDF generation additionally needs an isolated Chromium or Chromium headless shell. Never point it at a personal Chrome profile.

```bash
git clone <repository-url> start-community-os
cd start-community-os
python3 -m unittest discover -q
```

The synthetic demo needs no environment file. Before local operator or provider work, copy the blank template to ignored `.env.local`, fill only the variables needed for that run, and explicitly export them into the current shell:

```bash
cp .env.example .env.local
set -a
. ./.env.local
set +a
```

The core CLI deliberately does not auto-load `.env.local`. Re-run the export block in each new shell before launching the operator. Before publication, run the repository-productization tests, the clean-clone acceptance flow, and a tracked-file secret scan. `.env.local`, operator roots, uploads, protected evidence, real reports, and publication staging are ignored and must remain outside commits and distributable bundles.

## Synthetic demo

The built-in fixture uses no credentials and makes no provider calls.

```bash
python3 -m community_os build --config config/events/example.synthetic.json
```

The HTML appears below ignored `output/`. To generate a PDF, set `COMMUNITY_OS_CHROMIUM_EXECUTABLE` to an isolated Chromium executable and run:

```bash
python3 -m community_os build --config config/events/example.synthetic.json --pdf
```

## Configure an event

Launch the operator without `--event-config` to use the registered first-run setup. It writes a strict `event-release-v1` definition to `<operator-root>/event-definition.json` with mode `0600`. `config/events/openai-hackathon-2026.json` is the checked-in shape reference for the registered START source profile. The advanced `--event-config` path accepts only that exact schema and already registered adapter, mapping, report, privacy, and artifact identifiers. The demo builder's `config/events/example.synthetic.json` is a different, simpler contract and is not a protected-release event definition. Browser input cannot provide local paths, source hashes, or mapping hashes; the server derives them.

Protected operator state is durable evidence, not a cache. The default root is `$XDG_DATA_HOME/start-community-os/operator`, or `~/.local/share/start-community-os/operator` when `XDG_DATA_HOME` is unset. For a named event, prefer an explicit backed-up private path outside a disposable worktree. The CLI rejects `/tmp`, `/private/tmp`, the operating system's temporary directory, and their descendants. `--allow-ephemeral-root` exists only for synthetic automated tests; using it with real participant evidence defeats recovery and approval replay.

```bash
python3 -m community_os release-operator \
  --root /absolute/private/operator-root \
  --host 127.0.0.1 \
  --allowed-email operator@example.invalid \
  --release-owner-email owner@example.invalid
```

The command reads `OPERATOR_PROXY_SECRET` and `OPERATOR_PSEUDONYM_SECRET` from the local environment. Keep the service on loopback unless an authenticated proxy is deliberately configured.

## Operator workflow

1. Upload each required source into protected storage.
2. Review schema and identity exceptions.
3. Record notice, rights, retention, and provider approvals for this event.
4. Run only the enabled stages. A locked or unavailable optional stage is a valid state.
5. Resolve review cases and inspect private provenance and unknown states.
6. Choose bounded cover copy, then preview the interactive HTML and PDF.
7. Run QA, seal the reviewed semantic candidate, then use "Approve and stage partner share" as the authorized release owner. This writes the exact event, HTML, PDF, and artifact-set hashes and runs only the local publication stage.
8. For hosted measurement, create or select a PostHog EU project, disable IP capture under Settings > Project > General, and export the local verification credentials described below. The analytics form remains visible before verification. Preparation succeeds only after live verification of the project and public-key binding. The generated capture payload also disables GeoIP enrichment per event. This creates a separate local bundle and does not publish or deploy.
9. Export the verified Vercel configuration, HTML, partner PDF, and publication manifest. Deployment is a separate action.

The primary UI intentionally exposes only Upload, Review, Run, Preview, Approve, and Export. Advanced ledgers and QA remain available behind disclosures.

## Provider gates

- GitHub: optional. Set `GITHUB_TOKEN` only after event notice and public-source approval are current. Missing repositories are unknown, not negative.
- OpenAI: optional. Set `OPENAI_API_KEY` only after processor, purpose, payload, region, retention, security, budget, and human-review gates are current. Existing reviewed facts can be rerendered without another call.
- Coresignal: optional future overlay. `CORESIGNAL_API_TOKEN` alone does not enable it. Use explicit notice or consent and a small marginal-information canary before broader spend. It contributes zero to the current OpenAI Hackathon partner report.

Never commit provider keys. Blank environment variables keep every provider off.

## Report generation

Candidate rendering from protected reviewed aggregates is local and publication-ineligible until exact QA and human release approval pass. The dashboard compares cohorts only when membership and denominators are supported, keeps missing or unresolved reviewed evidence explicit as unknown, and never treats organizer selection as a quality label.

The analytics-free `public-staging` bundle contains only:

- `index.html`
- `partner-talent-brief.pdf`
- `publication-manifest.json`

The optional `deployment-staging` bundle contains only:

- `vercel.json`
- `index.html`
- `partner-talent-brief.pdf`
- `publication-manifest.json`

The final manifest binds the approved source staging plus the exact deployment bytes. The operator fails closed if a staged byte, source hash, CSP, analytics policy, or pipeline receipt changes. Do not add the operator, protected aggregates, QA detail, raw data, source maps, or audit files.

## PostHog analytics boundary

[Codex Sites](https://learn.chatgpt.com/docs/sites.md) reports total unique visitors and page views over time without adding an analytics SDK. [Vercel Web Analytics](https://vercel.com/docs/analytics) provides anonymous, cookie-free reach metrics but requires its project-level client script. The current report does not add that external runtime. Add PostHog only to learn which parts of the aggregate report partners use, not who the partners are. The only events are `report_opened`, `pdf_downloaded`, `cohort_selected`, `metric_selected`, and `overlap_region_selected`. The only business properties are `report_version`, `cohort_key`, `metric_key`, and `overlap_region`.

Do not collect names, emails, organization or partner identity, participant data, evidence values, free text, URLs, referrers, geolocation, device fingerprinting, or a stable viewer ID. Autocapture, pageview capture, person profiles, session replay, surveys, cookies, local storage, and session storage stay off. A new random identifier is created in memory for each page load, so event and page-open totals are useful but unique-person and return-visitor counts are intentionally unreliable.

Before preparing the bundle:

1. Use an EU PostHog project.
2. Disable IP capture under Settings > Project > General. Existing projects do not necessarily inherit an organization-level default.
3. Give the local process `POSTHOG_PERSONAL_API_KEY`, restricted to this project with only `Project: Read`, plus `POSTHOG_PROJECT_ID` and the public `POSTHOG_PUBLIC_PROJECT_KEY`. Organization-wide access is not required. The personal key remains local and must never enter the report, staging bundle, manifest, logs, prompt text, or repository.
4. Run the operator's verification action. It reads the live EU project, requires `anonymize_ips=true`, checks the public-key binding, and stores only a protected hash receipt bound to the project, public key, response, and verification time. A checkbox or self-attestation is not accepted.
5. Prepare the analytics bundle only while that machine-verification receipt is current and bound to the exact public key.
6. After deployment, verify in browser network tools that the only external origin is `https://eu.i.posthog.com` and that captured properties match the allowlist.

The public disclosure accurately calls this privacy-minimized analytics. Do not describe it as perfectly anonymous or as legal compliance.

The three content artifacts remain ordinary static files. The optional `vercel.json` wrapper pins response headers for a Vercel preview; the HTML also carries its script, style, connection, and referrer restrictions in a meta policy. Do not create or link a Vercel or Codex Sites project during local preparation. After explicit deployment approval, create a preview first, inspect actual response headers and behavior, and promote only the verified preview. A Codex Sites alternative must be saved without deployment and tested for PostHog connectivity and header behavior before its production deployment.

## Analytics review loop

After the public URL is verified and sent, schedule two read-only Codex reviews for day 7 and day 14, or one weekly review for the first three weeks. Use the existing project task if report context should stay together. Local scheduled tasks require the Codex desktop app and computer to be running at the scheduled time.

Give the scheduled task a read-only PostHog personal API key through the local secret store, never through the report, repository, prompt text, or public `phc_...` project key. Its query must return aggregates only: report opens, PDF download rate, cohort selections, metric selections, overlap-region selections, and week-over-week change. Suppress any behavioral slice below five page loads, do not export raw events, and state that the per-page-load identifier cannot measure unique people or returning visitors.

Use a webhook only for a narrow immediate threshold alert that justifies maintaining an authenticated receiver. A scheduled review is the default because it can compare periods, add low-sample caveats, and produce one partner-facing interpretation without adding another public endpoint.

## Future event data collection

Collect future demographic and outcome fields prospectively, directly from participants, and with a clear purpose. Good candidates are optional self-reported age band, gender, country or region, current role or seniority, student status, graduation year, institution, primary technical function, founder status, canonical GitHub handle, and consented professional-profile link. Keep nationality separate from current location and never infer sensitive traits from names, photos, or profiles.

For post-event value, add opt-in 30-day and 90-day follow-ups for collaborations, hires, pilots, funding conversations, continued projects, and shipped products. Define every answer option and missing state before collection. Do not retrofit these fields onto the current event or treat non-response as a negative outcome.

## Cleanup and retention

Run `privacy-cleanup` daily for every active protected operator root. The repository provides the command but not a background scheduler; a local launch agent, cron job, or private deployment scheduler is the operator's responsibility. Preview cleanup first, then apply only after checking the selected protected root and policy deadline.

```bash
python3 -m community_os privacy-cleanup \
  --root /absolute/private/operator-root \
  --event-config /absolute/private/operator-root/event-definition.json
python3 -m community_os cleanup --help
```

The enforced and configured schedule is:

| Data | Deadline | Cleanup behavior |
|---|---:|---|
| Protected source uploads | Absolute event-specific `privacy_operations.retention_deadline` | `privacy-cleanup` deletes the expired upload and all local derivatives, then clears its source slot. |
| Transient raw provider evidence | Maximum 24 hours | `privacy-cleanup` deletes expired or unreadable evidence and retains only minimized deletion receipts. |
| GitHub cache and stage | Approved gate value, 1 to 30 days | Physical deletion and downstream invalidation. |
| Applicant public-page cache and stage | Approved gate value, 1 to 14 days | Physical deletion and downstream invalidation. |
| Optional Coresignal cache and stage | Approved gate value, 1 to 30 days | Physical deletion and downstream invalidation. Coresignal remains off for the current release. |
| Semantic-classification cache and stage | 30 days | Physical deletion and downstream invalidation. Processor-side retention is a separate gate. |
| Aggregate preview and release bundle | Bound absolute deadline plus an explicitly approved rollback window | Deleted when its source deadline expires; changed inputs invalidate approval earlier. |
| Operator audit history, Privacy Operations records, external audit sink, and backups | Deployment-specific reviewed schedule | Not covered by `privacy-cleanup`; configure this before any non-local operator deployment. |

The simpler SQLite demo command preserves two older lifecycle ceilings: `cleanup --apply` redacts raw payloads and answers under the 12-month raw-data policy, while the separate ghost transition minimizes an inactive person's identity after the 36-month inactivity threshold. These do not replace the stricter release-operator deadlines above.

Rights-driven suppression or deletion invalidates affected aggregates and reports. Never delete old worktrees, branches, protected runs, or evidence stores as part of an unrelated release.

## Tests

```bash
python3 -m unittest discover -q
python3 -m compileall -q community_os tests
git diff --check
```

After a verified commit, run the clean-clone acceptance procedure in `README.md` from a fresh temporary clone with provider variables unset.

## Troubleshooting

- "Adapter missing" means the event export does not match a registered source profile. Add and test an adapter instead of loosening validation.
- "Approval ... missing/stale" means an upstream hash or attestation changed. Reapprove that exact stage; do not bypass it.
- PDF export requires an isolated executable at `COMMUNITY_OS_CHROMIUM_EXECUTABLE`.
- A suppressed value is not zero. It is below the privacy threshold or would reveal a small complement.
- Unknown means missing, insufficient, unavailable, conflicting, or unresolved evidence. It is not a negative judgment.
- Provider stages must remain locked when their credentials or event authorization are absent.
