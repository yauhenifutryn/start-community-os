# START Warsaw Community OS

Reusable, local-first talent intelligence for event communities. START Community OS ingests registered event exports, reconciles and reviews evidence privately, and generates an aggregate-only interactive HTML dashboard plus a composed landscape PDF.

This repository is source-available under the [PolyForm Free Trial License 1.0.0](LICENSE.md), not an open-source license. Evaluation for less than 32 consecutive calendar days is permitted. Redistribution, production use, and continued or commercial use outside that evaluation permission require a separate written license from the copyright holder. See [NOTICE.md](NOTICE.md).

Live demo: [OpenAI Hackathon 2026 partner dashboard](https://start-community-os.vercel.app/openai-hackathon-2026/). The published event report contains aggregate statistics only. Its local operator, SQLite state, source records, reviewed person-level evidence, provider credentials, and approval receipts are not deployed.

Current status: the current event's four-export aggregate, rich GitHub evidence, reviewed semantic projection, interactive partner HTML, landscape PDF, local operator, privacy-minimal PostHog transform, and event-specific Vercel route are implemented. Coresignal contributes zero to this release. GitHub, bounded applicant-public-page, optional Coresignal evaluation, and OpenAI semantic processing remain behind separate machine gates for future event runs. No deployment or external publication is performed by the test suite.

The protected operator is a private stateful server application. On first launch without `--event-config`, its authenticated setup screen creates a strict registered event definition at `<root>/event-definition.json`; restart the command once, then the UI handles protected uploads, review queues, resumable approved stages, bounded report copy, preview, release-owner semantic and publication approval, optional analytics preparation, and the exact static bundle boundary. Final publication approval writes the current event, HTML, PDF, and artifact-set hashes and runs only the local publication stage. Advanced deployments may still supply an explicit `--event-config`. The operator, raw inputs, aggregates, caches, reviews, and person-level classifications must never be placed on public static hosting.

The two partner artifacts have different jobs. The landscape PDF is the fixed, forwardable partner document. The self-contained HTML recomposes approved aggregate evidence across All, Accepted, and Attended cohorts. It updates values and denominators, lets readers inspect metric definitions and evidence limits, and includes one three-signal exact UpSet-style partition while keeping the complete static claims available without interaction. After exact approval, only `index.html`, `partner-talent-brief.pdf`, and `publication-manifest.json` may enter analytics-free, host-independent `public-staging`. If the release owner explicitly prepares PostHog, only `vercel.json`, `index.html`, `partner-talent-brief.pdf`, and `publication-manifest.json` may enter Vercel-ready `deployment-staging`. Nothing is deployed automatically.

## Quickstart

The runtime is Python standard-library code. Start with the synthetic, zero-credential path:

```bash
git clone <repository-url> start-community-os
cd start-community-os
python3 -m unittest discover -q
python3 -m community_os build --config config/events/example.synthetic.json
```

The zero-credential demo needs no environment file. For local operator or provider work, copy `.env.example` to ignored `.env.local`, fill only the values needed for that run, then export them into the current shell before launching a command:

```bash
cp .env.example .env.local
set -a
. ./.env.local
set +a
```

The core CLI deliberately does not auto-load `.env.local`. For PDF output, set `COMMUNITY_OS_CHROMIUM_EXECUTABLE` there or export it directly to an isolated Chromium executable, then add `--pdf`. Do not use a personal browser profile. See `docs/OPERATOR_GUIDE.md` for event setup, provider gates, report approval, cleanup, and troubleshooting; see `docs/ARCHITECTURE.md` for system and deployment boundaries.

## Supported events

Hackathons using the registered Luma and Devpost export profiles are supported today. Protected release runs use the exact `event-release-v1` schema enforced by `community_os/event_definition.py`; `config/events/openai-hackathon-2026.json` is the checked-in shape reference for the registered START source profile. The first-run operator generates that strict definition from server-owned adapters and mapping hashes. Advanced operators may supply a managed definition only when its adapters, mappings, report family, privacy policy, and artifact profile are already registered. Export columns still fail closed, so a different platform or schema needs a new registered adapter and synthetic fixture before it can process real participants.

The product does not train a model for each event. Reuse comes from versioned schemas, adapters, mappings, taxonomies, and report profiles; optional OpenAI processing classifies bounded reviewed evidence only after its separate approval gate. Demo days, startup competitions, and accelerator cohorts are the closest future profiles because they share application, selection, participation, and project or pitch stages. Conferences and community meetups need a different report family because project submission evidence is not a natural default.

## OpenAI Build Week

START Community OS is entered in the "Work and Productivity" track. The product existed before the submission period, then received a substantial Build Week extension led in Codex with GPT-5.6-sol: deterministic All, Accepted, and Attended cohort recomposition; an exact three-signal intersection view; the self-contained production dashboard and landscape PDF; a simpler private operator; privacy-minimal, hash-bound PostHog instrumentation; durable protected release storage; clean-clone synthetic acceptance; and public-product documentation.

Codex was used as the primary engineering environment for implementation, red-green tests, browser and PDF QA, privacy review, deployment verification, and adversarial review. GPT-5.6-sol helped make and test the hard product decisions, including separating selection from quality, distinguishing evidence absence from negative evidence, keeping Coresignal out of the current report, and disabling PostHog GeoIP enrichment in addition to IP storage. The live report makes no OpenAI or other enrichment-provider calls at runtime. See [the Build Week submission evidence](docs/BUILD_WEEK_SUBMISSION.md) for the demo outline, session ID, implementation evidence, and exact current limitations.

The initial ingestion and reporting prototype began before the July 13 submission period. The hackathon entry covers the substantial post-start extension listed above, not the earlier prototype. Ready-to-paste form copy, testing instructions, and the video script are in [the Devpost form package](docs/DEVPOST_FORM.md).

## Run the synthetic pipeline

```bash
python3 -m unittest discover -q
python3 -m community_os build --config config/events/example.synthetic.json
python3 -m community_os build --config config/events/example.synthetic.json --pdf
```

Generated databases and reports are written below `output/`, which is ignored by git. PDF export requires an isolated Chromium executable, never a personal browser profile.

Clean-clone acceptance after a verified commit:

```bash
acceptance_root="$(mktemp -d)"
git clone --no-local . "$acceptance_root/start-community-os"
cd "$acceptance_root/start-community-os"
env -u GITHUB_TOKEN -u OPENAI_API_KEY -u CORESIGNAL_API_TOKEN \
  -u POSTHOG_PERSONAL_API_KEY -u POSTHOG_PROJECT_ID \
  -u POSTHOG_PUBLIC_PROJECT_KEY -u VERCEL_PROJECT_ID \
  -u VERCEL_TEAM_SLUG -u VERCEL_TOKEN \
  python3 -m unittest discover -q
env -u GITHUB_TOKEN -u OPENAI_API_KEY -u CORESIGNAL_API_TOKEN \
  -u POSTHOG_PERSONAL_API_KEY -u POSTHOG_PROJECT_ID \
  -u POSTHOG_PUBLIC_PROJECT_KEY -u VERCEL_PROJECT_ID \
  -u VERCEL_TEAM_SLUG -u VERCEL_TOKEN \
  python3 -m community_os build --config config/events/example.synthetic.json
env -u GITHUB_TOKEN -u OPENAI_API_KEY -u CORESIGNAL_API_TOKEN \
  -u POSTHOG_PERSONAL_API_KEY -u POSTHOG_PROJECT_ID \
  -u POSTHOG_PUBLIC_PROJECT_KEY -u VERCEL_PROJECT_ID \
  -u VERCEL_TEAM_SLUG -u VERCEL_TOKEN \
  python3 -m community_os render-partner \
  --contract config/contracts/talent-intelligence-v1.synthetic.json \
  --event-contract config/contracts/talent-report-v3.synthetic.json \
  --html output/synthetic/partner.html \
  --pdf output/synthetic/partner.pdf
```

The tests, demo build, and partner render make no provider calls and use no provider credentials. The `render-partner` PDF step requires `COMMUNITY_OS_CHROMIUM_EXECUTABLE` to point to an isolated Chromium executable; verify the result with `pdfinfo`.

Generate the enriched partner report from validated aggregate contracts and the protected reviewed semantic aggregate:

```bash
python3 -m community_os render-partner \
  --contract "$TALENT_INTELLIGENCE_AGGREGATE" \
  --event-contract "$EVENT_EVIDENCE_AGGREGATE" \
  --semantic-aggregate "$SEMANTIC_AGGREGATE" \
  --html "$PARTNER_HTML" \
  --pdf "$PARTNER_PDF"
```

The semantic aggregate stays protected. The renderer projects only reviewed positive cohort metrics and explicit unknown states. Aggregate counts of evidence types cited by reviewed facts may be shown after cohort-relational privacy suppression; record-level provenance, provider operations, and unlinked source availability stay in private QA. Missing GitHub or professional-profile evidence never becomes a negative talent claim. The report never renders model prose, names, contact details, profile links, or repository links. The first approved partner staging is analytics-free. The separate deployment staging adds a hash-pinned CSP and only five allowlisted PostHog EU interaction events after the operator machine-verifies and binds the PostHog privacy receipt for a project with IP capture disabled.

Build both synthetic talent-intelligence briefs:

```bash
python3 -m community_os.talent_briefs \
  config/contracts/talent-intelligence-v1.synthetic.json \
  output/talent-intelligence \
  --pdf
```

Operational commands:

```bash
# Dry-run retention cleanup, then explicitly apply it.
python3 -m community_os cleanup --database output/example/community.sqlite
python3 -m community_os cleanup --database output/example/community.sqlite --apply

# Export unresolved identity matches without raw source identifiers.
python3 -m community_os review-identities \
  --database output/example/community.sqlite \
  --event-id 1 \
  --output output/example/identity-review.json

# Re-export an existing report.
python3 -m community_os export-pdf report.html report.pdf
```

## When final exports are ingested

1. Keep raw exports outside git.
2. For the protected operator, use first-run setup to generate an `event-release-v1` definition. Treat `config/events/openai-hackathon-2026.json` only as the registered START source profile shape reference, not as a place to add raw source paths or caller-selected hashes. The simpler `config/events/example.synthetic.json` belongs only to the zero-credential demo builder.
3. Run the matching strict adapter. Unknown or drifted columns fail closed; rejected artifact rows are reported separately.
4. Resolve every open identity review before sharing aggregates. Exact normalized email may link automatically. Bilateral applicant-provided GitHub or LinkedIn evidence may link while explicitly recording an email mismatch. Name, team, affiliation, fuzzy, or one-sided evidence never auto-merges.
5. Build the HTML/PDF and inspect the publication thresholds before forwarding it.

If the database contains ghost records, configure each HMAC key version through an environment-variable name in `ghost_identity_key_env`, for example `{"v1":"COMMUNITY_OS_GHOST_KEY_V1"}`. The secret stays out of config and git. Returning ghost identities are quarantined for explicit reactivation and never recreated as new active people.

Semantic classification is implemented but locked by default. It requires an exact approved processor record plus a managed `OPENAI_API_KEY`. The legacy structured classifier is limited to `subject_ref`, `signals`, and `evidence_refs`. The rich path uses four pseudonymized source sections, `application`, `career`, `devpost`, and `projects`, containing only bounded sanitized excerpts, controlled codes, and evidence references. Names, emails, profile or repository URLs, raw provider records, tokens, and raw exports are rejected from the outbound boundary. Provider approval must bind the exact purpose, payload version, field allowlist, reviewed DPA/terms, actual region and retention posture, security profile, and approval time. The accepted postures are EU with verified Zero Data Retention, or global with acknowledged default abuse-monitoring retention of up to 30 days. The built-in transport maps those postures only to `eu.api.openai.com` or `api.openai.com`; arbitrary hosts are rejected. A successful call to the EU route does not by itself prove EU project residency.

## Read in this order
1. `docs/CONCEPT.md`: the idea, decisions made, and Q&A on every design question.
2. `docs/ARCHITECTURE.md`: canonical product, privacy, approval, and deployment boundaries.
3. `docs/OPERATOR_GUIDE.md`: installation, synthetic demo, event operation, providers, retention, and troubleshooting.
4. `docs/DEPLOYMENT.md`: private/public boundaries, supported hosts, analytics, and release procedure.
5. `docs/PLAN.md`: architecture, canonical schema, build order, data-collection wishlist.
6. `docs/research/data-sources.md`: field-level inventory of Luma, Devpost, GitHub API, and optional Coresignal.
7. `docs/taxonomy-v1-review.md`: decisions required before any real-person AI classification.

## License

Copyright 2026 Yauheni Futryn. This code is available under the restrictive [PolyForm Free Trial License 1.0.0](LICENSE.md). It is not MIT-licensed and it is not open source. Commercial or production use requires a separate written license.
