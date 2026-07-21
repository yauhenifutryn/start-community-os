# Community OS

Community OS is a reusable event-intelligence pipeline. It turns applications, attendance, project submissions, and public project evidence into measurable cohort statistics and partner reports.

It imports registered event exports, reconciles records, supports controlled enrichment and human review, then generates deterministic aggregate contracts for an interactive dashboard and a fixed PDF. The OpenAI Hackathon report below is one event-specific use case, not the product itself.

## Live example

- [Open the START Warsaw x OpenAI report](https://start-community-os.vercel.app/openai-hackathon-2026/)
- [Download the eight-page partner brief](https://start-community-os.vercel.app/openai-hackathon-2026/partner-talent-brief.pdf)

The live report covers 286 applicants, 83 accepted participants, and 78 confirmed attendees. Partners can compare those cohorts, inspect product and technical evidence, and explore the founder, technical, and shipped-product signals in one three-signal exact UpSet-style partition. It does not reduce people to one talent score.

## How the pipeline works

1. An operator selects a registered event profile and imports the matching exports.
2. Strict adapters validate the source schemas and reject drifted columns.
3. The system reconciles identities and holds ambiguous links for review.
4. Approved GitHub and optional LinkedIn/Coresignal stages collect bounded project and professional evidence. OpenAI has a separate gate and receives only sanitized pseudonymous excerpts, controlled codes, and evidence references.
5. A human reviews the proposals. Deterministic code builds the All, Accepted, and Attended aggregates.
6. The same approved facts generate the HTML dashboard and landscape PDF.
7. Publication approval binds the exact event, report, PDF, and release hashes before anything is staged for hosting.

Completed stages are resumable, so a failed later step does not repeat finished provider work.

### Supported events

Hackathons using the registered Luma and Devpost export profiles are supported today. The product does not train a model for each event. Another event with the same export shapes needs new metadata and workbook sheet selections, not model fine-tuning or a rewritten pipeline.

A different platform or export schema still needs a new registered adapter and synthetic fixture. Non-hackathon formats may also need a new report profile. Those are engineering changes, not settings we pretend are already supported.

The first-run operator expands the registered START source profile in `config/events/openai-hackathon-2026.json` into a strict `event-release-v1` definition. Adapter IDs and mapping hashes stay server-owned.

## Run it locally

Clone the repository, run the tests, then run the credential-free ingestion and rendering smoke test:

```bash
git clone https://github.com/yauhenifutryn/start-community-os.git
cd start-community-os
python3 -m unittest discover -q
python3 -m community_os build --config config/events/example.synthetic.json
```

`build` checks the basic source-adapter, ingestion, database, and demo-rendering path. It is a smoke test, not the partner report. Render the checked-in synthetic partner contracts with:

```bash
python3 -m community_os render-partner \
  --contract config/contracts/talent-intelligence-v1.synthetic.json \
  --event-contract config/contracts/talent-report-v3.synthetic.json \
  --html output/synthetic/partner.html
```

Both commands write below `output/`, which Git ignores. They make no provider calls. Add `--pdf output/synthetic/partner.pdf` only after setting `COMMUNITY_OS_CHROMIUM_EXECUTABLE` to an isolated Chromium executable.

For local operator or provider work, copy the blank template to ignored `.env.local`, fill only what the run needs, then export it explicitly:

```bash
cp .env.example .env.local
set -a
. ./.env.local
set +a
```

The CLI does not auto-load `.env.local`. For a protected event run, follow [the operator guide](docs/OPERATOR_GUIDE.md) and use a durable private path outside the repository and system temporary directories.

<details>
<summary>Clean-clone acceptance</summary>

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
  --html output/synthetic/partner.html
```

The acceptance run must succeed without provider or deployment credentials.

</details>

## How GPT-5.6 and Codex were used

GPT-5.6 has one bounded runtime role. After explicit approval, it evaluates sanitized pseudonymous evidence from applications, career context, Devpost, and public projects, then returns a schema-constrained proposal. It does not receive an entire GitHub profile or source tree. Names, emails, profile and repository URLs, raw provider records, and tokens are rejected at the outbound boundary. A human reviews the proposal before deterministic code can include approved facts in aggregate contracts. The public dashboard makes no model calls.

Codex with GPT-5.6-sol was the main engineering environment for the Build Week extension. It was used to implement and test four product decisions that now live in code: keep organizer selection separate from demonstrated evidence, preserve missing evidence as unknown, require hash-bound human approval before semantic results can enter a partner release, and deploy only the verified static bundle rather than the protected operator. Codex also drove browser and PDF checks, count re-derivation, security review, and deployment verification. It is part of how the product was built, not a runtime dependency that generates reports on demand.

## Data and release boundary

Raw exports, normalized records, provider responses, review state, credentials, and approval receipts stay in the protected operator. They are not part of the hosted site or this public repository.

The public report contains aggregate values and definitions. It does not include participant names, contact details, profile links, repository links, or model-written prose. Coresignal contributed no data to the live report. The hosted page records only five allowlisted report interactions and uses no cookies, persistent identity, profiles, replay, URLs, referrers, IP storage, or GeoIP enrichment. Before analytics staging, the operator machine-verifies and binds the PostHog privacy receipt.

See [the architecture](docs/ARCHITECTURE.md) for the full trust and release boundaries.

## Build Week reuse disclosure

The first ingestion and reporting prototype began on 11 July 2026, before the OpenAI Build Week submission period opened on 13 July. It was not built from zero during the competition.

The project is submitted in the Work and Productivity category. The Build Week entry covers the substantial work completed after the period opened: the reusable protected release operator, reviewed semantic workflow and approval records, deterministic cohort recomposition, exact three-signal intersection, production dashboard and PDF, analytics controls, and verified GitHub-to-Vercel release.

The implementation evidence and primary Codex session ID are in [the Build Week submission notes](docs/BUILD_WEEK_SUBMISSION.md).

## License

Copyright 2026 Yauheni Futryn.

The Community OS software is source-available under the [PolyForm Free Trial License 1.0.0](LICENSE.md). It is not MIT-licensed or open source. The license permits evaluation for fewer than 32 consecutive calendar days. Redistribution, production use, continued evaluation, or commercial use outside that permission requires a separate written license from the copyright holder. Original documentation and media are copyright Yauheni Futryn and all rights are reserved unless a file states otherwise.

START Warsaw and OpenAI names and marks appear only in the event-specific example. They remain the property of their respective owners and are not licensed under PolyForm. See [NOTICE.md](NOTICE.md).
