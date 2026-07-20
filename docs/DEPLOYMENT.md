# Partner dashboard deployment

START Community OS separates the private event operator from the public partner artifact. Hosting is optional and never part of report generation.

## Private and public boundaries

Keep the operator, SQLite database, source exports, provider payloads, reviewed person facts, approvals, QA, and raw or protected files on the operator's machine. Never copy them into a static host directory.

Only these approved aggregate artifacts may enter public staging:

- `index.html`
- `partner-talent-brief.pdf`
- `publication-manifest.json`

The analytics-free bundle is the canonical content artifact. An optional release-owner action may derive a separate analytics bundle containing the same HTML/PDF claims, a new manifest, and a host security-policy adapter. It does not deploy anything.

## Host matrix

| Host | Base static bundle | Custom response headers | Current analytics adapter | Release position |
|---|---|---|---|---|
| Vercel | Supported | Supported through generated `vercel.json` | Implemented and hash-bound | Current recommendation for an analytics-enabled preview |
| Cloudflare Pages | Supported | Supported through `_headers` | Analytics-free template only | Good static alternative; do not claim analytics parity until a generated hash-bound adapter is added and tested |
| GitHub Pages | Supported for basic files | Not equivalent to Vercel or Cloudflare response headers | None | Static demo only; not the recommended partner release host |
| Codex Sites | Candidate for compatible static projects | Custom response headers are unverified in this repository | Built-in unique visitors and page views; custom PostHog wiring is unverified | Reach-only alternative after a saved, non-deployed compatibility review; every Sites deployment URL is production |

The analytics-free Cloudflare-style template is in `deploy/public/_headers`. The verified analytics transform generates `vercel.json` inside `deployment-staging`. The generated file, not a hand-edited copy, is the deployment input.

## PostHog setup

`.env.example` includes blank PostHog and optional Vercel conventions for operators and future automation adapters. Never commit a real value. A variable being present does not enable analytics. The core CLI does not auto-load `.env.local`; the local deployment and scheduled-review adapters may read it only after their explicit gates pass.

The supported workflow is deliberately explicit:

1. Create or select a PostHog EU project.
2. Disable IP capture in the PostHog project settings.
3. Stage and approve the exact analytics-free partner bundle.
4. Create a short-lived personal API key restricted to this project with only `Project: Read`, then export it as `POSTHOG_PERSONAL_API_KEY` with the numeric `POSTHOG_PROJECT_ID`. Organization-wide access is not required. The public project key remains `POSTHOG_PUBLIC_PROJECT_KEY` or is pasted into the local operator.
5. In the local release-owner operator, choose "Prepare analytics bundle". The operator reads the live EU project settings, verifies `anonymize_ips=true`, verifies that the project returns the same public key, writes a protected hash receipt, and binds that receipt to the analytics approval and deployment manifest. Every capture also sends `$geoip_disable=true`, because disabling IP storage alone does not prevent PostHog from deriving location fields. A checkbox or verbal confirmation is not accepted.
6. Remove or revoke the short-lived settings-verification key after the protected receipt and bundle are prepared. Keep the separate query-only key described below only if scheduled analytics review is required.
7. Verify the generated manifest, `vercel.json`, browser network requests, allowed events, mobile layout, PDF download, and exact artifact hashes before deployment.
8. For read-only day-7 and day-14 reviews, create a separate personal key restricted to this project with only `Query: Read`, then store it as `POSTHOG_PERSONAL_API_KEY` with the numeric `POSTHOG_PROJECT_ID` in ignored local configuration.

Do not run the generic PostHog installation wizard for the static partner bundle. The repository uses a smaller audited capture client, no PostHog SDK, and a hash-bound content security policy. Session replay, autocapture, pageview capture, person profiles, surveys, feature flags, data-warehouse sources, and CRM connections remain off for this release. They add collection surface without answering the approved aggregate questions.

The repository does not auto-enable tracking, create a PostHog project, or deploy a site. A future automation wrapper may read the ignored local values, but it must preserve the same explicit approval, IP-capture confirmation, event allowlist, and hash binding. An authenticated Vercel CLI session is sufficient for deployment; `VERCEL_TOKEN` is only a non-interactive CI fallback.

## Current recommendation

For the current partner release, keep the operator and SQLite data local. Deploy only the exact aggregate bundle. Use Vercel for the first controlled preview because its generated response-header and PostHog adapter is already part of the tested release flow. Keep Cloudflare Pages as the next host adapter. Codex Sites can provide built-in unique visitors and page views for an eligible deployed Site, but use it only for reach analytics unless a saved, non-deployed compatibility review separately verifies this bundle, custom response headers, PDF delivery, and the PostHog interaction contract. GitHub Pages remains a static-demo option.
