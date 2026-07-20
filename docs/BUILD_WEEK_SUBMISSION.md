# START Community OS, OpenAI Build Week submission

## Submission fields

- Project: START Community OS
- Tagline: Turn event evidence into a privacy-safe, decision-useful partner brief without exposing participant records.
- Track: Work and Productivity
- Live dashboard: https://start-community-os.vercel.app/openai-hackathon-2026/
- Downloadable PDF: https://start-community-os.vercel.app/openai-hackathon-2026/partner-talent-brief.pdf
- Public repository: add the final GitHub URL after repository creation
- Public demo video: add the final YouTube URL after upload
- Primary Codex session ID: `019f7482-e669-7963-aabd-9066b0f26989`

## What START Community OS does

Event teams collect applications, attendance exports, project submissions, GitHub evidence, and manual review notes, but partner reporting usually collapses that evidence into a few vanity counts or a spreadsheet. START Community OS turns registered exports into one local reviewed evidence workflow, deterministic cohort aggregates, an interactive partner dashboard, and a fixed landscape PDF.

The private operator owns uploads, reconciliation, review, provider gates, preview, approvals, exports, and retention. The public artifact contains aggregate statistics only. Partners can compare all 286 applicants, 83 organizer-selected participants, and 78 confirmed attendees; inspect metric definitions and denominators; and explore an exact Founder, Technical, and Shipped-product intersection without browsing people. Selection is never presented as proof of quality, and missing evidence is never treated as a negative judgment.

The current release uses reviewed application, public-project, and event-submission evidence already collected for the event. Coresignal contributes zero because its retained trial sample was partial, internal-only, and not release-eligible. Gender, age, nationality, location, graduation year, and post-event outcomes are omitted because they were unavailable or unreviewed and were not inferred.

## What changed during Build Week

The underlying local event pipeline existed before the July 13 submission period. During Build Week, Codex with GPT-5.6-sol led a substantial production extension:

1. Added deterministic, privacy-thresholded semantic aggregates for All, Accepted, and Attended cohorts.
2. Rebuilt the public artifact as a self-contained responsive dashboard with keyboard cohort navigation, evidence disclosures, and an exact three-signal intersection visualization.
3. Rebalanced the partner PDF into a seven-page decision document with larger type, consistent visual rules, and a dedicated interpretation page.
4. Simplified the local private operator around upload, review, approved runs, preview, approval, analytics preparation, and export.
5. Added durable protected release storage and an explicit guard against using temporary directories for approval evidence.
6. Added privacy-minimal PostHog capture for five aggregate interactions only. It uses no cookies, persistent identity, profiles, replay, autocapture, participant data, URLs, or referrers; it disables both IP storage and GeoIP enrichment.
7. Productized the repository with synthetic fixtures, blank credential templates, provider gates, architecture and operator documentation, deployment separation, retention guidance, and a zero-credential clean-clone acceptance path.
8. Deployed a hash-verified Vercel production route and scheduled aggregate-only day-7 and day-14 analytics reviews.

Codex was not used as a one-shot code generator. It maintained one long-running implementation goal, wrote failing tests before behavior changes, rederived headline counts independently, drove desktop and mobile browser QA, rendered and inspected the PDF, coordinated bounded fresh-context reviews, caught a real PostHog GeoIP privacy problem during live verification, and fixed it before partner distribution.

## How it works

1. A local operator selects a registered event profile and imports supported exports.
2. Strict adapters reject schema drift and preserve source provenance in protected state.
3. Identity reconciliation and review resolve ambiguous links before aggregation.
4. Optional GitHub or OpenAI enrichment runs only behind separate, exact approval gates. Coresignal is optional and excluded from this release.
5. Reviewed facts project into deterministic cohort aggregates with privacy thresholds and explicit unknown states.
6. The HTML and PDF consume validated aggregate contracts, never raw participant records.
7. Publication approval binds the event, HTML, PDF, and artifact-set hashes.
8. An optional separate transform adds the audited PostHog client and Vercel security headers without changing report claims.

## Built with

- Python 3 standard library and SQLite for the local operator and deterministic pipeline
- Self-contained HTML, CSS, and JavaScript for the public dashboard
- Headless Chromium for PDF composition
- Vercel static hosting and response headers
- PostHog EU for five privacy-minimal aggregate interaction events
- Codex with GPT-5.6-sol for implementation, testing, design iteration, verification, and deployment
- Optional OpenAI Responses API, GitHub, and Coresignal adapters behind explicit local gates; none makes a runtime call from the live partner dashboard

## Validation evidence

- Current report counts: 286 applicants, 83 accepted participants, 78 confirmed attendees
- Operational event facts: 20 of 20 teams submitted; 76 of 78 on-site identities linked to submitted teams; 2 unmatched
- Reviewed semantic source coverage: application 270, public projects 172, event submissions 61, dedicated career-provider context 0
- Whole-person unresolved: 18 of 286, comprising 14 no-evidence and 4 conflict states; excluded from positive claims
- Coresignal contribution to the current partner release: 0
- Production report and PDF return HTTP 200 with exact approved bytes and restrictive response headers
- Fresh production PostHog events contain `$geoip_disable=true` and no derived GeoIP properties
- The full test suite and clean-clone synthetic acceptance are rerun before final submission

The value `event submissions 61` means submission evidence was cited in 61 reviewed semantic facts. It is not attendance or team-submission completion. The value `public projects 172` means public-project evidence was used in 172 reviewed facts. It is not a quality judgment about the remainder.

## Demo video outline

Target duration: 2 minutes 30 seconds, landscape, English voiceover.

1. 0:00 to 0:18, problem and promise. Show the live cover and explain that communities have rich evidence but weak partner reporting.
2. 0:18 to 0:42, private workflow. Show the local operator using synthetic data only, from upload through reviewed aggregate and approval.
3. 0:42 to 1:18, live dashboard. Switch All, Accepted, and Attended; open one evidence definition; show that denominator and unknown-state explanations move with the cohort.
4. 1:18 to 1:43, intersections. Show the Founder, Technical, and Shipped-product exact partition and explain that the rows are mutually exclusive and sum to all 286 applicants.
5. 1:43 to 2:03, partner delivery. Download the PDF and show two decision pages plus the final definitions page.
6. 2:03 to 2:22, Codex and GPT-5.6-sol. Show the test, browser-QA, privacy-gate, and deployment workflow; mention the live discovery and removal of PostHog GeoIP enrichment.
7. 2:22 to 2:30, close. Return to the live report and explain the next step: repeat the same contract for future events, then add harmonized cross-event trends.

The voiceover must explicitly say that Codex with GPT-5.6-sol drove the Build Week extension and that the public dashboard is aggregate-only. Do not show the real private operator state, raw exports, participant names, credentials, or protected review artifacts in the recording.

## What comes next

- Reuse the registered event workflow for future hackathons, demo days, startup competitions, and accelerator cohorts.
- Collect consented structured fields that partners actually request, especially role stage, location at a suitable level, graduation year, work authorization, collaboration intent, and post-event outcomes.
- Add a new adapter and synthetic fixture for every new export schema rather than accepting loose CSVs.
- Add cross-event trends only after at least two compatible reviewed event contracts exist.
- Evaluate Coresignal only as a consented targeted canary measuring marginal information over applications and GitHub before broader spend.
