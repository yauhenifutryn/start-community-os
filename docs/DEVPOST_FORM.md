# OpenAI Build Week, ready-to-paste Devpost fields

## General information

**Project name**

START Community OS

**Elevator pitch**

Turn event evidence into privacy-safe partner intelligence without exposing participant records.

## Project story

```markdown
## Inspiration

Community teams collect rich evidence across applications, attendance, project submissions, public repositories, and manual review. After an event, that evidence usually collapses into a few vanity counts or a spreadsheet. Partners cannot see what the community can actually build, while publishing raw participant records would create an unacceptable privacy risk.

START Community OS turns that fragmented evidence into a reviewed, aggregate-only partner report.

## What it does

The private local operator imports registered event exports, rejects schema drift, reconciles identities, records review decisions, and projects only approved evidence into deterministic cohort aggregates. The public artifact contains no participant records.

Partners can compare all applicants, organizer-accepted participants, and confirmed attendees; inspect metric definitions and denominators; explore an exact Founder, Technical, and Shipped-product intersection; and download a fixed landscape PDF. Missing evidence stays unknown, selection is never presented as proof of quality, and small or unsafe slices are suppressed.

The live OpenAI x START Warsaw report covers 286 applicants, 83 accepted participants, and 78 confirmed attendees.

## How we built it

The operator and pipeline use Python and SQLite. The public dashboard is self-contained HTML, CSS, and JavaScript. Headless Chromium composes the PDF. Vercel serves only an exact four-file deployment bundle with restrictive response headers. PostHog EU receives five allowlisted aggregate interaction events with no cookies, persistent identity, profiles, replay, autocapture, URLs, referrers, IP storage, or GeoIP enrichment.

GPT-5.6 is integrated through an approval-gated OpenAI Responses workflow. It can turn bounded, pseudonymized evidence packets into structured proposals for human review. It does not publish prose, make individual decisions, or run from the live public dashboard.

## What was built during OpenAI Build Week

I began the initial ingestion and reporting prototype on July 11, before the July 13 submission period. The project is therefore disclosed as pre-existing. Only the substantial extension completed after the submission period began should be evaluated:

- deterministic All, Accepted, and Attended cohort recomposition;
- the responsive public dashboard and exact three-signal intersection view;
- the composed partner PDF and evidence definitions;
- the simplified private operator and review workflow;
- durable, hash-bound semantic and publication approval records;
- privacy-minimal PostHog instrumentation, including a live fix that removed GeoIP enrichment;
- a sanitized, zero-credential repository with synthetic fixtures, clean-clone acceptance, and deployment separation; and
- the verified Vercel production release.

Codex with GPT-5.6-sol was the primary engineering environment for this extension. It drove red-green tests, architecture and product decisions, desktop and mobile browser QA, PDF inspection, privacy review, adversarial review, and deployment verification. The primary Codex session ID is `019f7482-e669-7963-aabd-9066b0f26989`.

## Challenges

The hardest part was not rendering charts. It was preserving the meaning of the evidence. Accepted participants are not automatically stronger than other applicants. Missing GitHub or professional-profile evidence is not a negative signal. Counts must keep their correct denominators as readers change cohorts. Analytics must measure report interactions without identifying the partner or leaking participant information.

During production verification, fresh PostHog events exposed derived GeoIP fields even though IP storage was disabled. We treated that as a release blocker, added an explicit `$geoip_disable` property, regenerated the hash-bound bundle, and verified new events before sharing the report.

## What we learned

Privacy controls and product usefulness are not opposites. A report becomes more credible when every metric explains its evidence boundary, unknown state, denominator, and suppression rule. Codex was most valuable as a persistent engineering collaborator that could challenge claims, test invariants, and follow a release from code through the live deployment.

## What's next

The next step is to run the same registered workflow for future hackathons, demo days, startup competitions, and accelerator cohorts. Cross-event trends will be added only after at least two compatible reviewed event contracts exist. Optional professional-data enrichment will remain a separate, consented canary rather than a default input.
```

## Built-with tags

Use these tags:

- Python
- SQLite
- HTML5
- CSS
- JavaScript
- OpenAI
- OpenAI Responses API
- GPT-5.6
- Codex
- Vercel
- PostHog
- GitHub Actions
- Chromium

## Try-it-out links

1. **Live aggregate partner report**

   https://start-community-os.vercel.app/openai-hackathon-2026/
2. **Downloadable partner PDF**

   https://start-community-os.vercel.app/openai-hackathon-2026/partner-talent-brief.pdf

The live report is the correct judge-facing product link. It is a real output from the protected workflow, not a fake sample. The private operator is deliberately not exposed on the internet. Judges can test the complete workflow with the synthetic, zero-credential fixture in the repository.

## Project media

Recommended 3:2 images, in this order:

1. Report cover with the 286, 83, and 78 cohort counts.
2. A cohort comparison after switching from All to Accepted or Attended.
3. The exact Founder, Technical, and Shipped-product intersection view.
4. Two representative pages from the landscape PDF.
5. The local operator running synthetic data only, with no real names or protected paths visible.

Use image 1 as the thumbnail. Do not upload screenshots containing participant records, credentials, private operator state, or protected review artifacts.

## Video demo

Target length: 2 minutes 35 seconds. Use an English voiceover. Do not use copyrighted music or expose private participant data.

### Shot list and voiceover

**0:00 to 0:18, live report cover**

> Event communities collect rich applications, attendance, project submissions, and public evidence. But partners usually receive a few vanity counts or a spreadsheet. START Community OS turns that evidence into a privacy-safe, decision-useful partner report.

**0:18 to 0:43, switch All, Accepted, and Attended**

> This is the live report from the OpenAI x START Warsaw Hackathon. It covers 286 applicants, 83 organizer-accepted participants, and 78 confirmed attendees. Every cohort change recomposes the metrics, denominators, ordering, and explanation. Selection is never treated as proof of quality.

**0:43 to 1:05, open one metric definition**

> Every claim shows what evidence supports it and what remains unknown. Missing GitHub or career evidence is not converted into a negative judgment, and unsafe small slices are suppressed rather than exposed.

**1:05 to 1:27, exact intersection view**

> The intersection view shows exact, mutually exclusive combinations of founder, technical, and shipped-product signals. The rows reconcile to the full cohort, so the visualization cannot inflate totals by double-counting people.

**1:27 to 1:46, download and page through the PDF**

> Partners can also download a fixed landscape brief. The HTML is for exploration; the PDF is the forwardable decision document. Both are generated from the same validated aggregate contracts and contain no participant records.

**1:46 to 2:20, repository architecture, tests, and synthetic command**

> I started the initial ingestion and reporting prototype before the submission period. During Build Week, Codex with GPT-5.6-sol drove the substantial production extension: cohort recomposition, the responsive dashboard, the PDF, the private operator, approval-bound releases, clean-clone testing, privacy review, and deployment verification. GPT-5.6 is also integrated through a gated Responses workflow that converts bounded pseudonymized evidence into structured proposals for human review. The public report itself makes no model calls.

**2:20 to 2:35, return to the live cover**

> The result is a repeatable way for communities to prove what their events produce without turning participants into a public database. Next, we will run the same contract across future events and add comparable trends only when the evidence is truly compatible.

## Additional information for judges

**Submitter type**

Choose `Individual` if submitting personally. Choose `Organization` only if Fundacja START Warsaw is the legal entrant and you are authorized to represent it. This choice must match the actual ownership of the submission.

**Country of residence**

Enter your actual legal country of residence. Do not infer this from the event location.

**Category**

Work and Productivity

**Repository URL**

https://github.com/yauhenifutryn/start-community-os

**Judge testing link and instructions**

```text
The production link is the aggregate-only partner report:
https://start-community-os.vercel.app/openai-hackathon-2026/

The private operator is intentionally not internet-exposed because it handles source records and review state. To test the complete workflow safely, clone the repository and run:

python3 -m unittest discover -q
python3 -m community_os build --config config/events/example.synthetic.json

The synthetic path requires no credentials and makes no GitHub, OpenAI, Coresignal, PostHog, or Vercel provider calls. Generated artifacts are written below output/.
```

**Primary Codex session ID**

`019f7482-e669-7963-aabd-9066b0f26989`

**Plugin or developer-tool instructions**

Not applicable. START Community OS is submitted as a Work and Productivity application, not as a plugin or developer tool.

## Final submission checklist

- Repository is visible to judges for the full judging period.
- Repository contains the restrictive source-available license and no participant data or credentials.
- README distinguishes pre-existing work from the Build Week extension.
- Live report and PDF return successfully.
- Public YouTube video is under three minutes and includes English audio covering the product, Codex, and GPT-5.6.
- Thumbnail and gallery images are 3:2 and contain no private state.
- Submitter type, country of residence, and ownership statements are personally verified.
- Final rules acceptance is completed by the submitter.
