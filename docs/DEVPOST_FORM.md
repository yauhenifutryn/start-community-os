# OpenAI Build Week, ready-to-paste Devpost fields

## General information

**Project name**

START Community OS

**Elevator pitch**

Turn event applications, projects, and delivery evidence into a live partner view of who builds, ships, and leads.

## Project story

```markdown
## Inspiration

Community teams collect rich evidence across applications, attendance, project submissions, public repositories, and manual review. After an event, that evidence usually collapses into a few vanity counts or a spreadsheet. Partners still cannot answer the useful questions: who has built beyond an idea, where technical depth appears, which people have founded ventures, and where shipping or customer-delivery evidence exists.

START Community OS turns that fragmented evidence into a reviewed partner intelligence system and a report people can actually use in investment, hiring, and portfolio conversations.

## What it does

The private local operator imports registered event exports, rejects schema drift, reconciles identities, records review decisions, and projects approved evidence into deterministic cohort aggregates. The public artifact contains no participant records.

Partners can compare all applicants, organizer-accepted participants, and confirmed attendees; inspect product maturity, technical capability, founder, shipping, and delivery signals; explore an exact Founder, Technical, and Shipped-product intersection; and download an eight-page landscape brief.

The live OpenAI x START Warsaw report covers 286 applicants, 83 accepted participants, and 78 confirmed attendees.

## How we built it

The operator and pipeline use Python and SQLite. The public dashboard is self-contained HTML, CSS, and JavaScript. Headless Chromium composes the PDF. GitHub stores the exact hash-bound static mirror and Vercel deploys it from `main` with restrictive response headers. PostHog EU receives five allowlisted report-interaction events with no cookies, persistent identity, profiles, replay, autocapture, URLs, referrers, IP storage, or GeoIP enrichment.

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

Codex with GPT-5.6-sol was the primary engineering environment for this extension. It drove red-green tests, architecture and product decisions, desktop and mobile browser QA, PDF inspection, privacy review, adversarial review, and deployment verification. The primary dashboard-build Codex session ID is `019f7482-e669-7963-aabd-9066b0f26989`; deployment verification continued in a later Codex task and is represented by its commits and live checks.

## Challenges

The hardest part was not rendering charts. It was preserving the meaning of the evidence while making the result useful. Accepted participants are not automatically stronger than other applicants. A prototype is not the same as shipped work. Founder history, technical depth, customer validation, and delivery scope overlap, but they should remain inspectable rather than collapse into one synthetic talent score. Counts also need the correct denominator whenever readers change cohorts.

During production verification, fresh PostHog events exposed derived GeoIP fields even though IP storage was disabled. We treated that as a release blocker, added an explicit `$geoip_disable` property, regenerated the hash-bound bundle, and verified new events before sharing the report.

## What we learned

A partner report becomes more credible when each signal keeps its definition, denominator, and evidence boundary. The exact intersection is more useful than a generic ranking because partners can see the combinations that matter for a specific conversation. Codex was most valuable as a persistent engineering collaborator that could challenge claims, test invariants, and follow a release from code through the live deployment.

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

1. Upload `assets/social/devpost-thumbnail.png`, the 3:2 "Founder. Technical. Shipped." card.
2. A cohort comparison after switching from All to Accepted or Attended.
3. The exact Founder, Technical, and Shipped-product intersection view.
4. Two representative pages from the landscape PDF.
5. The report cover with the 286, 83, and 78 cohort counts.

Use image 1 as the thumbnail. Do not upload screenshots containing participant records, credentials, private operator state, or protected review artifacts.

## Video demo

Target length: 2 minutes 39 seconds. Use an English AI-generated voiceover and disclose that fact in the YouTube description. Do not use copyrighted music or expose private participant data.

### Shot list and voiceover

**0:00 to 0:14, live report cover**

> Event teams collect applications, project submissions, GitHub work, and attendance, then reduce it all to a spreadsheet. START Community OS turns that evidence into a partner view of what members have built, how deeply, and where they have shipped.

**0:14 to 0:36, live dashboard on All applicants**

> This is the live OpenAI x START Warsaw report: 286 applicants, 83 accepted participants, 78 attendees, and 20 of 20 final teams submitted a project. It surfaces 187 people with prototype-or-beyond evidence, 150 with substantive technical depth, and 123 with data and AI engineering evidence.

**0:36 to 0:58, switch cohorts and inspect Shipped products**

> Switching cohorts recalculates each value, share, denominator, definition, and comparison. Selecting "Shipped products" reveals its definition and the same signal across all three cohorts. Partners can inspect product evidence, technical capability, and delivery without collapsing them into one opaque talent score.

**0:58 to 1:15, exact intersection view**

> Here is the distinctive view: an exact application-evidence intersection of founder, technical, and shipped-product signals. Eighteen applicants show all three, and every person appears once, so the combinations cannot double-count people.

**1:15 to 1:25, download and page through the PDF**

> The same approved evidence also produces this eight-page landscape PDF, ready to forward into a partner meeting.

**1:25 to 1:56, GPT-5.6 product role**

> GPT-5.6 has one specific product job. It evaluates bounded evidence from applications, Devpost, and public projects, then returns a strict structured proposal for product maturity, technical depth, execution scope, originality, validation, capabilities, and domain. A human reviews the proposal; deterministic code aggregates approved results into the report. The public page makes no model calls.

**1:56 to 2:29, Codex engineering evidence**

> Codex with GPT-5.6-sol was my primary engineering environment for the Build Week extension. I used red-green tests, interaction checks, PDF inspection, independent count re-derivation, fresh-context review, and production verification. The key decisions were to separate selection from quality and keep maturity, technical depth, founder history, and delivery inspectable instead of merging them into a synthetic ranking. A live analytics check even exposed derived GeoIP fields; we blocked release, added the disable flag, and verified the fix before deployment.

**2:29 to 2:39, closing card**

> START Community OS replaces static event recaps with reusable evidence infrastructure. Next, we will apply the same contract to a new event and build comparable trends across communities.

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
