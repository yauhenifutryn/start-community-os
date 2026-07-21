# OpenAI Build Week, ready-to-paste Devpost fields

## General info

### Project name

Community OS

### Elevator pitch

Turn community event exports into measurable KPIs and partner-ready evidence with one reusable, reviewed pipeline.

## Project details

### About the project

```markdown
## Why I built it

Community events collect useful evidence in applications, attendance exports, project submissions, public repositories, and organiser review. After the event, most of it ends up in a spreadsheet. Partners get a headcount, but not a clear picture of what the community can build and deliver.

Community OS turns supported event exports into measurable KPIs, reviewed evidence, and a partner-ready report. I developed the product for use in communities including START Warsaw; the live OpenAI x START Warsaw report is one verified output of that system.

## How it works

The local operator imports registered Luma and Devpost export shapes, rejects schema drift, reconciles identities, and sends ambiguous matches to review. Optional enrichment uses bounded pseudonymous evidence packets. GPT-5.6 returns a strict structured proposal, a human accepts or corrects it, and deterministic code calculates cohort metrics. The approved aggregate contract then renders the interactive HTML report and an eight-page PDF.

This workflow is reusable. For another supported Luma and Devpost hackathon, an organiser changes the event metadata and selects the new exports. The adapters, evidence taxonomy, review gates, aggregate contracts, and renderers stay the same. No event-specific model fine-tuning is required. A new platform or export schema still needs a registered adapter and synthetic fixture, and a different event format may need a new report profile.

## Live proof

The current report covers 286 applicants, 83 accepted participants, and 78 confirmed attendees. Partners can switch cohorts, inspect the definition and denominator behind every KPI, compare product and technical signals, and examine the exact Founder, Technical, and Shipped-product intersection. Twenty of twenty final teams submitted a project.

The public report contains aggregate results. The private operator remains local because it handles source records and review state. Judges can run the full workflow with the repository's synthetic fixture and no provider credentials.

## What I built during Build Week

I started the first ingestion and reporting prototype on July 11, two days before the July 13 submission period. This is a disclosed extension of that project. During Build Week I built the reusable reviewed pipeline and its production release: strict adapters and synthetic acceptance data, deterministic All, Accepted, and Attended recomposition, a simpler private operator, durable approval and publication records, the live responsive report and PDF, privacy-minimal product analytics, and the GitHub-to-Vercel release path.

Codex with GPT-5.6-sol was my main engineering environment for this extension. I used it to turn product decisions into failing tests, implement the pipeline and interface, rederive the headline counts, inspect the PDF and desktop/mobile states, review privacy boundaries, and verify the production release. One live analytics check found derived GeoIP fields. I stopped the release, added the explicit disable property, and verified fresh events before sharing the report.

GPT-5.6 also has a bounded role inside the product. It proposes structured classifications from approved evidence. It does not publish the report, rank people, or run from the public page. Human review controls the evidence; deterministic code controls the numbers.

## What I learned

The hard part was not drawing charts. It was keeping every number tied to a definition, denominator, and reviewed source. Selection is not proof of quality, missing evidence is not a negative judgement, and useful talent signals should stay inspectable instead of being compressed into one score.

Next I want to run the same contract on another compatible event. Cross-event trends will wait until two real event runs use comparable reviewed definitions.
```

### Built with

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

### Try it out

1. Live partner report: https://start-community-os.vercel.app/openai-hackathon-2026/
2. Downloadable partner PDF: https://start-community-os.vercel.app/openai-hackathon-2026/partner-talent-brief.pdf

Use the live report as the main judge-facing link. It is a production output of the pipeline, not a mock. The repository provides the safe end-to-end test path.

### Project media

Upload these in order:

1. `assets/social/devpost-thumbnail.png` as the 3:2 thumbnail.
2. The report overview with the 286, 83, and 78 cohort counts.
3. A cohort comparison after switching to Accepted or Attended.
4. The exact Founder, Technical, and Shipped-product intersection.
5. Representative pages from the PDF.

Do not upload private operator screens, participant records, credentials, or protected review artefacts.

### Video demo link

The public YouTube demo link is included in the submitted Devpost entry.

The final video is 2:59, landscape, and in English. It uses OpenAI `gpt-4o-mini-tts` with the `marin` voice, no music, and no designed sound effects. The end card and YouTube description disclose: "AI-generated narration: OpenAI Speech API. Not a human voice recording." Third-party event marks appear only to identify the documented event use case.

#### Video plan and narration

**0:00 to 0:15, the problem**

Show four event evidence sources resolving into the missing partner KPI.

> Communities already collect applications, attendance, submissions, and project evidence. The hard part is connecting those exports into credible KPIs a partner can trust, and a case for funding the next event.

**0:15 to 0:32, the system, not one report**

Animate the reconcile, enrich, review, and publish value chain.

> Community OS turns that evidence into a repeatable system: reconcile the people, enrich the signal, review the model proposals, then publish consistent dashboards and briefs. The report is one verified output, not the product itself.

**0:32 to 0:54, conservative identity reconciliation**

Compare the exact-identifier join path with the explicit review path for ambiguous evidence.

> First, records are reconciled conservatively. Exact normalized emails, or matching applicant-provided GitHub and LinkedIn identifiers, can join a record. Weaker matches by name, team, affiliation, or a one-sided profile are held for review instead of being silently merged.

**0:54 to 1:22, enrichment and privacy boundary**

Show bounded GitHub evidence, the inactive LinkedIn gate, identity filtering, the schema-constrained packet, storage off, and human review.

> With approval, GitHub adds bounded public project evidence. LinkedIn enrichment is separately gated and contributed zero data here. Before GPT-5.6, the pipeline strips identity and contact data, links, secrets, and repository paths. The model receives privacy-minimized, schema-constrained evidence with storage off. A human reviews every proposal.

**1:22 to 1:48, live cohort intelligence**

Drive the verified All, Accepted, and Attended states in the production report.

> This live OpenAI X START Warsaw report starts with 286 applicants, 83 accepted participants, and 78 confirmed attendees. Switch the cohort and every count, denominator, and comparison recomposes under the same metric definition. Partners can inspect what people built, technical depth, founder evidence, customer delivery, and where the community can contribute.

**1:48 to 2:11, exact intersection and PDF**

Show the real clicked 18-person intersection, then the verified eight-page PDF.

> Cross-referencing goes beyond totals. One view partitions every applicant into eight mutually exclusive Founder, Technical, and Shipped combinations. Eighteen sit in the full intersection, and all eight rows reconcile to 286. The same approved KPI contract then produces an eight-page partner brief.

**2:11 to 2:29, reusable with an honest boundary**

Compare the event metadata and exports that change with the adapters, taxonomy, review gates, and renderers that stay fixed.

> For another supported hackathon, the operator changes event metadata and selects new exports while the registered adapters, taxonomy, review gates, and renderers stay in place. A new platform or schema still needs an explicit adapter, mapping, and synthetic test.

**2:29 to 2:51, traceable engineering chain**

Show verified red-green tests, browser and PDF checks, the GeoIP stop-and-fix, GitHub history, and Vercel.

> Codex with GPT-5.6-sol extended the system through red-green tests, browser and PDF checks, and production verification. When live verification found derived GeoIP still present, publication stopped until the payload and regression test were fixed. The public GitHub history and Vercel route close the trace.

**2:51 to 2:59, close**

Hold the Community OS wordmark and the AI-voice disclosure.

> Community OS: private evidence in, credible partner intelligence out. Make the next event measurable.

## Additional info for judges and organisers

### Submitter type

Choose `Individual` if you are submitting personally. Choose `Organization` only if Fundacja START Warsaw is the legal entrant and you are authorised to represent it.

### Country of residence

Enter your actual legal country of residence.

### Category

Work and Productivity

This is the closest fit because Community OS is an analytics and reporting workflow for community operators and their partners.

### Code repository

https://github.com/yauhenifutryn/start-community-os

The repository is public and source-available under the PolyForm Free Trial License 1.0.0. It is not MIT-licensed or open source. The licence permits evaluation for fewer than 32 consecutive days; production, redistribution, continued evaluation, or commercial use outside that permission requires a separate written licence.

### Judge testing link and instructions

```text
Production report:
https://start-community-os.vercel.app/openai-hackathon-2026/

The private operator is intentionally not internet-exposed because it handles source records and review state. To test the complete workflow safely:

git clone https://github.com/yauhenifutryn/start-community-os.git
cd start-community-os
python3 -m unittest discover -q
python3 -m community_os build --config config/events/example.synthetic.json

The synthetic path needs no credentials and makes no GitHub, OpenAI, Coresignal, PostHog, or Vercel provider calls. Generated artefacts are written below output/.
```

### Primary Codex `/feedback` Session ID

`019f7482-e669-7963-aabd-9066b0f26989`

This is the `/feedback` Session ID used in the submitted Devpost entry.

### Plugin or developer-tool instructions

Not applicable. Community OS is a Work and Productivity application, not a plugin or developer tool.

## Official requirements checked

- [Official rules](https://openai.devpost.com/rules)
- [FAQ](https://openai.devpost.com/details/faqs)
- [Submission update confirming AI-assisted voiceover](https://openai.devpost.com/updates/45282-openai-build-week-submissions-are-open-plugin-launch)
