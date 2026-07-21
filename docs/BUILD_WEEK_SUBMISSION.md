# Community OS, Build Week evidence pack

## Submission fields

- Project: Community OS
- Elevator pitch: Turn community event exports into measurable KPIs and partner-ready evidence with one reusable, reviewed pipeline.
- Category: Work and Productivity
- Live report: https://start-community-os.vercel.app/openai-hackathon-2026/
- PDF: https://start-community-os.vercel.app/openai-hackathon-2026/partner-talent-brief.pdf
- Public repository: https://github.com/yauhenifutryn/start-community-os
- Licence: PolyForm Free Trial License 1.0.0, source-available and not open source
- Demo video: public YouTube link included in the submitted Devpost entry
- Primary Codex `/feedback` Session ID: `019f7482-e669-7963-aabd-9066b0f26989`

## What Community OS does

Community OS is reusable event-intelligence infrastructure developed by Yauheni Futryn for use in communities including START Warsaw. A private local operator turns supported Luma and Devpost exports into reviewed evidence and deterministic cohort KPIs. The same approved aggregate contract renders an interactive partner report and fixed PDF.

The live OpenAI x START Warsaw release is one verified output. It covers 286 applicants, 83 accepted participants, 78 confirmed attendees, and 20 of 20 final teams with a project submission. Partners can switch cohorts, inspect each metric's definition and denominator, and examine combinations such as the exact Founder, Technical, and Shipped-product intersection.

For another supported hackathon, the organiser changes the event metadata and selects the new exports. The adapters, evidence taxonomy, review gates, aggregate contracts, and renderers stay in place. No per-event model fine-tuning is required. A new platform or export shape still needs a registered adapter and synthetic fixture. A substantially different event format may need a new report profile.

The public report contains aggregate results. Source records, identity reconciliation, enrichment state, and review decisions stay in the private operator.

## What changed during Build Week

The first ingestion and reporting prototype began on July 11, before the July 13 submission period. The eligible Build Week work is the substantial extension completed after the period opened:

- reusable registered adapters, strict schema checks, and a zero-credential synthetic acceptance path;
- deterministic All, Accepted, and Attended cohort recomposition with explicit unknown states;
- a simplified local operator for ingestion, review, approval, preview, and export;
- durable semantic and publication approvals bound to exact artefact hashes;
- the responsive public report, exact three-signal intersection, and eight-page PDF;
- five allowlisted aggregate analytics events, including a verified fix that disables GeoIP enrichment;
- a sanitised public repository and GitHub-to-Vercel release path.

Commit history and the Codex session record distinguish this extension from the pre-existing prototype.

## Codex and GPT-5.6

Codex with GPT-5.6-sol was the main engineering environment for the Build Week extension. It was used for red-green tests, implementation, interface work, desktop and mobile checks, PDF inspection, independent count rederivation, scoped review, and production verification. It did not produce the report as a one-time artefact. The work focused on the reusable pipeline and the controls needed to run it again.

GPT-5.6 has a bounded role inside the product. It converts approved pseudonymous evidence packets into strict structured proposals for human review. It does not rank participants, approve its own output, calculate final metrics, or run from the public dashboard. Deterministic code builds the aggregate contract after review.

## Testing instructions

```text
git clone https://github.com/yauhenifutryn/start-community-os.git
cd start-community-os
python3 -m unittest discover -q
python3 -m community_os build --config config/events/example.synthetic.json
```

The synthetic workflow requires no credentials and makes no provider calls. It writes generated artefacts below `output/`. Judges can also inspect the production report at https://start-community-os.vercel.app/openai-hackathon-2026/.

Fresh public-clone verification completed on July 21, 2026: 1,166 tests passed with 2 expected skips, and the zero-credential synthetic build completed successfully.

## Demo video outline

Target 2:59. Use a public YouTube video with English audio. The final narration uses OpenAI `gpt-4o-mini-tts` with the `marin` voice. The end card and YouTube description disclose that it is AI-generated narration.

1. 0:00 to 0:15: show the fragmented event inputs and state the partner reporting problem.
2. 0:15 to 0:32: establish Community OS as the reusable reconcile, enrich, review, and publish system.
3. 0:32 to 0:54: show conservative identity reconciliation and the explicit review path for ambiguous matches.
4. 0:54 to 1:22: show bounded GitHub evidence, the separately gated LinkedIn path with zero current data, the identity-filtered GPT-5.6 packet, storage off, and human review.
5. 1:22 to 1:48: drive real All, Accepted, and Attended states in the live OpenAI x START Warsaw report.
6. 1:48 to 2:11: show the real 18-person exact intersection and the verified eight-page PDF.
7. 2:11 to 2:29: explain config-driven reuse and the honest new-adapter boundary.
8. 2:29 to 2:51: show Codex evidence from red-green tests to production verification, including the GeoIP stop-and-fix and GitHub-to-Vercel path.
9. 2:51 to 2:59: close on the product purpose and AI-voice disclosure.

Do not record real participant rows, protected operator state, credentials, or provider responses. Use synthetic evidence when demonstrating the private workflow.

## Official sources

- [OpenAI Build Week official rules](https://openai.devpost.com/rules)
- [OpenAI Build Week FAQ](https://openai.devpost.com/details/faqs)
- [Submission update confirming AI-assisted voiceover](https://openai.devpost.com/updates/45282-openai-build-week-submissions-are-open-plugin-launch)
