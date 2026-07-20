# Implementation Plan: Slice 1, Hackathon Talent Data Room

Status: superseded by the Talent Data Room Studio implementation checkpoint on 2026-07-12. The final Luma, track-preference, and two-sheet Devpost exports have been received and inspected. Coresignal and AI enrichment remain disabled.

## Architecture (approach A, decided)

Local pipeline plus a local browser operator. Everything remains repeatable; the normal workflow is dropping the three exports into explicit slots, reviewing validation and identity exceptions, then generating HTML and PDF.

```
inputs/                      canonical store                 outputs/
  luma/*.csv        ->  [ingest] -> [normalize] ->  SQLite   -> [render] -> dataroom-<event>.html
  devpost/*.csv                        |            (append-                dataroom-combined.html
  custom/*.csv|json                [enrich]          only,
                                   [classify]        event-
                                   [anonymize]       scoped)
```

### Pipeline stages
1. **Ingest.** Read raw exports. Per-source adapter with a config-driven field mapping (YAML/JSON mapping file per source, so a changed export format is a mapping edit, not code).
2. **Normalize.** Map into the canonical schema; dedupe people across events and platforms (email primary key, GitHub/LinkedIn URL secondary; fuzzy name match only as a flagged suggestion, never automatic).
3. **Enrich.** For each person with provided URLs: GitHub API (repos, stars, languages, activity; 1 GraphQL + N REST calls per person, budget against 5,000/hr), Coresignal collect (employment, education years). Store raw enrichment snapshots with timestamps; 12-month retention cap on raw enriched records (Kaspr precedent).
4. **Classify.** LLM classification into the FIXED taxonomy (versioned): occupation category, builder-signal tier, standout facts. Low-confidence rows go to a manual review file. Estimated age band computed from education years; individual-level values internal-only.
5. **Anonymize.** Aggregation with pipeline-enforced rules: k>=5 on every published cell including cross-tabs, complementary suppression, differencing check vs previously published reports, highlight facts only with consent flag set.
6. **Render.** Self-contained HTML data room from a template (mock at `mock/talent-data-room-mock.html` is the design reference): per-event and combined variants, PostHog EU snippet with `persistence:'memory'`, autocapture off, partner+event stamped at generation time.

### Canonical schema (first sketch, finalize against real exports)
- `person`: id, email(s), name, github_url, linkedin_url, consent flags (aggregate_stats, enrichment, highlight_fact), created/updated.
- `event`: id, name, date, platform(s), type (hackathon/meetup/recruitment).
- `application`: person_id, event_id, source (luma/devpost/custom), raw answers (JSON), status (applied/accepted/declined/waitlist), timestamps.
- `participation`: person_id, event_id, checked_in, team_id, submission_id.
- `submission`: event_id, team_id, title, built_with tags, links, judging scores.
- `enrichment_snapshot`: person_id, source (github/coresignal), payload JSON, fetched_at.
- `classification`: person_id, event_id, taxonomy_version, occupation, signal_tier, facts JSON, confidence, reviewed_by.

Partner follow-up and downstream outcome collection are not part of this report. The current artifact uses only START-owned registration, attendance, team, track, submission, project, and artifact-completeness evidence.

## Build order (next week)
1. **Day 0, data in hand:** get real Luma + Devpost exports from the completed hackathon. Verify actual columns against docs/research/data-sources.md (several Devpost fields are UNVERIFIED). Verify Luma `guests/list` JSON against the public OpenAPI spec if API access exists.
2. **Taxonomy workshop (team, 1 hour):** fix occupation categories, the "impressive" rubric, signal tiers. Version it as `taxonomy-v1`.
3. **Ingest + normalize** for the two real sources; canonical SQLite store; dedupe report.
4. **Classify + aggregate** with the anonymization rules; eyeball outputs against raw data (spot-check 10 people manually).
5. **Render** the real data room from the (iterated) mock template. PostHog wiring last.
6. **Enrichment** (GitHub first, Coresignal behind a flag) only after 1-5 works end to end; it is additive, not blocking. Before first Coresignal run: Art. 14 notice text ready, DPIA one-pager written, consent checkboxes live on future forms.
7. **Compliance artifacts** (parallel, mostly writing): privacy notice update, one-page LIA, Art. 14 notice email text, consent checkbox copy (drafts in docs/research/gdpr-privacy-and-sponsors.md).

Definition of done for slice 1: a single render command produces a data room from raw exports with zero manual editing, and the anonymization rules are enforced in code (the renderer refuses sub-threshold cells).

## Ideal data collection wishlist (add to every future form)
From the gaps analysis (docs/research/data-sources.md):
1. **GitHub username + LinkedIn URL** (Luma has a native social-profile question type). Kills the entity-resolution problem at the source. Highest priority.
2. **Consent lines**: aggregate-stats transparency line + enrichment checkbox (drafts ready).
3. **Occupation category** as a fixed dropdown matching taxonomy-v1.
4. **"Most impressive thing you've built"** open text (the LLM's best signal source).
5. **Current or expected graduation year** (replaces age inference for students).
6. **"Looking for a team?"** flag (Luma lacks it; Devpost has it).
7. Optional post-event feedback belongs to a later program workflow and is not required for this data room.

## Later slices (unchanged from CONCEPT.md)
- Slice 2: hardened unification layer (new sources = mapping files).
- Slice 3 (October): internal member layer; person-linked living profiles (LLM-wiki), recruitment funnel, update pipeline.
- Slice 4: voice-agent applicant screener feeding the same schema.
- Phase 3+: hosted data rooms, paid continuous partner access with consented person-level visibility; productization for other communities.

## Open items to verify with real data
- Devpost export field list (occupation, referral source flagged UNVERIFIED).
- Luma guests/list JSON schema.
- Whether Coresignal is re-enabled for a later cohort. It is not part of the current build.
- Whether past-event data has any consent language attached (determines how highlight facts from past cohorts are handled: likely aggregate-only, no quotes).
- EDPB draft Guidelines 02/2026 on Anonymisation (consultation until 2026-10-30): re-check k-anonymity rules against the final text.
