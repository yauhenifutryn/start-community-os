# PRODUCT.md — START Warsaw Community OS

register: product

## Product purpose
Talent intelligence for a startup community. Ingests hackathon/event applicant data (Luma, Devpost, custom forms), normalizes and enriches it, and generates a partner-facing anonymized "talent data room": a self-contained HTML report sent to sponsors and VCs as evidence of talent quality (funnel, demographics, occupation mix, talent-signal facts, cross-event trends). Internal person-linked views come later. Long term: productized as "community OS" for other communities.

## Users
- Primary (of the data room artifact): VC partners and corporate sponsor decision-makers. They open an emailed HTML file on a laptop in a bright office between meetings and decide in about 90 seconds whether this community is a credible talent source. Skeptical, numerate, allergic to marketing fluff.
- Secondary: the community operator team who generate and curate the reports.

## Brand and tone
- Parent brand (START Warsaw): burgundy `#80011f`, navy `#00002c`, ink `#171729`, paper `#fcfbf7`, and the Avenir-first fallback stack defined in `DESIGN.md`.
- Tone of the data room: audited document, not pitch deck. Editorial report credibility ("annual report" energy), data-dense but calm. Numbers carry the persuasion; design stays out of the way but is unmistakably crafted.
- The artifact must survive being forwarded: self-contained, no external requests, no analytics, readable on any screen, printable.

## Anti-references
- Dark "crypto dashboard" aesthetic; neon on black; gradient-text SaaS heroes.
- Generic BI-tool exports (Looker/Metabase screenshots pasted into a deck).
- Pitch-deck hype language ("world-class talent!!"), vanity metrics without denominators.
- Anything that looks like a template a sponsor has seen from ten other communities.

## Strategic principles
- Credibility through restraint and methodology transparency (show denominators, show definitions, mark estimates as estimates).
- Privacy is a feature: aggregates only, k>=5 buckets, and the report says so.
- Longitudinal beats snapshot: trends across events are the moat; the design must make the time axis first-class.
