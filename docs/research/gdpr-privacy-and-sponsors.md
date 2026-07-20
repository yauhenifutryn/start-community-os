# GDPR / Anonymization Posture + Sponsor Expectations

Researched 2026-07-09 (web agent). Claims carry inline sources; UNVERIFIED items flagged.

## Topic A: GDPR / privacy

### 1. Lawful basis for aggregate partner reporting: two-step model
- **Step 1 (internal computation over identifiable data):** recommended basis is **legitimate interest, Art. 6(1)(f)**, with a documented one-page LIA (purpose / necessity / balancing). Consent is NOT recommended for the statistics themselves: it is withdrawable and operationally fragile. ([TermsFeed](https://www.termsfeed.com/blog/gdpr-compliance-events-attendee-lists-name-tags/), [Splash](https://splashthat.com/blog/gdpr-for-event-marketing))
- **Step 2 (published output):** truly anonymized aggregates fall **outside GDPR entirely** per Recital 26 ([gdpr-info.eu](https://gdpr-info.eu/recitals/no-26/); Poland-specific: [Crowe Poland](https://www.crowe.com/pl/en-us/insights/anonymization-of-personal-data)).
- **Purpose limitation:** Art. 89(1) makes further processing for statistical purposes "not incompatible" with original collection, conditional on minimisation/pseudonymisation safeguards ([Art. 89](https://gdpr-info.eu/art-89-gdpr/)). Recital 162: results must be aggregate and **never used for decisions about a particular person** ([Recital 162](https://gdpr-info.eu/recitals/no-162/)): sponsors must not be able to single anyone out or request drill-downs that would.

### 2. Anonymization standard; is k>=5 enough?
- WP29 Opinion 05/2014 (WP216) three-risk test: singling out, linkability, inference ([EC PDF](https://ec.europa.eu/justice/article-29/documentation/opinion-recommendation/files/2014/wp216_en.pdf); exact wording reconstructed from secondary sources, UNVERIFIED verbatim).
- **Watch item:** EDPB adopted draft Guidelines 02/2026 on Anonymisation on 2026-07-08, consultation until 2026-10-30 ([EDPB](https://www.edpb.europa.eu/public-consultations/guidelines-on-anonymisation_en)). WP216 operative until final. Re-check our rules against the final text.
- Real-world suppression thresholds: UK ONS <3, US CMS 1-10, Canada 10/20, Eurostat delegates to states.
- **Verdict: k>=5 is defensible but insufficient alone.** Required extras:
  1. Apply k to every **cross-tabulation**, not just single-variable cells.
  2. **Complementary suppression** (suppressed cells must not be reconstructable from totals).
  3. Guard against **differencing across successive reports** (event N vs N+1).
  4. Consider k>=10 for cohorts under 50 or sensitive cuts.

### 3. Broker enrichment (Coresignal) and enforcement precedents
- **CNIL v. Kaspr (2024-12-05), CONFIRMED:** fined for scraping LinkedIn contact data (~160M contacts). CNIL's page says EUR 240,000 ([cnil.fr](https://www.cnil.fr/en/data-scraping-kaspr-fined-eu240000)); EDPB summary says EUR 200,000 (discrepancy noted, CNIL primary). Grounds: no lawful basis (exceeded reasonable expectations), 5-year retention, no/late Art. 12/14 notice, poor access-request handling. Closest precedent to Coresignal's model.
- Lusha: CNIL probe closed out-of-scope 2018; live Garante investigation, outcome UNVERIFIED. Coresignal, Bright Data: no GDPR enforcement found.
- **Our obligations as broker customer:**
  - **Art. 14 notice within one month of enrichment**: identity, purposes, basis, data categories, source, recipients, retention, rights ([Art. 14](https://gdpr-info.eu/art-14-gdpr/), [ICO](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/individual-rights/individual-rights/right-to-be-informed/)). We have applicants' emails, so the "disproportionate effort" exemption is NOT credible; include the notice in the acceptance/confirmation email.
  - **Lightweight DPIA** advisable (WP29 triggers: datasets matched/combined + evaluation/scoring).
  - Retention limit on raw enriched records (e.g., delete/anonymize 12 months post-event, avoiding Kaspr's retention failure).

### 4. Inferred data (age from university years)
Inferred data about an identifiable person IS personal data (CJEU Nowak C-434/16). Estimated age tied to an individual record = personal data regardless of accuracy; melted into k>=5 aggregates = outside scope. Keep individual-level age estimates internal-only, never exported.

### 5. Consent/notice language (drafts)
Real-world analogue: MLH privacy policy's aggregate-sharing clause ([mlh.com/privacy](https://www.mlh.com/privacy)); no public checkbox template exists for broker enrichment, bespoke drafting required.

- **Draft 1, aggregate statistics (transparency line, LI basis, checkbox optional):**
  "We compile anonymized, aggregate statistics about our applicant community (e.g., experience levels, fields of study, project activity) and share them with event partners and sponsors. These statistics never identify you individually and are always based on groups of at least 5 people. Learn more in our Privacy Policy."
- **Draft 2, enrichment (explicit unticked checkbox, recommended):**
  "[ ] I agree that START Warsaw may supplement my application with publicly available professional information (e.g., my public GitHub activity and public professional profiles obtained via third-party providers) to assess applications and produce anonymized community statistics. Details, sources, and your right to object are described in our Privacy Policy."
- **Draft 3, combined short-form (space-constrained Luma forms):**
  "[ ] I understand that START Warsaw processes my application data as described in the Privacy Policy, may enrich it with publicly available professional information (GitHub, public professional profiles), and publishes only anonymized group-level statistics (groups of 5+) to partners and sponsors."

### 6. PostHog in the static data room
- EU Cloud confirmed (AWS Frankfurt), `api_host: https://eu.i.posthog.com`; PostHog = processor, we = controller, sign DPA ([posthog.com](https://posthog.com/blog/posthog-cloud-eu), [GDPR docs](https://posthog.com/docs/privacy/gdpr-compliance)).
- **ePrivacy Art. 5(3) applies to localStorage the same as cookies**, regardless of audience size (EDPB Guidelines 2/2023). No carve-out for known-recipient HTML files.
- **Defensible v1 config: `persistence: 'memory'`**, autocapture OFF, session recording OFF. Memory-only persistence stores nothing on the device, staying out of the Art. 5(3) trigger; add footer line "This page uses privacy-preserving, cookieless analytics hosted in the EU."

## Topic B: sponsor expectations

Motivations ranked (primary: [MLH Understanding Your Sponsors](https://guide.mlh.com/general-information/getting-sponsorship/understanding-your-sponsors)):
1. **Recruiting/talent pipeline**: dominant driver; one organizer models ~$1k recruiting value per attendee vs ~$200/attendee sponsorship cost (UNVERIFIED single-source model: [Hackonomics 101](https://medium.com/@alexeymk/hackonomics-101-ad619910b134)).
2. **Product/API adoption**: peer-reviewed: sponsored-hackathon attendees 20.4% more likely to adopt the platform next year ([Rice Business Wisdom](https://business.rice.edu/wisdom/peer-reviewed-research/tech-companies-should-sponsor-hackathons)).
3. Brand awareness / innovation positioning.
4. VC deal flow / startup scouting (appears in VC-side content, not standard prospectuses).

Metrics appearing in sponsor materials: attendance/applicant counts, geographic reach, school/company mix, technologies used (sponsor API adoption), hires/interviews sourced, resume-book access. Prospectus norms: 2-3 pages, 3 tiers ([MLH prospectus guide](https://guide.mlh.com/general-information/getting-sponsorship/sponsorship-prospectus), [example decks](https://github.com/MLH/mlh-hackathon-organizer-guide/tree/master/Organizer-Resources/Previous-Sponsorship-Decks)).

**Implication:** our planned content maps directly onto what sponsors already buy on. Highest-value additions: technology/skill breakdowns, and over time, recruiting conversion numbers (interviews/hires sourced), the metric with the clearest dollar translation.

## Practical v1 compliance checklist
1. Privacy notice update: name the purposes (aggregate partner stats; enrichment from public sources) with legal bases.
2. One-page LIA for the aggregation processing.
3. Art. 14 enrichment notice in acceptance/confirmation emails.
4. Lightweight DPIA for the enrichment pipeline.
5. Pipeline-enforced anonymization: k>=5 on every published cell including cross-tabs; complementary suppression; no attributable free-text quotes; k>=10 for cohorts <50; differencing check between reports.
6. Inferred age aggregate-only.
7. Coresignal due-diligence file + DPA + 12-month retention cap on raw enriched records.
8. PostHog: EU cloud, memory persistence, autocapture off, DPA, footer notice.
9. Recital 162 guardrail: sponsors get statistics only, no individual drill-downs, contractual line in sponsor agreements.
10. Watch EDPB draft Guidelines 02/2026 on Anonymisation (final version expected after 2026-10-30).

## Addendum: EU vs US regulatory burden (added 2026-07-09)
The compliance machinery in this doc is essentially EU-only. US: no federal GDPR equivalent (no lawful basis, Art. 14, retention, or anonymization requirements for general data); state laws (CCPA/CPRA + ~20 states) apply above business thresholds ($25M revenue / 100k+ consumers) and exempt nonprofits entirely; public-profile scraping is chiefly a platform-ToS/contract issue (hiQ v. LinkedIn: CFAA claims failed for public data, contract claims survived), which is why the data-broker industry is US-centric. Twists: (1) GDPR is extraterritorial, following EU residents' data regardless of company location, so it fully applies to START Warsaw and to any US community processing EU applicants; (2) productization angle: "GDPR-compliant by construction" (k>=5 in code, retention automation, ghost records) is a moat for selling community OS to EU communities and a trust feature for US ones.
