# Field-Level Source Inventory: Luma, Devpost, GitHub API, Coresignal

Researched 2026-07-09 (web agent). Claims carry inline sources; UNVERIFIED items flagged.

## 1. Luma (lu.ma)

### Access mechanics
- **CSV export** (organizer dashboard): no API needed. [Download Guest List as CSV](https://help.luma.com/p/download-guest-csv)
- **Public API**: base URL `https://public-api.luma.com`, auth via `x-luma-api-key` header. **Requires an active Luma Plus subscription** on the calendar being accessed. [Luma API help](https://help.luma.com/p/luma-api), [Getting Started](https://docs.luma.com/reference/getting-started-with-your-api)
- API keys scoped to a single calendar (Calendar -> Settings -> Developer -> API Keys).
- **Rate limits**: calendar keys 200 req/min; organization keys 500 req/min; 429 on excess.
- OpenAPI 3.1 spec public at `https://public-api.luma.com/openapi.json`; LLM index at `https://docs.luma.com/llms.txt`.

### Relevant API endpoints
| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/calendars/events/list` | GET | List events on a calendar |
| `/v1/events/get` | GET | Single event details |
| `/v1/events/guests/list` | GET | List guests (includes registration answers) |
| `/v1/events/guests/get` | GET | Single guest |
| `/v1/events/guests/update-status` | POST | Approval/check-in status |
| `/v1/calendars/contacts/*` | GET/POST | Calendar-level contacts, tags |

UNVERIFIED: exact JSON field names of `guests/list` (inferred from CSV docs + third-party wrappers: [Databar](https://databar.ai/explore/luma-api/get-event-guests), [Arcade](https://docs.arcade.dev/en/resources/integrations/productivity/luma-api)). Verify against the OpenAPI spec before building.

### Field inventory: Guest List CSV export
| Field | Notes/caveats |
|---|---|
| Name, Email | Core |
| Phone number | Only if collected |
| Registration date | |
| Approval status | going/waitlist/declined/pending; "Decline" on a pending guest also writes `declined` (documented UI/data mismatch) |
| Ticket type | |
| Check-in status (in-person) / join status (online) | |
| QR code URL | Third-party check-in integration |
| Payment amount/tax/total, coupon | Paid events only |
| Custom source / referral | |
| Custom registration question answers | One column per active question; **deleted questions vanish from future exports**: export before deleting a question |

### Registration question types available
Short/long text, single/multiple choice, social profile (Instagram/X/LinkedIn/YouTube), company, checkbox, terms/agreement, website. No conditional logic, no per-ticket-type questions; first/last name split requires Luma Plus. [Collect Registration Questions](https://help.luma.com/p/collect-registration-questions)

## 2. Devpost

### Access mechanics
No public organizer API. Access via **Manage -> Metrics** dashboard, CSV reports generated one at a time. [Metrics and reports](https://help.devpost.com/article/96-metrics-and-reports)
Reports have a **PII toggle** ("Do not include" strips name/email): we can request the non-PII variant directly instead of stripping downstream.

### Registrant Data report fields
| Field | Notes |
|---|---|
| First/last name, email | Optional PII, excludable |
| Portfolio URL | |
| Submitted-project flag / project URLs / count | |
| Location (city/state/country) | Self-reported, optional: expect high null rates |
| College/University | |
| Job specialty / occupation category | UNVERIFIED at individual-article level |
| Registered-at timestamp | |
| Teammate-availability flag | "looking for team" |
| Referral source ("how heard") | UNVERIFIED at individual-article level |

### Projects (submission) report fields
| Field | Notes |
|---|---|
| Title, submission URL, status, judging status | |
| Highest step completed, created-at | Drop-off/funnel analysis |
| About text, "Try it out" link, demo video link | |
| Opt-in prizes selected | Sponsor-relevant |
| "Built with" tags | Closest tech-stack signal |
| Custom submission-form answers | Organizer-defined |
| Team colleges, member count, member names/emails | Optional PII |

Devpost's own caveat: data is self-reported (nicknames vs legal names). [Export projects data](https://help.devpost.com/article/86-metrics-export-projects-data)

### Judging exports
Scores and comments by judge; average scores by project. Up to 6 organizer-defined criteria, scored 1-5. [How judging works](https://help.devpost.team/article/231-how-judging-works)

### Aggregate-only reports
Country data (counts only), conversion by UTM (excludes tracking-blockers and EU opt-outs), progress over time. [Export country data](https://help.devpost.com/article/98-metrics-export-country-data)

### Devpost user profile (account level, NOT in organizer exports)
Photo, name, location, bio, links, skills tags, occupation category, school + graduation date (required if student), **birth month/year (eligibility field)**, GitHub OAuth connection, hackathon portfolio. [Profile](https://help.devpost.com/article/108-update-your-profile-and-username), [Portfolio](https://help.devpost.com/article/115-what-is-a-devpost-portfolio-and-how-do-i-use-it)

**Key finding:** Devpost captures birth year and graduation year but they appear ABSENT from organizer exports. Getting them from Devpost would require scraping public profiles (ToS question). Cleaner: ask on our own forms.

### What Devpost does NOT give organizers
- Emails of visitors who never registered; non-registrant analytics; birth/graduation year in exports; any developer API.

## 3. GitHub API

### Auth and rate limits
| Tier | Limit |
|---|---|
| Unauthenticated | 60 req/hr (per IP) |
| Authenticated PAT | 5,000 req/hr |
| GitHub App (Enterprise Cloud) | 15,000 req/hr |
| Search API | ~30 req/min authenticated (current unauthenticated figure UNVERIFIED, re-check docs) |

[Rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api), [May 2025 changelog](https://github.blog/changelog/2025-05-08-updated-rate-limits-for-unauthenticated-requests/)

### `GET /users/{username}` fields
`login/id/avatar/html_url` (identity), `name`, `company` (free text), `blog`, `location` (free text), `email` (only if public), `bio`, `twitter_username`, **`hireable`** (explicit hiring-open signal), `public_repos`, `public_gists`, `followers`, `following`, **`created_at`** (account-age proxy), `updated_at`, `type` (filter bots/orgs). [Docs](https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28)

### Requires extra calls
| Signal | How |
|---|---|
| Stars received | Sum `stargazers_count` over `GET /users/{u}/repos` (no aggregate field) |
| Languages | `GET /repos/{o}/{r}/languages` per repo, aggregated |
| Public org memberships | `GET /users/{u}/orgs` |
| Pinned repos | GraphQL only (`user.pinnedItems`) |
| Contribution activity | GraphQL only (`user.contributionsCollection`); no official all-time total exists ([open request #35675](https://github.com/orgs/community/discussions/35675)) |

Cost note: a full talent profile is 1 GraphQL call + N REST calls (languages) per person; budget against 5,000/hr.

## 4. Coresignal

### Products and API shape
Employee/Person API in three tiers: Base (raw), Clean (normalized), **Multi-source** (richest). Two-step: Search (POST, filters like `headline`, `experience_title`) -> IDs -> Collect (GET by ID). [Employee Data API](https://coresignal.com/solutions/employee-data-api/), [docs](https://docs.coresignal.com/employee-api/base-employee-api)

### Pricing
Subscription from **$49/mo**, credit-based (Search 1 credit/query; Collect 1-2 credits/record by tier). Free trial: 400 search + 200 collect credits, 7 days, no card. One-time datasets from $1,000. UNVERIFIED: whether the $49 tier includes Multi-source Employee API. [Pricing docs](https://docs.coresignal.com/introduction/pricing-and-subscriptions), [pricing page](https://coresignal.com/pricing/)

### Multi-source Employee record fields (directly fetched data dictionary, high confidence)
- Identity: `full_name` (+parsed), `picture_url`
- Network: `connections_count`, `followers_count`
- URLs: `professional_network_url` (LinkedIn), socials, `website`
- Contact: `primary_professional_email` with confidence level (verified/matched/guessed): use with caution
- Location: country/city/state + ISO codes
- Current role: `headline`, `summary`, `active_experience_title/company/department/management_level`, `is_working`, `is_decision_maker`
- Skills: `inferred_skills` (AI-derived, probabilistic, not ground truth), `historical_skills`
- **Employment history**: `experience[]` with `position_title`, `management_level`, `date_from/to_year/month`, `duration_months`
- **Education**: `education[]` with `institution_name`, `degree`, `date_from_year`, `date_to_year`, `activities_and_societies` -> the age-estimation source; label all derived ages as estimates
- Certifications/patents/publications/awards (sparse for early-career people)
- Salary estimates (`projected_base_salary_p25/median/p75`): modeled, disclose as estimate if ever used
- Freshness: `created_at`, `updated_at`, `checked_at`, `is_deleted`

[Data Dictionary: Multi-source Employee API](https://docs.coresignal.com/employee-api/multi-source-employee-api/data-dictionary-multi-source-employee-api)

### Compliance posture
Self-published claims: public professional data only, GDPR/CCPA alignment, deletion/opt-out honored, founding member of Ethical Web Data Collection Initiative. [Data Transparency](https://coresignal.com/data-transparency/). This is self-certification, not independent verification; our own lawful-basis analysis still applies (see gdpr-privacy.md).

## Gaps: signal no source provides -> ask on application forms

| Signal | Why missing | Form field |
|---|---|---|
| Consent to enrichment/aggregation | No source provides per-person opt-in | Explicit checkboxes (see gdpr-privacy.md drafts) |
| Verified age / birth year | Devpost has it but does not export it; Coresignal only enables inference | Optional age band or birth year |
| Graduation year (verified) | Devpost: student-only + not exported; Coresignal: stale-LinkedIn inference | "Current or expected graduation year" |
| Occupation category (clean taxonomy) | Devpost loose, Coresignal raw title strings | Fixed dropdown: student / early-career / senior / founder / researcher / other |
| Self-rated skills | GitHub = activity volume, not competence; Coresignal = inferred | Top 3 skills, or skip |
| "Most impressive thing you built" | Devpost covers submitted projects only | Open-text application question (also the LLM's best signal source) |
| Team-formation intent | Devpost flag exists; Luma has nothing | "Looking for a team?" |
| **Cross-platform identity key** | No shared ID across Luma/Devpost/GitHub/LinkedIn; fuzzy email/name matching otherwise | **Ask directly for GitHub username + LinkedIn URL on every form.** Single cheapest fix for the hardest downstream problem. |

## Verify before building
1. Luma `guests/list` JSON schema against the public OpenAPI spec.
2. GitHub Search API current unauthenticated limit.
3. Coresignal $49 tier feature gate (Multi-source included?).
4. Devpost export fields against a real export from our own hackathon (especially occupation/referral fields flagged UNVERIFIED).
