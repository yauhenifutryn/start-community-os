# Talent Data Room design system

## Direction

The report is an audited editorial briefing, not a BI dashboard. It should feel calm, exact, and easy to forward: white paper, deep navy ink, START Warsaw crimson accents, large evidence-led headlines, thin rules, and generous whitespace.

## Visual grammar

- The canonical interface tokens match the deployed START Warsaw track-preference form: navy `#00002c`, burgundy `#80011f`, paper `#fcfbf7`, ink `#171729`, muted `#5d5d6e`, rule `#d5d4db`, focus `#d8a7b4`, selected tint `#fff5f7`, error `#94252a`, and success `#187447`.
- Use the official white START Warsaw lockup from `assets/brand/start-warsaw-white.svg` on navy. The repository includes no licensed Avenir font binary; the fallback stack below is the portable public baseline.
- Typography follows `AvenirLTNextPro, "Avenir Next", Avenir, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`. No Avenir binary is bundled until a portable webfont license and files are supplied.
- Crimson is reserved for exhibit labels, primary series, active navigation, and the funnel's advanced people.
- Navy carries body ink, secondary series, and the cover.
- Neutral gray shows stopped funnel stages, supporting copy, rules, and pending states.
- Unit dots are used only when one mark genuinely represents one person.
- Horizontal bars are used for ranked categorical comparison.
- Lines are used only for comparable cross-event series with at least two time points.
- Every exhibit includes its denominator or scope, source context, and a table fallback where useful.
- The hero participant journey may use an alluvial only after reconciliation produces mutually exclusive stages with consistent units. Team and submission matrices, attendance signature dots, builder-signal intersections, and track-domain heatmaps are preferred over generic chart-library defaults.

## Interaction and motion

Primary evidence is visible without interaction. The aggregate-only HTML dashboard supports All, Accepted, and Attended cohorts because those selections change the population and denominator. It deliberately avoids editorial lens switches that would only reorder the same limited evidence. Metric focus and activation expose definitions, evidence standards, denominators, cohort comparisons, and unknown states. One reviewed three-signal exact partition can be explored without person-level browsing; additional cross-sections appear only when every cell and complement passes the privacy threshold.

Motion is brief and functional. Use transform and opacity for selection transitions, keep controls responsive during motion, and honor reduced-motion preferences. Decorative motion must not delay evidence or change the meaning of a chart.

The approved base report remains analytics-free. Hosted measurement is created only by a separate post-publication transform after exact release-owner approval. That transform allows a fixed aggregate interaction event set, ephemeral page-load identity, no stable viewer profile, and no participant properties. Analytics configuration never changes report claims or unlocks publication.

## Print

PDF is a composed static briefing. Interactive controls are removed, each report page carries its evidence state, and synthetic examples are labeled on every exhibit. The cover, typography, chart palette, and information hierarchy remain consistent with the HTML artifact.

## Data-state rule

Real reports never inherit synthetic narrative or metrics. Missing classified, longitudinal, outcome, Devpost, or Coresignal data renders as an explicit readiness state until its validated aggregate becomes available.

Source workbooks are schema inputs, not trusted tables by default. Headerless or data-first worksheets require an explicit source adapter and reconciliation checks before ingestion.
