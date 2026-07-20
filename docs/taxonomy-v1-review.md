# Taxonomy v1 Review

Status: draft, not approved for real-person classification.

The pipeline can ingest, deduplicate, aggregate, and render without AI. Semantic classification remains disabled until START Warsaw approves:

1. The occupation and builder-signal categories in `taxonomy/v1.draft.json`.
2. The exact fields that may be sent to an external model.
3. The OpenAI model and expected cost/quality tradeoff.
4. The prompt and structured output schema.
5. The privacy basis, processor terms, region, retention, logging, and transparency requirements.

Suggested AI steps after approval:

- Normalize free-text occupation into the fixed taxonomy.
- Classify builder signal from application evidence and, later, Devpost/GitHub evidence.
- Generalize a consented highlight to reduce linkability.

Deterministic steps that must never depend on AI:

- CSV ingestion and schema validation.
- Identity evidence and manual conflict resolution.
- Consent, opt-out, retention, and ghost transitions.
- Statistical disclosure checks.
- Rendering and PDF export.
