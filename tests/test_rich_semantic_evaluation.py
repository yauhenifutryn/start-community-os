from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import re
import tempfile
import unittest

from community_os.enrichment.openai_rich_semantic_assessment import (
    OpenAIRichSemanticAssessmentProvider,
)
from community_os.enrichment.rich_semantic_assessment import (
    PROMPT_VERSION,
    validate_profile_evidence,
    validate_rich_semantic_assessment,
)
from community_os.enrichment.semantic_taxonomy import (
    ALL_DIMENSIONS,
    CAREER_FIELDS,
    PROJECT_FIELDS,
    TAXONOMY_VERSION,
)
from community_os.enrichment.transport import HttpResponse
from community_os.rich_semantic_evaluation import (
    RetryableEvaluationError,
    RichSemanticEvaluationStore,
    RichSemanticEvaluator,
    cleanup_expired_rich_semantic_evaluation,
    evaluation_schema_sha256,
    labeled_sample_hashes,
    recommendation_policy_sha256,
)
from community_os.semantic_metrics import (
    matching_metric_keys,
    partner_report_taxonomy_schema_sha256,
)
from tests.test_rich_semantic_assessment import (
    semantic_taxonomy_for_assessment,
)


NOW = datetime(2026, 7, 15, 8, 0, tzinfo=UTC)
KNOWN_IDENTITY_LITERALS = ("Fixture Person",)
FLATTENED_LABEL_KEYS = (
    "builder_level",
    "cross_source_confidence",
    "reason_codes",
    *(f"project.{field}" for field in PROJECT_FIELDS),
    *(f"career.{field}" for field in CAREER_FIELDS),
    *(f"sources.{field}" for field in ALL_DIMENSIONS),
)
V5_GOLD_FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "enrichment"
    / "rich_semantic_evaluation_v5.json"
)
V5_GOLD_CASE_REFS = (
    "case:v1:1ad5e659b4a6b7f5c2774849d0339144c360d9faae3c3b44c1c73af6a5a3fa77",
    "case:v1:24a797e9f4b855765343341e6ddcc36e4f32eb74e1299aea4d5461cc64e32567",
    "case:v1:28ea8482d0e769e50aa5b32203bc9b8b0aa0bee33ae6b24e53ef951d6e4bf73a",
    "case:v1:476e663808a734b04d18b64da37b2cbb5338b04e02421aadb0ab31baf0dcf500",
    "case:v1:500cfc8b61706373dbcdd3c7302fa069a86bff680c6c4b97eb2704e9e1e41d3d",
    "case:v1:79b49a1be131f642ce22191da57100f3f7949738fe45d8cc649974d8f3caef95",
    "case:v1:84fa4b1924188941f3b7f9030542b24bffcbfe77dc6c19b0f377ced3ab80d41c",
    "case:v1:cc042ee9b40788c25bab04a08df26e2527c7691745ad9c7a4a761fbeee30f7db",
    "case:v1:e316365206903394b7c04a407468961db0f73bc02bb16d341beaf4c9f41c5ec2",
    "case:v1:ea0e8dafb5c73ac120cb37909279eb3459ae7579d1b9c9b5055f5d1d305959a3",
)
V5_GOLD_HASHES = {
    "sample_sha256": "82716c22abae8cb20c52d821296f696e3f91b0fa7e92f5f8bbc10878f48921eb",
    "case_refs_sha256": "41939236fcdea6d3a4e42257fe7c57e779a104fe9d1ec6904d0ccc1086f06e5a",
    "labels_sha256": "79024f27442a6f0a554682273ded3e1b248c948074c52e69d45266176a3c01fc",
}
V5_ALL_PARTNER_METRICS = (
    "advanced_technical_evidence",
    "differentiated_problem",
    "meaningful_validation",
    "primary_execution",
    "serious_product_builder",
    "standout_builder",
    "substantive_technical_evidence",
)
V5_EXPECTED_PARTNER_METRICS = {
    V5_GOLD_CASE_REFS[0]: (),
    V5_GOLD_CASE_REFS[1]: (
        "meaningful_validation",
        "substantive_technical_evidence",
    ),
    V5_GOLD_CASE_REFS[2]: V5_ALL_PARTNER_METRICS,
    V5_GOLD_CASE_REFS[3]: (),
    V5_GOLD_CASE_REFS[4]: ("substantive_technical_evidence",),
    V5_GOLD_CASE_REFS[5]: (
        "advanced_technical_evidence",
        "meaningful_validation",
        "substantive_technical_evidence",
    ),
    V5_GOLD_CASE_REFS[6]: (),
    V5_GOLD_CASE_REFS[7]: V5_ALL_PARTNER_METRICS,
    V5_GOLD_CASE_REFS[8]: V5_ALL_PARTNER_METRICS,
    V5_GOLD_CASE_REFS[9]: (
        "advanced_technical_evidence",
        "differentiated_problem",
        "substantive_technical_evidence",
    ),
}
V5_FORBIDDEN_IDENTITY_KEYS = frozenset({
    "candidate_id",
    "company_name",
    "contact",
    "email",
    "full_name",
    "github",
    "handle",
    "linkedin",
    "name",
    "organization_name",
    "participant_id",
    "person_id",
    "phone",
    "product_name",
    "profile_url",
    "subject_ref",
    "telephone",
    "url",
    "username",
})
V5_NAMED_ENTITY_PATTERN = re.compile(
    r"\b[A-Z][a-z]{2,}(?:[ -][A-Z][a-z]{2,})+\b|"
    r"\b[A-Za-z][A-Za-z0-9&'-]+\s+"
    r"(?:Corporation|Corp|Foundation|GmbH|Inc|Labs?|LLC|Ltd|Studio|"
    r"Technologies|Ventures)\b"
)
V5_FORBIDDEN_REAL_WORLD_LITERALS = (
    "deepseek",
    "gemma",
    "machine at uw",
    "mbank",
    "ml in pl",
    "ollama",
    "qwen",
)
V5_SYNTHETIC_EXCERPT_CONTRACT = {
    V5_GOLD_CASE_REFS[0]: {
        "project_01:description": (
            "starter workspace with promotional claims and sample pages"
        ),
        "project_01:readme": (
            "template repository containing sample screens, placeholder "
            "testimonials, and setup instructions without release, deployment, "
            "customer, or adoption evidence."
        ),
        "role_01:description": (
            "participated in pitch workshops and shared general product feedback."
        ),
        "role_01:title": "founder in residence",
        "role_02:description": (
            "supported community sessions and reviewed presentation drafts."
        ),
        "role_02:title": "senior advisor",
    },
    V5_GOLD_CASE_REFS[1]: {
        "project_01:description": (
            "curated directory of technical events and learning resources"
        ),
        "project_01:readme": (
            "maintained directory template listing technical events, learning "
            "groups, and investor resources; it provides no standalone software "
            "product."
        ),
        "project_02:description": "voice interaction comparison prototype",
        "project_02:readme": (
            "prototype compares two interruption-handling modes while holding the "
            "voice pipeline constant; documentation includes setup steps and "
            "evaluation guidance but no deployment evidence."
        ),
        "project_03:description": "",
        "project_03:readme": (
            "local document indexing prototype that ingests bounded source files "
            "and produces linked reference pages for offline browsing."
        ),
    },
    V5_GOLD_CASE_REFS[2]: {
        "application_01:achievement": "",
        "application_01:experience": (
            "i designed and shipped a secure developer runtime, a local model "
            "benchmark, and an isolated command environment; the work covered "
            "architecture, implementation, release packaging, and evaluation."
        ),
        "project_01:description": "local model performance benchmark",
        "project_01:readme": (
            "command-line benchmark measures startup, prompt processing, reasoning, "
            "generation, and output latency; it compares multiple local models and "
            "emits structured reports."
        ),
        "project_02:description": "sandboxed runtime for coding workflows",
        "project_02:readme": (
            "released runtime accelerates coding workflows with isolated tool "
            "execution, file operations, status commands, and repeatable benchmark "
            "paths."
        ),
        "project_03:description": "isolated command execution service",
        "project_03:readme": (
            "service runs shell commands in a bounded in-memory filesystem with "
            "configurable network rules, resource limits, and structured execution "
            "results."
        ),
    },
    V5_GOLD_CASE_REFS[3]: {},
    V5_GOLD_CASE_REFS[4]: {
        "devpost_01:project": (
            "working browser application imports energy data, compares live "
            "scenarios, and exports a verified reduction plan; the observed demo "
            "completed import, analysis, and export."
        ),
    },
    V5_GOLD_CASE_REFS[5]: {
        "application_01:achievement": "",
        "application_01:experience": (
            "built modeling and simulation tools for industrial research and "
            "contributed to widely adopted scientific software; evidence describes "
            "technical contribution but does not establish primary authorship of "
            "this repository."
        ),
        "project_01:description": "industrial process modeling toolkit",
        "project_01:readme": (
            "released scientific toolkit formulates optimization stages for utility "
            "use, equipment count, stream matching, and network design; documentation "
            "includes reproducible examples and deployment guidance."
        ),
        "project_02:description": "",
        "project_02:readme": (
            "course-support repository organizes recorded lectures, interactive "
            "exercises, and research-report guidance for advanced process "
            "optimization."
        ),
        "project_03:description": "",
        "project_03:readme": "",
    },
    V5_GOLD_CASE_REFS[6]: {
        "role_01:description": (
            "led a software team that delivered customer data systems and scaled "
            "production services across multiple regions."
        ),
        "role_01:title": "engineering lead",
        "role_02:description": (
            "built backend services and converted research prototypes to customer "
            "workflows."
        ),
        "role_02:title": "software engineer",
    },
    V5_GOLD_CASE_REFS[7]: {
        "application_01:achievement": "",
        "application_01:experience": (
            "i founded and built an agent data platform, developer tooling, and "
            "automation systems; i contributed architecture, product decisions, "
            "implementation, and live demonstrations."
        ),
        "project_01:description": "collaborative local-first document editor",
        "project_01:readme": (
            "deployed document editor supports structured text, offline persistence, "
            "real-time collaboration, access controls, shared pages, search, and "
            "isolated storage."
        ),
        "project_02:description": "compatible in-memory data service",
        "project_02:readme": (
            "released data service implements common key-value, collection, "
            "scripting, expiration, and client compatibility features with documented "
            "operational limits."
        ),
        "project_03:description": "browser-based local development workspace",
        "project_03:readme": (
            "development workspace provides an editor, shell, version control, "
            "package execution, live preview, local automation, and persistent "
            "virtual files without a remote execution service."
        ),
    },
    V5_GOLD_CASE_REFS[8]: {
        "application_01:achievement": (
            "a live pilot ran daily for eight weeks across three small fleets, "
            "reduced failed deliveries, and won a technical impact award."
        ),
        "application_01:experience": (
            "i designed and built the core platform end to end, including streaming "
            "data ingestion, explainable risk scoring, idempotent event processing, "
            "deployment, and operator workflows."
        ),
        "devpost_01:project": (
            "a deployed routing platform ingests streaming events, predicts delivery "
            "risk, assigns retry safe interventions, and records operator outcomes. "
            "the observed demo completed ingestion, scoring, intervention, and follow "
            "up."
        ),
        "project_01:description": (
            "a routing platform for intervention based delivery risk reduction"
        ),
        "project_01:readme": (
            "the platform ingests and deduplicates live route events, scores delivery "
            "risk, assigns retry safe interventions, and records operator outcomes. "
            "the released deployment supports the pilot workflow from event intake "
            "through follow up."
        ),
    },
    V5_GOLD_CASE_REFS[9]: {
        "application_01:achievement": "",
        "application_01:experience": (
            "i designed an end-to-end voice automation system with event routing, "
            "planner and worker agents, memory retrieval, tool execution, desktop "
            "control, and workflow orchestration."
        ),
        "project_01:description": "multi-agent desktop automation prototype",
        "project_01:readme": (
            "prototype combines screen analysis, workflow nodes, event routing, tool "
            "execution, and operator controls across a browser interface and local "
            "service."
        ),
        "project_02:description": "voice-controlled spatial workspace prototype",
        "project_02:readme": (
            "prototype routes multilingual voice requests through specialized agents "
            "and renders structured results in an interactive spatial interface; it "
            "includes memory, ambiguity resolution, and multi-tool planning."
        ),
        "project_03:description": "music generation research prototype",
        "project_03:readme": "research notes",
    },
}


def load_v5_gold_fixture() -> list[dict[str, object]]:
    return json.loads(V5_GOLD_FIXTURE_PATH.read_text(encoding="utf-8"))


def free_text_excerpts(item: dict[str, object]) -> dict[str, str]:
    evidence_value = item["evidence"]
    excerpts: dict[str, str] = {}
    for packet in evidence_value["application"]:
        code = packet["evidence_code"]
        excerpts[f"{code}:achievement"] = packet["achievement_excerpt"]
        excerpts[f"{code}:experience"] = packet["experience_excerpt"]
    for packet in evidence_value["career"]:
        code = packet["role_code"]
        excerpts[f"{code}:description"] = packet["description_excerpt"]
        excerpts[f"{code}:title"] = packet["title_excerpt"]
    for packet in evidence_value["devpost"]:
        excerpts[f'{packet["evidence_code"]}:project'] = packet["project_excerpt"]
    for packet in evidence_value["projects"]:
        code = packet["project_code"]
        excerpts[f"{code}:description"] = packet["description_excerpt"]
        excerpts[f"{code}:readme"] = packet["readme_excerpt"]
    return excerpts


def reference_source_family(reference: str) -> str:
    return {
        "application": "application",
        "devpost": "devpost",
        "project": "projects",
        "role": "career",
    }[reference.split("_", 1)[0]]


def reference_for_dimension(
    evidence_value: dict[str, object], *, family: str, dimension: str,
) -> str:
    packets = evidence_value[family]
    if dimension == "external_validation" and family == "projects":
        engagement_rank = {"none": 0, "some": 1, "notable": 2, "high": 3}
        packets = sorted(
            packets,
            key=lambda packet: (
                -max(
                    engagement_rank[packet["stars_band"]],
                    engagement_rank[packet["forks_band"]],
                ),
                packet["project_code"],
            ),
        )[:1]
    references = sorted({
        reference
        for packet in packets
        for reference in packet["evidence_refs"]
    })
    preferences = {
        "application": ("experience", "achievement"),
        "career": ("description", "title"),
        "devpost": ("project", "demo"),
        "projects": ("readme", "description", "deployment", "release", "ownership"),
    }[family]
    if dimension == "product_maturity":
        preferences = {
            "application": ("achievement", "experience"),
            "career": ("description", "title"),
            "devpost": ("demo", "project"),
            "projects": ("deployment", "release", "readme", "description"),
        }[family]
    elif dimension == "external_validation":
        preferences = {
            "application": ("achievement", "experience"),
            "career": ("description", "title"),
            "devpost": ("project", "demo"),
            "projects": ("readme", "description", "deployment", "release"),
        }[family]
    for suffix in preferences:
        for reference in references:
            if reference.endswith(f":{suffix}"):
                return reference
    raise AssertionError(f"no {family} reference supports {dimension}")


def assessment_from_v5_gold_case(item: dict[str, object]) -> dict[str, object]:
    evidence_value = item["evidence"]
    label = item["label"]
    taxonomy = label["semantic_taxonomy"]
    evidence_by_dimension = {
        dimension: sorted(
            reference_for_dimension(
                evidence_value, family=family, dimension=dimension,
            )
            for family in label["source_families_by_dimension"][dimension]
        )
        for dimension in ALL_DIMENSIONS
    }
    evidence_refs = sorted({
        reference
        for references in evidence_by_dimension.values()
        for reference in references
    })
    project = taxonomy["project"]
    return {
        "builder_level": label["builder_level"],
        "career_summary": "",
        "cross_source_confidence": label["cross_source_confidence"],
        "evidence_refs": evidence_refs,
        "execution_scope": project["execution_scope"],
        "external_validation": (
            "none"
            if project["external_validation"] == "none_observed"
            else project["external_validation"]
        ),
        "originality": project["problem_differentiation"],
        "product_maturity": project["product_maturity"],
        "project_summary": "",
        "rationale": "The bounded synthetic evidence supports the gold label.",
        "reason_codes": list(label["reason_codes"]),
        "review_state": "human_review_required",
        "semantic_taxonomy": {
            "version": TAXONOMY_VERSION,
            "project": dict(project),
            "career": dict(taxonomy["career"]),
            "evidence_by_dimension": evidence_by_dimension,
        },
        "technical_depth": project["technical_depth"],
    }


def evidence(*, code: str = "project_01") -> dict[str, object]:
    return {
        "projects": [{
            "activity_recency": "active_90d",
            "age_band": "established",
            "deployment_signal": "deployment_observed",
            "description_excerpt": "A workflow product with durable jobs and audit receipts.",
            "evidence_refs": [
                f"{code}:ownership",
                f"{code}:description", f"{code}:readme",
                f"{code}:release", f"{code}:deployment",
            ],
            "forks_band": "none",
            "issues_band": "some",
            "language_code": "python",
            "productization_codes": ["issues_enabled", "license_present"],
            "project_code": code,
            "readme_excerpt": "Runs background work, retries failures, and records operator decisions.",
            "repository_relationship": "profile_owned_nonfork",
            "release_signal": "release_observed",
            "size_band": "medium",
            "stars_band": "none",
            "topic_codes": ["developer_tools"],
        }],
        "application": [{
            "evidence_code": "application_01",
            "experience_excerpt": "",
            "achievement_excerpt": "Built and shipped the supplied workflow product.",
            "evidence_refs": ["application_01:achievement"],
        }],
        "devpost": [],
        "career": [],
    }


def case(
    ordinal: int, *, builder: str = "substantial",
    maturity: str = "working_product",
) -> dict[str, object]:
    expected = assessment(builder=builder, maturity=maturity)
    return {
        "case_ref": f"case:v1:{ordinal:064x}",
        "evidence": evidence(),
        "label": label_from_assessment(expected),
    }


def assessment(
    *, builder: str = "substantial",
    maturity: str = "working_product",
    confidence: str = "high",
) -> dict[str, object]:
    value: dict[str, object] = {
        "builder_level": builder,
        "career_summary": "",
        "cross_source_confidence": confidence,
        "evidence_refs": [
            "project_01:description", "project_01:deployment",
            "application_01:achievement",
        ],
        "execution_scope": "substantial_contributor",
        "external_validation": "none",
        "originality": "ordinary",
        "product_maturity": maturity,
        "project_summary": "A working product with explicit operational evidence.",
        "rationale": "The supplied project evidence supports the bounded classification.",
        "reason_codes": ["shipped_working_product"],
        "review_state": "human_review_required",
        "technical_depth": "advanced",
    }
    if builder == "exploratory":
        value.update({
            "execution_scope": "contributor",
            "reason_codes": [
                "prototype_only"
                if maturity == "prototype"
                else "shipped_working_product"
            ],
            "technical_depth": "moderate",
        })
    elif builder == "standout":
        value.update({
            "execution_scope": "primary_builder",
            "external_validation": "meaningful",
            "originality": "differentiated",
            "reason_codes": [
                "differentiated_problem",
                "shipped_working_product",
                "technically_substantial",
            ],
            "technical_depth": "exceptional",
        })
    elif builder == "insufficient" and maturity == "unknown":
        value.update({
            "cross_source_confidence": "low",
            "evidence_refs": [],
            "execution_scope": "unknown",
            "external_validation": "none",
            "originality": "unknown",
            "product_maturity": "unknown",
            "reason_codes": ["insufficient_evidence"],
            "technical_depth": "unknown",
        })
    if maturity == "production_evidence" and builder != "insufficient":
        value["reason_codes"] = sorted({
            *value["reason_codes"], "production_operations",
        })
    value["semantic_taxonomy"] = semantic_taxonomy_for_assessment(value)
    return value


def label_from_assessment(value: dict[str, object]) -> dict[str, object]:
    taxonomy = value["semantic_taxonomy"]
    source_families = {
        dimension: sorted({
            {
                "application": "application",
                "devpost": "devpost",
                "project": "projects",
                "role": "career",
            }[str(reference).split("_", 1)[0]]
            for reference in taxonomy["evidence_by_dimension"][dimension]
        })
        for dimension in ALL_DIMENSIONS
    }
    return {
        "builder_level": value["builder_level"],
        "cross_source_confidence": value["cross_source_confidence"],
        "reason_codes": sorted(value["reason_codes"]),
        "semantic_taxonomy": {
            "project": dict(taxonomy["project"]),
            "career": dict(taxonomy["career"]),
        },
        "source_families_by_dimension": source_families,
    }


class ProviderResponsesTransport:
    def __init__(
        self, model: str,
        predictions: list[tuple[str, str] | dict[str, object]], *,
        tokens: tuple[int, int] = (10, 5),
        endpoint: str = "https://api.openai.com/v1/responses",
    ) -> None:
        self.endpoint = endpoint
        self.model = model
        self.predictions = list(predictions)
        self.tokens = tokens
        self.requests = 0

    def request(self, *, headers, body, timeout, max_bytes):
        self.requests += 1
        prediction = self.predictions.pop(0)
        if isinstance(prediction, dict):
            predicted_assessment = prediction
        else:
            builder, maturity = prediction
            predicted_assessment = assessment(builder=builder, maturity=maturity)
        envelope = {
            "model": self.model,
            "status": "completed",
            "usage": {
                "input_tokens": self.tokens[0],
                "output_tokens": self.tokens[1],
            },
            "output": [{"type": "message", "content": [{
                "type": "output_text",
                "text": json.dumps(predicted_assessment),
            }]}],
        }
        return HttpResponse(
            200, {}, json.dumps(envelope).encode("utf-8"), self.endpoint,
        )


def model_binding(model: str, version: str, *, input_rate: int, output_rate: int) -> dict[str, object]:
    return {
        "endpoint": "https://api.openai.com/v1/responses",
        "input_cost_per_million_usd_micros": input_rate,
        "max_output_tokens": 4_000,
        "max_request_bytes": 65_536,
        "model": model,
        "model_version": version,
        "normalization_version": "rich-semantic-normalization-v14",
        "output_cost_per_million_usd_micros": output_rate,
        "reasoning_effort": "low",
        "store": False,
    }


def runtime_binding(model: str, version: str) -> dict[str, object]:
    rates = (1_000_000, 6_000_000) if model == "gpt-5.6-luna" else (2_500_000, 15_000_000)
    return {
        **model_binding(model, version, input_rate=rates[0], output_rate=rates[1]),
        "prompt_version": PROMPT_VERSION,
        "region": "global",
        "schema_sha256": evaluation_schema_sha256(),
    }


def approval_record(sample: list[dict[str, object]], **overrides: object) -> dict[str, object]:
    hashes = labeled_sample_hashes(sample)
    record: dict[str, object] = {
        "agreement_threshold_basis_points": 8_000,
        "approval_id": "release-owner-rich-semantic-model-evaluation-20260715",
        "approved_at": NOW.isoformat().replace("+00:00", "Z"),
        "approved_by": "release_owner",
        "case_refs_sha256": hashes["case_refs_sha256"],
        "distribution": "internal_only_pending_human_review",
        "evaluation_version": "rich-semantic-model-evaluation-v5",
        "expires_at": (NOW + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        "labels_sha256": hashes["labels_sha256"],
        "max_attempts_per_case": 2,
        "max_provider_attempts": 32,
        "models": [
            model_binding(
                "gpt-5.6-luna", "gpt-5.6-luna",
                input_rate=1_000_000, output_rate=6_000_000,
            ),
            model_binding(
                "gpt-5.6-terra", "gpt-5.6-terra",
                input_rate=2_500_000, output_rate=15_000_000,
            ),
        ],
        "prompt_version": PROMPT_VERSION,
        "retention_days": 3,
        "sample_sha256": hashes["sample_sha256"],
        "schema_sha256": evaluation_schema_sha256(),
        "source_scope": "pseudonymous_rich_semantic_labeled_sample",
    }
    record.update(overrides)
    return record


def write_approval(root: Path, sample: list[dict[str, object]], **overrides: object) -> Path:
    path = root / "approval.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(approval_record(sample, **overrides)), encoding="utf-8")
    return path


class RichSemanticEvaluationGoldFixtureTests(unittest.TestCase):
    def test_v5_fixture_has_ten_sorted_unique_cases_and_full_taxonomy(self) -> None:
        sample = load_v5_gold_fixture()

        case_refs = tuple(item["case_ref"] for item in sample)
        self.assertEqual(case_refs, V5_GOLD_CASE_REFS)
        self.assertEqual(len(case_refs), 10)
        self.assertEqual(len(set(case_refs)), 10)
        for item in sample:
            label = item["label"]
            taxonomy = label["semantic_taxonomy"]
            self.assertEqual(set(taxonomy["project"]), set(PROJECT_FIELDS))
            self.assertEqual(set(taxonomy["career"]), set(CAREER_FIELDS))
            self.assertEqual(
                set(label["source_families_by_dimension"]),
                set(ALL_DIMENSIONS),
            )

    def test_v5_fixture_covers_source_families_and_required_edge_cases(self) -> None:
        sample = load_v5_gold_fixture()
        cases = {item["case_ref"]: item for item in sample}
        populated_families = {
            family
            for item in sample
            for family, packets in item["evidence"].items()
            if packets
        }
        self.assertEqual(
            populated_families,
            {"application", "career", "devpost", "projects"},
        )

        no_evidence = cases[V5_GOLD_CASE_REFS[3]]
        self.assertTrue(all(not packets for packets in no_evidence["evidence"].values()))
        self.assertEqual(no_evidence["label"]["builder_level"], "insufficient")
        self.assertEqual(
            no_evidence["label"]["semantic_taxonomy"]["project"][
                "external_validation"
            ],
            "unknown",
        )
        self.assertTrue(all(
            not families
            for families in no_evidence["label"][
                "source_families_by_dimension"
            ].values()
        ))

        devpost_only = cases[V5_GOLD_CASE_REFS[4]]
        self.assertEqual(
            {family for family, packets in devpost_only["evidence"].items() if packets},
            {"devpost"},
        )
        self.assertEqual(
            devpost_only["label"]["semantic_taxonomy"]["project"][
                "product_maturity"
            ],
            "working_product",
        )
        self.assertEqual(
            devpost_only["label"]["semantic_taxonomy"]["project"][
                "execution_scope"
            ],
            "unknown",
        )

        career_only = cases[V5_GOLD_CASE_REFS[6]]
        self.assertEqual(
            {family for family, packets in career_only["evidence"].items() if packets},
            {"career"},
        )
        self.assertEqual(career_only["label"]["builder_level"], "insufficient")
        self.assertEqual(
            career_only["label"]["semantic_taxonomy"]["project"][
                "external_validation"
            ],
            "unknown",
        )
        self.assertEqual(
            career_only["label"]["semantic_taxonomy"]["career"]["career_stage"],
            "senior",
        )

        mixed_positive = cases[V5_GOLD_CASE_REFS[8]]
        self.assertEqual(
            {family for family, packets in mixed_positive["evidence"].items() if packets},
            {"application", "devpost", "projects"},
        )
        self.assertEqual(mixed_positive["label"]["builder_level"], "standout")
        self.assertEqual(
            mixed_positive["label"]["semantic_taxonomy"]["project"][
                "product_maturity"
            ],
            "production_evidence",
        )

        false_positive_trap = cases[V5_GOLD_CASE_REFS[0]]
        self.assertEqual(false_positive_trap["label"]["builder_level"], "exploratory")
        self.assertEqual(
            false_positive_trap["label"]["semantic_taxonomy"]["project"],
            {
                "product_maturity": "prototype",
                "technical_depth": "basic",
                "execution_scope": "unknown",
                "external_validation": "none_observed",
                "problem_differentiation": "derivative",
                "market_domains": [],
                "technical_methods": [],
                "demonstrated_capabilities": ["frontend_engineering"],
            },
        )
        self.assertIn("tutorial_or_template", false_positive_trap["label"]["reason_codes"])

    def test_v5_fixture_controlled_lists_are_sorted_and_unique(self) -> None:
        for item in load_v5_gold_fixture():
            label = item["label"]
            taxonomy = label["semantic_taxonomy"]
            controlled_lists = [
                label["reason_codes"],
                taxonomy["project"]["market_domains"],
                taxonomy["project"]["technical_methods"],
                taxonomy["project"]["demonstrated_capabilities"],
                taxonomy["career"]["career_functions"],
                taxonomy["career"]["career_delivery"],
                *label["source_families_by_dimension"].values(),
            ]
            for values in controlled_lists:
                self.assertEqual(values, sorted(set(values)))
            for project in item["evidence"]["projects"]:
                self.assertEqual(
                    project["productization_codes"],
                    sorted(set(project["productization_codes"])),
                )
                self.assertEqual(
                    project["topic_codes"],
                    sorted(set(project["topic_codes"])),
                )
            for devpost in item["evidence"]["devpost"]:
                self.assertEqual(
                    devpost["technology_codes"],
                    sorted(set(devpost["technology_codes"])),
                )

    def test_v5_blind_adjudication_corrections_are_preserved(self) -> None:
        cases = {item["case_ref"]: item for item in load_v5_gold_fixture()}

        bounded_runtime = cases[V5_GOLD_CASE_REFS[2]]["label"]
        self.assertNotIn(
            "awards_or_recognition",
            bounded_runtime["reason_codes"],
        )

        broad_systems = cases[V5_GOLD_CASE_REFS[7]]["label"]
        self.assertEqual(
            broad_systems["semantic_taxonomy"]["project"]["technical_depth"],
            "advanced",
        )
        self.assertEqual(
            broad_systems["semantic_taxonomy"]["project"][
                "problem_differentiation"
            ],
            "differentiated",
        )

        design_only = cases[V5_GOLD_CASE_REFS[9]]["label"]
        self.assertEqual(
            design_only["semantic_taxonomy"]["project"]["execution_scope"],
            "unknown",
        )
        self.assertEqual(
            design_only["source_families_by_dimension"]["execution_scope"],
            [],
        )
        self.assertEqual(
            design_only["semantic_taxonomy"]["career"]["career_delivery"],
            [],
        )
        self.assertEqual(
            design_only["source_families_by_dimension"]["career_delivery"],
            [],
        )
        self.assertNotIn("end_to_end_delivery", design_only["reason_codes"])

    def test_v5_depth_and_problem_contrasts_are_preserved(self) -> None:
        cases = {item["case_ref"]: item for item in load_v5_gold_fixture()}
        expected = {
            V5_GOLD_CASE_REFS[1]: ("moderate", "derivative"),
            V5_GOLD_CASE_REFS[4]: ("moderate", "ordinary"),
            V5_GOLD_CASE_REFS[5]: ("advanced", "ordinary"),
            V5_GOLD_CASE_REFS[7]: ("advanced", "differentiated"),
            V5_GOLD_CASE_REFS[9]: ("advanced", "ambitious"),
        }

        for case_ref, contrast in expected.items():
            project = cases[case_ref]["label"]["semantic_taxonomy"]["project"]
            with self.subTest(case_ref=case_ref):
                self.assertEqual(
                    (project["technical_depth"], project["problem_differentiation"]),
                    contrast,
                )

    def test_v5_gold_reconstructs_valid_assessments_and_partner_metrics(self) -> None:
        sample = load_v5_gold_fixture()

        self.assertEqual(labeled_sample_hashes(sample), V5_GOLD_HASHES)
        for item in sample:
            normalized_evidence = validate_profile_evidence(item["evidence"])
            self.assertEqual(normalized_evidence, item["evidence"])
            assessment_value = assessment_from_v5_gold_case(item)
            validated = validate_rich_semantic_assessment(
                assessment_value,
                evidence=normalized_evidence,
            )
            label = item["label"]
            taxonomy = validated["semantic_taxonomy"]
            self.assertEqual(
                taxonomy["project"],
                label["semantic_taxonomy"]["project"],
            )
            self.assertEqual(
                taxonomy["career"],
                label["semantic_taxonomy"]["career"],
            )
            for dimension in ALL_DIMENSIONS:
                actual_families = sorted({
                    reference_source_family(reference)
                    for reference in taxonomy["evidence_by_dimension"][dimension]
                })
                self.assertEqual(
                    actual_families,
                    label["source_families_by_dimension"][dimension],
                    f'{item["case_ref"]} {dimension}',
                )
            self.assertEqual(
                matching_metric_keys({
                    "builder_level": validated["builder_level"],
                    "execution_scope": validated["execution_scope"],
                    "external_validation": validated["external_validation"],
                    "originality": validated["originality"],
                    "product_maturity": validated["product_maturity"],
                    "technical_depth": validated["technical_depth"],
                }),
                V5_EXPECTED_PARTNER_METRICS[item["case_ref"]],
            )

    def test_v5_fixture_is_identifier_free(self) -> None:
        sample = load_v5_gold_fixture()
        serialized = json.dumps(sample, ensure_ascii=False)

        self.assertIsNone(re.search(r"https?://|www\.", serialized, re.IGNORECASE))
        self.assertIsNone(re.search(
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            serialized,
            re.IGNORECASE,
        ))
        self.assertIsNone(re.search(r"(?<![\w])@[A-Za-z0-9_]", serialized))
        self.assertIsNone(V5_NAMED_ENTITY_PATTERN.search(serialized))

        violations: list[str] = []
        serialized_casefold = serialized.casefold()
        leaked_literals = sorted(
            literal
            for literal in V5_FORBIDDEN_REAL_WORLD_LITERALS
            if literal in serialized_casefold
        )
        if leaked_literals:
            violations.append(f"real-world literals: {leaked_literals}")
        for item in sample:
            case_ref = item["case_ref"]
            actual_excerpts = free_text_excerpts(item)
            expected_excerpts = V5_SYNTHETIC_EXCERPT_CONTRACT[case_ref]
            for excerpt_key in sorted(set(actual_excerpts) | set(expected_excerpts)):
                if actual_excerpts.get(excerpt_key) != expected_excerpts.get(excerpt_key):
                    violations.append(f"{case_ref} {excerpt_key}")
        self.assertEqual(violations, [])

        def scan_keys(value: object) -> None:
            if isinstance(value, dict):
                self.assertFalse(
                    V5_FORBIDDEN_IDENTITY_KEYS.intersection(value),
                    V5_FORBIDDEN_IDENTITY_KEYS.intersection(value),
                )
                for nested in value.values():
                    scan_keys(nested)
            elif isinstance(value, list):
                for nested in value:
                    scan_keys(nested)

        scan_keys(sample)
        for item in sample:
            self.assertEqual(
                validate_profile_evidence(item["evidence"]),
                item["evidence"],
            )


class RichSemanticEvaluationStoreTests(unittest.TestCase):
    def create_store(
        self, directory: str, sample: list[dict[str, object]], *,
        clock=lambda: NOW, **approval_overrides: object,
    ) -> RichSemanticEvaluationStore:
        root = Path(directory) / "rich-semantic-evaluation"
        approval_path = write_approval(root, sample, **approval_overrides)
        return RichSemanticEvaluationStore(
            root,
            release_root=Path(directory) / "protected-operator",
            approval_path=approval_path,
            labeled_sample=sample,
            clock=clock,
        )

    def test_exact_hash_bound_sample_and_model_posture_create_restrictive_store(self) -> None:
        sample = [case(1), case(2, builder="exploratory", maturity="prototype")]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)

            self.assertEqual(store.root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(store.results.stat().st_mode & 0o777, 0o700)
            self.assertEqual(store.attempts.stat().st_mode & 0o777, 0o700)
            self.assertEqual(store.approval_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(store.approval.sample_sha256, labeled_sample_hashes(sample)["sample_sha256"])

    def test_stale_v4_evaluation_approval_is_rejected(self) -> None:
        sample = [case(1)]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(PermissionError, "approval scope"):
                self.create_store(
                    directory, sample,
                    evaluation_version="rich-semantic-model-evaluation-v4",
                )

    def test_changed_label_evidence_or_model_binding_fails_closed(self) -> None:
        sample = [case(1)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rich-semantic-evaluation"
            approval_path = write_approval(root, sample)
            changed_label = [case(1, builder="standout")]
            with self.assertRaisesRegex(PermissionError, "sample"):
                RichSemanticEvaluationStore(
                    root, release_root=Path(directory) / "protected-operator",
                    approval_path=approval_path, labeled_sample=changed_label,
                    clock=lambda: NOW,
                )

            changed_evidence = json.loads(json.dumps(sample))
            changed_evidence[0]["evidence"]["projects"][0][
                "description_excerpt"
            ] += " Changed."
            with self.assertRaisesRegex(PermissionError, "sample"):
                RichSemanticEvaluationStore(
                    root, release_root=Path(directory) / "protected-operator",
                    approval_path=approval_path, labeled_sample=changed_evidence,
                    clock=lambda: NOW,
                )

            record = approval_record(sample)
            record["models"][0]["store"] = True
            approval_path.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(PermissionError, "approval"):
                RichSemanticEvaluationStore(
                    root, release_root=Path(directory) / "protected-operator",
                    approval_path=approval_path, labeled_sample=sample,
                    clock=lambda: NOW,
                )

    def test_v5_gold_contract_rejects_stale_labels_wrong_lists_and_sources(self) -> None:
        sample = [case(1)]
        baseline = labeled_sample_hashes(sample)
        changed = json.loads(json.dumps(sample))
        changed[0]["label"]["semantic_taxonomy"]["project"][
            "market_domains"
        ] = ["enterprise_operations"]

        self.assertNotEqual(
            baseline["labels_sha256"], labeled_sample_hashes(changed)["labels_sha256"],
        )

        stale_v4 = json.loads(json.dumps(sample))
        stale_v4[0]["label"] = {
            "builder_level": "substantial",
            "execution_scope": "substantial_contributor",
            "product_maturity": "working_product",
            "required_reason_codes": ["shipped_working_product"],
            "supporting_source_families": ["application", "projects"],
            "technical_depth": "advanced",
            "uncertainty_state": "resolved",
        }
        with self.assertRaisesRegex(ValueError, "label fields"):
            labeled_sample_hashes(stale_v4)

        incoherent = json.loads(json.dumps(sample))
        incoherent[0]["label"]["builder_level"] = "standout"
        with self.assertRaisesRegex(ValueError, "gold label"):
            labeled_sample_hashes(incoherent)

        wrong_project_list = json.loads(json.dumps(sample))
        wrong_project_list[0]["label"]["semantic_taxonomy"]["project"][
            "market_domains"
        ] = ["software_engineering"]
        with self.assertRaisesRegex(ValueError, "taxonomy"):
            labeled_sample_hashes(wrong_project_list)

        wrong_career_list = json.loads(json.dumps(sample))
        wrong_career_list[0]["label"]["semantic_taxonomy"]["career"][
            "career_functions"
        ] = ["backend_engineering"]
        with self.assertRaisesRegex(ValueError, "taxonomy"):
            labeled_sample_hashes(wrong_career_list)

        wrong_dimension_source = json.loads(json.dumps(sample))
        wrong_dimension_source[0]["label"]["source_families_by_dimension"][
            "technical_depth"
        ] = ["career"]
        with self.assertRaisesRegex(ValueError, "taxonomy"):
            labeled_sample_hashes(wrong_dimension_source)

        non_string_source = json.loads(json.dumps(sample))
        non_string_source[0]["label"]["source_families_by_dimension"][
            "technical_depth"
        ] = [[]]
        with self.assertRaisesRegex(ValueError, "taxonomy"):
            labeled_sample_hashes(non_string_source)

        unsupported_authorship = json.loads(json.dumps(sample))
        unsupported_authorship[0]["evidence"]["application"] = []
        for dimension, families in unsupported_authorship[0]["label"][
            "source_families_by_dimension"
        ].items():
            unsupported_authorship[0]["label"][
                "source_families_by_dimension"
            ][dimension] = [family for family in families if family != "application"]
        unsupported_authorship[0]["label"]["source_families_by_dimension"][
            "execution_scope"
        ] = ["projects"]
        with self.assertRaisesRegex(ValueError, "gold label"):
            labeled_sample_hashes(unsupported_authorship)

    def test_cleanup_deletes_expired_results_but_not_live_attempt_budget(self) -> None:
        sample = [case(1)]
        current = [NOW]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, clock=lambda: current[0])
            store.begin_provider_attempt(model="gpt-5.6-luna", case_ref=sample[0]["case_ref"])
            store.put_result(
                model="gpt-5.6-luna", case_ref=sample[0]["case_ref"],
                value={"assessment": assessment(), "input_tokens": 100,
                       "output_tokens": 20, "cost_usd_micros": 220},
            )
            self.assertEqual(len(list(store.results.glob("*.json"))), 1)

            current[0] = NOW + timedelta(days=4)
            receipt = store.cleanup_expired()

            self.assertEqual(receipt["deleted_count"], 1)
            self.assertEqual(list(store.results.glob("*.json")), [])
            self.assertEqual(len(list(store.attempts.glob("*.json"))), 1)
            self.assertEqual((store.root / "cleanup-receipt.json").stat().st_mode & 0o777, 0o600)

    def test_result_requires_reserved_attempt_and_bound_cost_accounting(self) -> None:
        sample = [case(1)]
        value = {
            "assessment": assessment(), "input_tokens": 100,
            "output_tokens": 20, "cost_usd_micros": 220,
        }
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)
            with self.assertRaisesRegex(PermissionError, "attempt"):
                store.put_result(
                    model="gpt-5.6-luna", case_ref=sample[0]["case_ref"], value=value,
                )

            store.begin_provider_attempt(
                model="gpt-5.6-luna", case_ref=sample[0]["case_ref"],
            )
            with self.assertRaisesRegex(PermissionError, "cost"):
                store.put_result(
                    model="gpt-5.6-luna", case_ref=sample[0]["case_ref"],
                    value={**value, "cost_usd_micros": 219},
                )
            record = store.put_result(
                model="gpt-5.6-luna", case_ref=sample[0]["case_ref"], value=value,
            )
            self.assertEqual(record["value"]["cost_usd_micros"], 220)

            self.assertEqual(
                store.get_result(
                    model="gpt-5.6-luna", case_ref=sample[0]["case_ref"],
                ),
                value,
            )

    def test_output_token_limit_has_a_sanitized_bounded_cost_receipt(self) -> None:
        sample = [case(1)]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)
            attempt = store.begin_provider_attempt(
                model="gpt-5.6-luna", case_ref=sample[0]["case_ref"],
            )

            receipt = store.put_failed_attempt(
                model="gpt-5.6-luna",
                case_ref=sample[0]["case_ref"],
                attempt_number=attempt,
                failure_code="output_token_limit",
                model_version="gpt-5.6-luna",
                usage={"input_tokens": 100, "output_tokens": 4_000},
            )

            self.assertEqual(receipt["failure_code"], "output_token_limit")
            self.assertEqual(receipt["cost_usd_micros"], 24_100)
            self.assertEqual(
                set(receipt), RichSemanticEvaluationStore._FAILED_ATTEMPT_FIELDS,
            )

            second = store.begin_provider_attempt(
                model="gpt-5.6-luna", case_ref=sample[0]["case_ref"],
            )
            with self.assertRaisesRegex(PermissionError, "metadata"):
                store.put_failed_attempt(
                    model="gpt-5.6-luna",
                    case_ref=sample[0]["case_ref"],
                    attempt_number=second,
                    failure_code="provider_free_text",
                    model_version="gpt-5.6-luna",
                    usage={"input_tokens": 100, "output_tokens": 10},
                )

    def test_store_enforces_per_model_case_retry_ceiling(self) -> None:
        sample = [case(1)]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)
            for _ in range(2):
                store.begin_provider_attempt(
                    model="gpt-5.6-luna", case_ref=sample[0]["case_ref"],
                )
            with self.assertRaisesRegex(PermissionError, "case retry ceiling"):
                store.begin_provider_attempt(
                    model="gpt-5.6-luna", case_ref=sample[0]["case_ref"],
                )

    def test_deleted_trailing_attempt_is_reconstructed_and_still_consumes_budget(self) -> None:
        sample = [case(1)]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(
                directory, sample, max_attempts_per_case=1,
            )
            number = store.begin_provider_attempt(
                model="gpt-5.6-luna", case_ref=sample[0]["case_ref"],
            )
            attempt_path = store.attempts / f"{number:06d}.json"
            attempt_path.unlink()

            with self.assertRaisesRegex(PermissionError, "case retry ceiling"):
                store.begin_provider_attempt(
                    model="gpt-5.6-luna", case_ref=sample[0]["case_ref"],
                )

            self.assertTrue(attempt_path.is_file())
            self.assertEqual(store.attempt_state.stat().st_mode & 0o777, 0o600)
            state = json.loads(store.attempt_state.read_text(encoding="utf-8"))
            self.assertEqual(state["high_watermark"], 1)
            self.assertEqual(len(state["reservations"]), 1)

    def test_scheduled_cleanup_works_after_approval_expiry_in_fresh_process(self) -> None:
        sample = [case(1)]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)
            store.begin_provider_attempt(
                model="gpt-5.6-luna", case_ref=sample[0]["case_ref"],
            )
            store.put_result(
                model="gpt-5.6-luna", case_ref=sample[0]["case_ref"],
                value={
                    "assessment": assessment(), "input_tokens": 100,
                    "output_tokens": 20, "cost_usd_micros": 220,
                },
            )

            receipt = cleanup_expired_rich_semantic_evaluation(
                store.root, release_root=Path(directory) / "protected-operator",
                now=NOW + timedelta(days=8),
            )

            self.assertEqual(receipt["deleted_count"], 3)
            self.assertEqual(list(store.results.glob("*.json")), [])
            self.assertEqual(list(store.attempts.glob("*.json")), [])
            self.assertTrue(store.approval_path.exists())
            self.assertEqual((store.root / "cleanup-receipt.json").stat().st_mode & 0o777, 0o600)


class RichSemanticEvaluatorTests(unittest.TestCase):
    def create_store(
        self, directory: str, sample: list[dict[str, object]], *,
        clock=lambda: NOW, **approval_overrides: object,
    ) -> RichSemanticEvaluationStore:
        root = Path(directory) / "rich-semantic-evaluation"
        return RichSemanticEvaluationStore(
            root,
            release_root=Path(directory) / "protected-operator",
            approval_path=write_approval(root, sample, **approval_overrides),
            labeled_sample=sample,
            clock=clock,
        )

    @staticmethod
    def runner(
        version: str,
        predictions: list[tuple[str, str] | dict[str, object]], *,
        tokens: tuple[int, int],
    ):
        model = "gpt-5.6-luna" if "luna" in version else "gpt-5.6-terra"
        return OpenAIRichSemanticAssessmentProvider(
            api_key="fixture-key-not-secret",
            sleeper=lambda _seconds: None,
            known_identity_literals=KNOWN_IDENTITY_LITERALS,
            model=model,
            reasoning_effort="low",
            transport=ProviderResponsesTransport(
                version, predictions, tokens=tokens,
            ),
            region="global",
        )

    def test_real_openai_provider_runs_through_evaluation_harness(self) -> None:
        sample = [
            case(1),
            case(2, builder="exploratory", maturity="prototype"),
        ]
        luna_transport = ProviderResponsesTransport(
            "gpt-5.6-luna", [
                ("substantial", "working_product"),
                ("exploratory", "prototype"),
            ],
        )
        terra_transport = ProviderResponsesTransport(
            "gpt-5.6-terra", [
                ("substantial", "working_product"),
                ("exploratory", "prototype"),
            ],
        )
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": OpenAIRichSemanticAssessmentProvider(
                        api_key="fixture-key-not-secret",
                        sleeper=lambda _seconds: None,
                        known_identity_literals=KNOWN_IDENTITY_LITERALS,
                        model="gpt-5.6-luna",
                        reasoning_effort="low",
                        transport=luna_transport,
                        region="global",
                    ),
                    "gpt-5.6-terra": OpenAIRichSemanticAssessmentProvider(
                        api_key="fixture-key-not-secret",
                        sleeper=lambda _seconds: None,
                        known_identity_literals=KNOWN_IDENTITY_LITERALS,
                        model="gpt-5.6-terra",
                        reasoning_effort="low",
                        transport=terra_transport,
                        region="global",
                    ),
                },
            )

            self.assertEqual(report["recommended_model"], "gpt-5.6-luna")
            self.assertEqual(luna_transport.requests, 2)
            self.assertEqual(terra_transport.requests, 2)

    def test_single_model_diagnostic_is_exactly_bound_and_can_meet_threshold(self) -> None:
        sample = [
            case(1),
            case(2, builder="exploratory", maturity="prototype"),
        ]
        bindings = approval_record(sample)["models"][:1]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)

            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna",
                        [
                            ("substantial", "working_product"),
                            ("exploratory", "prototype"),
                        ],
                        tokens=(10, 5),
                    ),
                },
            )

            self.assertEqual(
                report["report_version"], "rich-semantic-evaluation-report-v9",
            )
            self.assertEqual(
                report["recommendation_policy_sha256"],
                recommendation_policy_sha256(),
            )
            self.assertEqual(
                report["partner_report_taxonomy_schema_sha256"],
                partner_report_taxonomy_schema_sha256(),
            )
            self.assertEqual(report["recommended_model"], "gpt-5.6-luna")
            self.assertEqual(len(report["models"]), 1)

    def test_report_flattens_all_v5_fields_and_detects_taxonomy_differences(self) -> None:
        sample = [case(1)]
        sample[0]["evidence"]["devpost"] = [{
            "demo_state": "observed",
            "evidence_code": "devpost_01",
            "evidence_refs": ["devpost_01:project", "devpost_01:demo"],
            "project_excerpt": "A reviewed working submission with a live demo.",
            "submission_state": "submitted",
            "technology_codes": ["applied_ai"],
        }]
        label = sample[0]["label"]
        label["cross_source_confidence"] = "medium"
        label["reason_codes"] = [
            "advanced_system_design", "shipped_working_product",
        ]
        label["semantic_taxonomy"]["project"]["technical_depth"] = "exceptional"
        label["semantic_taxonomy"]["project"]["market_domains"] = [
            "enterprise_operations",
        ]
        label["source_families_by_dimension"]["product_maturity"] = [
            "application", "devpost", "projects",
        ]
        bindings = approval_record(sample)["models"][:1]
        prediction = assessment()

        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna", [prediction], tokens=(10, 5),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["builder_agreement_basis_points"], 10_000)
            self.assertEqual(model["maturity_agreement_basis_points"], 10_000)
            self.assertEqual(model["joint_agreement_basis_points"], 0)
            expected_agreement = {key: 10_000 for key in FLATTENED_LABEL_KEYS}
            for key in (
                "cross_source_confidence", "reason_codes",
                "project.technical_depth", "project.market_domains",
                "sources.product_maturity",
            ):
                expected_agreement[key] = 0
            self.assertEqual(
                list(model["field_agreement_basis_points"]),
                list(FLATTENED_LABEL_KEYS),
            )
            self.assertEqual(model["field_agreement_basis_points"], expected_agreement)
            self.assertEqual(
                model["disagreements"][0]["field_matches"],
                {key: basis_points == 10_000 for key, basis_points in expected_agreement.items()},
            )
            self.assertIsNone(report["recommended_model"])
            self.assertEqual(
                report["selection_reason"],
                "no_model_met_report_scalar_minimum_floor",
            )

    def test_extra_reason_code_remains_diagnostic_when_release_scalars_match(self) -> None:
        sample = [
            case(1),
            case(2, builder="exploratory", maturity="prototype"),
        ]
        bindings = approval_record(sample)["models"][:1]
        prediction = assessment()
        prediction["reason_codes"] = sorted({
            *prediction["reason_codes"], "tutorial_or_template",
        })
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna",
                        [
                            prediction,
                            assessment(
                                builder="exploratory", maturity="prototype",
                            ),
                        ],
                        tokens=(10, 5),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(
                model["field_agreement_basis_points"]["reason_codes"],
                5_000,
            )
            self.assertEqual(model["joint_agreement_basis_points"], 5_000)
            self.assertEqual(report["recommended_model"], "gpt-5.6-luna")
            self.assertEqual(model["report_scalar_minimum_basis_points"], 10_000)
            self.assertEqual(model["partner_metric_recall_basis_points"], 10_000)

    def test_source_family_variance_is_diagnostic_but_provenance_stays_visible(self) -> None:
        sample = [
            case(1),
            case(2, builder="exploratory", maturity="prototype"),
        ]
        sample[0]["label"]["source_families_by_dimension"][
            "technical_depth"
        ] = ["application"]
        bindings = approval_record(sample)["models"][:1]

        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna",
                        [
                            assessment(),
                            assessment(
                                builder="exploratory", maturity="prototype",
                            ),
                        ],
                        tokens=(10, 5),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(
                model["field_agreement_basis_points"]["sources.technical_depth"],
                5_000,
            )
            self.assertTrue(
                model["disagreements"][0]["field_matches"]["sources.product_maturity"],
            )
            self.assertFalse(
                model["disagreements"][0]["field_matches"]["sources.technical_depth"],
            )
            self.assertEqual(report["recommended_model"], "gpt-5.6-luna")
            self.assertEqual(
                model["mandatory_review_coverage_basis_points"], 10_000,
            )
            self.assertEqual(model["material_public_error_case_count"], 0)
            self.assertEqual(model["correction_case_count"], 1)
            self.assertEqual(model["expected_human_escalation_case_count"], 1)

    def test_partner_metric_precision_below_threshold_blocks_recommendation(self) -> None:
        sample = [
            case(index, builder="exploratory", maturity="prototype")
            for index in range(1, 11)
        ]
        for sample_case in sample[:3]:
            sample_case["label"]["semantic_taxonomy"]["project"][
                "technical_depth"
            ] = "basic"
        bindings = approval_record(sample)["models"][:1]
        predictions = [
            assessment(builder="exploratory", maturity="prototype")
            for _ in sample
        ]

        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna", predictions, tokens=(10, 5),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["joint_agreement_basis_points"], 7_000)
            self.assertEqual(model["impressive_false_positive_count"], 0)
            self.assertEqual(model["impressive_false_negative_count"], 0)
            self.assertEqual(model["partner_metric_false_positive_count"], 3)
            self.assertEqual(model["partner_metric_false_negative_count"], 0)
            self.assertEqual(model["partner_metric_precision_basis_points"], 7_000)
            self.assertIsNone(report["recommended_model"])
            self.assertEqual(
                report["selection_reason"],
                "no_model_met_partner_metric_precision_threshold",
            )

    def test_reviewed_taxonomy_false_positive_can_pass_when_precision_is_high(self) -> None:
        sample = [
            *[case(index) for index in range(1, 5)],
            case(5, builder="exploratory", maturity="prototype"),
        ]
        bindings = approval_record(sample)["models"][:1]
        predictions = [
            *[assessment() for _ in range(4)],
            assessment(builder="exploratory", maturity="prototype"),
        ]
        predictions[0]["semantic_taxonomy"]["project"]["market_domains"] = [
            "education_learning", "healthcare_life_sciences",
        ]

        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna", predictions, tokens=(10, 5),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["partner_taxonomy_false_positive_count"], 1)
            self.assertEqual(model["partner_taxonomy_false_negative_count"], 0)
            self.assertGreaterEqual(
                model["partner_taxonomy_precision_basis_points"], 8_000,
            )
            self.assertEqual(model["material_public_error_case_count"], 1)
            self.assertEqual(model["correction_case_count"], 1)
            self.assertEqual(model["expected_human_escalation_case_count"], 1)
            self.assertEqual(model["mandatory_review_case_count"], 5)
            self.assertEqual(
                model["mandatory_review_coverage_basis_points"], 10_000,
            )
            self.assertEqual(report["recommended_model"], "gpt-5.6-luna")
            self.assertEqual(
                report["selection_reason"],
                "proposal_quality_thresholds_met_mandatory_human_review_"
                "before_release_ranked_by_quality_then_escalation_then_cost",
            )

    def test_partner_taxonomy_precision_below_threshold_blocks_recommendation(self) -> None:
        sample = [case(index) for index in range(1, 6)]
        bindings = approval_record(sample)["models"][:1]
        predictions = [assessment() for _ in sample]
        for prediction in predictions:
            prediction["semantic_taxonomy"]["project"]["market_domains"] = [
                "climate_energy",
                "education_learning",
                "financial_services",
                "healthcare_life_sciences",
            ]

        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna", predictions, tokens=(10, 5),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["partner_taxonomy_false_positive_count"], 15)
            self.assertLess(model["partner_taxonomy_precision_basis_points"], 8_000)
            self.assertIsNone(report["recommended_model"])
            self.assertEqual(
                report["selection_reason"],
                "no_model_met_partner_taxonomy_precision_threshold",
            )

    def test_bounded_conservative_partner_metric_misses_can_pass_with_full_review(self) -> None:
        sample = [
            *[case(index) for index in range(1, 6)],
            case(6, builder="exploratory", maturity="prototype"),
        ]
        bindings = approval_record(sample)["models"][:1]
        predictions = [
            *[assessment() for _ in range(5)],
            assessment(builder="exploratory", maturity="prototype"),
        ]
        predictions[0]["technical_depth"] = "basic"
        predictions[0]["semantic_taxonomy"] = semantic_taxonomy_for_assessment(
            predictions[0],
        )

        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna", predictions, tokens=(10, 5),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["partner_metric_false_positive_count"], 0)
            self.assertEqual(model["partner_metric_false_negative_count"], 3)
            self.assertGreaterEqual(model["partner_metric_recall_basis_points"], 8_000)
            self.assertGreaterEqual(model["report_scalar_minimum_basis_points"], 8_000)
            self.assertEqual(
                model["mandatory_review_coverage_basis_points"], 10_000,
            )
            self.assertEqual(report["recommended_model"], "gpt-5.6-luna")

    def test_weakest_report_scalar_can_use_the_documented_seven_thousand_floor(self) -> None:
        sample = [
            *[case(index) for index in range(1, 10)],
            case(10, builder="exploratory", maturity="prototype"),
        ]
        bindings = approval_record(sample)["models"][:1]
        predictions = [
            *[assessment() for _ in range(9)],
            assessment(builder="exploratory", maturity="prototype"),
        ]
        for prediction in predictions[:3]:
            prediction["originality"] = "unknown"
            prediction["semantic_taxonomy"] = semantic_taxonomy_for_assessment(
                prediction,
            )

        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna", predictions, tokens=(10, 5),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["report_scalar_minimum_basis_points"], 7_000)
            self.assertGreaterEqual(
                model["report_scalar_agreement_basis_points"], 8_000,
            )
            self.assertEqual(report["recommended_model"], "gpt-5.6-luna")

    def test_report_scalar_below_the_documented_floor_blocks_recommendation(self) -> None:
        sample = [case(index) for index in range(1, 11)]
        bindings = approval_record(sample)["models"][:1]
        predictions = [assessment() for _ in sample]
        for prediction in predictions[:4]:
            prediction["originality"] = "unknown"
            prediction["semantic_taxonomy"] = semantic_taxonomy_for_assessment(
                prediction,
            )

        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna", predictions, tokens=(10, 5),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["report_scalar_minimum_basis_points"], 6_000)
            self.assertIsNone(report["recommended_model"])
            self.assertEqual(
                report["selection_reason"],
                "no_model_met_report_scalar_minimum_floor",
            )

    def test_taxonomy_recall_can_use_the_documented_seven_thousand_floor(self) -> None:
        sample = [
            *[case(index) for index in range(1, 10)],
            case(10, builder="exploratory", maturity="prototype"),
        ]
        bindings = approval_record(sample)["models"][:1]
        predictions = [
            *[assessment() for _ in range(9)],
            assessment(builder="exploratory", maturity="prototype"),
        ]
        for prediction in predictions[:4]:
            for dimension in (
                "market_domains", "technical_methods",
                "demonstrated_capabilities",
            ):
                prediction["semantic_taxonomy"]["project"][dimension] = []
                prediction["semantic_taxonomy"]["evidence_by_dimension"][
                    dimension
                ] = []
        for prediction in predictions[4:8]:
            prediction["semantic_taxonomy"]["project"]["market_domains"] = []
            prediction["semantic_taxonomy"]["evidence_by_dimension"][
                "market_domains"
            ] = []

        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna", predictions, tokens=(10, 5),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["partner_taxonomy_recall_basis_points"], 7_000)
            self.assertEqual(model["partner_metric_recall_basis_points"], 10_000)
            self.assertEqual(report["recommended_model"], "gpt-5.6-luna")

    def test_taxonomy_recall_below_the_documented_floor_blocks_recommendation(self) -> None:
        sample = [case(index) for index in range(1, 11)]
        bindings = approval_record(sample)["models"][:1]
        predictions = [assessment() for _ in sample]
        for prediction in predictions[:5]:
            for dimension in (
                "market_domains", "technical_methods",
                "demonstrated_capabilities",
            ):
                prediction["semantic_taxonomy"]["project"][dimension] = []
                prediction["semantic_taxonomy"]["evidence_by_dimension"][
                    dimension
                ] = []

        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna", predictions, tokens=(10, 5),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["partner_taxonomy_recall_basis_points"], 6_875)
            self.assertIsNone(report["recommended_model"])
            self.assertEqual(
                report["selection_reason"],
                "no_model_met_partner_taxonomy_recall_floor",
            )

    def test_incorrect_negative_proposal_is_still_in_mandatory_review_and_escalation(self) -> None:
        sample = [case(1, builder="standout", maturity="production_evidence")]
        bindings = approval_record(sample)["models"][:1]
        prediction = assessment(builder="insufficient", maturity="unknown")

        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna", [prediction], tokens=(10, 5),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["mandatory_review_case_count"], 1)
            self.assertEqual(
                model["mandatory_review_coverage_basis_points"], 10_000,
            )
            self.assertEqual(model["material_public_error_case_count"], 1)
            self.assertEqual(model["correction_case_count"], 1)
            self.assertEqual(model["expected_human_escalation_case_count"], 1)
            self.assertIsNone(report["recommended_model"])

    def test_one_reviewed_impressive_false_positive_can_pass_quality_thresholds(self) -> None:
        sample = [
            case(1, builder="exploratory", maturity="prototype"),
            *[case(index) for index in range(2, 11)],
        ]
        bindings = approval_record(sample)["models"][:1]
        predictions = [assessment() for _ in sample]

        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna", predictions, tokens=(10, 5),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["impressive_false_positive_count"], 1)
            self.assertGreaterEqual(
                model["impressive_agreement_basis_points"], 8_000,
            )
            self.assertEqual(report["recommended_model"], "gpt-5.6-luna")

    def test_impressive_band_agreement_cannot_hide_full_label_disagreement(self) -> None:
        sample = [
            case(1, builder="standout", maturity="production_evidence"),
            case(2, builder="exploratory", maturity="prototype"),
        ]
        bindings = approval_record(sample)["models"][:1]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)

            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna",
                        [
                            ("substantial", "working_product"),
                            ("exploratory", "working_product"),
                        ],
                        tokens=(10, 5),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["joint_agreement_basis_points"], 0)
            self.assertEqual(model["impressive_agreement_basis_points"], 10_000)
            self.assertEqual(model["impressive_false_positive_count"], 0)
            self.assertEqual(model["impressive_false_negative_count"], 0)
            self.assertIsNone(report["recommended_model"])
            self.assertEqual(
                report["selection_reason"],
                "no_model_met_report_scalar_agreement_threshold",
            )

    def test_impressive_error_budget_rejects_one_false_negative_on_six_cases(self) -> None:
        sample = [
            case(1, builder="standout", maturity="production_evidence"),
            *[
                case(index, builder="exploratory", maturity="prototype")
                for index in range(2, 7)
            ],
        ]
        bindings = approval_record(sample)["models"][:1]
        predictions = [("exploratory", "prototype")] * 6
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)

            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna", predictions, tokens=(10, 5),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["impressive_agreement_basis_points"], 8_333)
            self.assertEqual(model["impressive_false_negative_count"], 1)
            self.assertIsNone(report["recommended_model"])
            self.assertEqual(
                report["selection_reason"],
                "no_model_met_partner_metric_recall_threshold",
            )

    def test_resume_reuses_valid_result_without_another_provider_call(self) -> None:
        sample = [case(1)]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)
            store.begin_provider_attempt(
                model="gpt-5.6-luna", case_ref=sample[0]["case_ref"],
            )
            cached = {
                "assessment": assessment(), "input_tokens": 10,
                "output_tokens": 5, "cost_usd_micros": 40,
            }
            store.put_result(
                model="gpt-5.6-luna", case_ref=sample[0]["case_ref"], value=cached,
            )
            luna_transport = ProviderResponsesTransport("gpt-5.6-luna", [])
            luna = OpenAIRichSemanticAssessmentProvider(
                api_key="fixture-key-not-secret", sleeper=lambda _seconds: None,
                known_identity_literals=KNOWN_IDENTITY_LITERALS,
                model="gpt-5.6-luna", reasoning_effort="low",
                transport=luna_transport, region="global",
            )

            RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": luna,
                    "gpt-5.6-terra": self.runner(
                        "gpt-5.6-terra", [("substantial", "working_product")],
                        tokens=(10, 5),
                    ),
                },
            )

            self.assertEqual(luna_transport.requests, 0)

    def test_domain_invalid_model_output_consumes_bounded_retry(self) -> None:
        sample = [case(1)]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)
            luna_transport = ProviderResponsesTransport(
                "gpt-5.6-luna",
                [
                    ("substantial", "not_a_maturity"),
                    ("substantial", "working_product"),
                ],
            )
            luna = OpenAIRichSemanticAssessmentProvider(
                api_key="fixture-key-not-secret", sleeper=lambda _seconds: None,
                known_identity_literals=KNOWN_IDENTITY_LITERALS,
                model="gpt-5.6-luna", reasoning_effort="low",
                transport=luna_transport, region="global",
            )

            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": luna,
                    "gpt-5.6-terra": self.runner(
                        "gpt-5.6-terra", [("substantial", "working_product")],
                        tokens=(10, 5),
                    ),
                },
            )

            self.assertEqual(luna_transport.requests, 2)
            self.assertEqual(report["models"][0]["joint_agreement_basis_points"], 10_000)

    def test_invalid_completed_output_is_receipted_and_included_in_cost(self) -> None:
        sample = [case(1)]
        bindings = approval_record(sample)["models"][:1]
        invalid = assessment(confidence="high")
        invalid["builder_level"] = "invalid_tier"
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna",
                        [invalid, assessment(confidence="high")],
                        tokens=(100, 10),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["input_tokens"], 200)
            self.assertEqual(model["output_tokens"], 20)
            self.assertEqual(model["cost_usd_micros"], 320)
            self.assertEqual(model["failed_attempt_count"], 1)
            self.assertIsNone(report["recommended_model"])
            self.assertEqual(
                report["selection_reason"],
                "no_model_met_zero_failure_requirement",
            )
            receipts = list(store.failed_attempts.glob("*.json"))
            self.assertEqual(len(receipts), 1)
            receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
            self.assertEqual(
                receipt["failure_code"],
                "semantic_output_invalid_validation",
            )
            self.assertEqual(receipt["input_tokens"], 100)
            self.assertEqual(receipt["output_tokens"], 10)
            self.assertEqual(receipt["cost_usd_micros"], 160)
            self.assertEqual(receipts[0].stat().st_mode & 0o777, 0o600)
            serialized = json.dumps(receipt, sort_keys=True)
            self.assertNotIn("assessment", serialized)
            self.assertNotIn("evidence", serialized)
            self.assertNotIn("project_", serialized)

    def test_unreceipted_retry_failure_blocks_recommendation(self) -> None:
        sample = [case(1)]
        bindings = approval_record(sample)["models"][:1]
        success = ProviderResponsesTransport(
            "gpt-5.6-luna", [("substantial", "working_product")],
        )

        class FailOnceThenSucceedTransport:
            endpoint = "https://api.openai.com/v1/responses"

            def __init__(self) -> None:
                self.requests = 0

            def request(self, *, headers, body, timeout, max_bytes):
                self.requests += 1
                if self.requests == 1:
                    return HttpResponse(500, {}, b"", self.endpoint)
                return success.request(
                    headers=headers, body=body, timeout=timeout,
                    max_bytes=max_bytes,
                )

        transport = FailOnceThenSucceedTransport()
        provider = OpenAIRichSemanticAssessmentProvider(
            api_key="fixture-key-not-secret",
            sleeper=lambda _seconds: None,
            known_identity_literals=KNOWN_IDENTITY_LITERALS,
            model="gpt-5.6-luna",
            reasoning_effort="low",
            transport=transport,
            region="global",
        )
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={"gpt-5.6-luna": provider},
            )

            model = report["models"][0]
            self.assertEqual(model["failed_attempt_count"], 1)
            self.assertEqual(model["cost_usd_micros"], 40)
            self.assertEqual(list(store.failed_attempts.glob("*.json")), [])
            self.assertIsNone(report["recommended_model"])
            self.assertEqual(
                report["selection_reason"],
                "no_model_met_zero_failure_requirement",
            )

    def test_mutable_wrapper_binding_is_rejected_before_transport(self) -> None:
        sample = [case(1)]

        def wrapper(_evidence: dict[str, object]) -> dict[str, object]:
            return {
                "assessment": assessment(),
                "model_version": "gpt-5.6-luna",
                "usage": {"input_tokens": 1, "output_tokens": 1},
            }

        wrapper.evaluation_binding = runtime_binding(
            "gpt-5.6-luna", "gpt-5.6-luna",
        )
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)

            with self.assertRaisesRegex(PermissionError, "concrete OpenAI provider"):
                RichSemanticEvaluator(store).evaluate(
                    labeled_sample=sample,
                    runners={
                        "gpt-5.6-luna": wrapper,
                        "gpt-5.6-terra": self.runner(
                            "gpt-5.6-terra",
                            [("substantial", "working_product")], tokens=(1, 1),
                        ),
                    },
                )

            self.assertEqual(list(store.attempts.glob("*.json")), [])

    def test_actual_endpoint_model_reasoning_and_store_mismatches_fail_before_transport(self) -> None:
        class StoreEnabledProvider(OpenAIRichSemanticAssessmentProvider):
            @property
            def store(self) -> bool:
                return True

        scenarios = (
            ("endpoint", "gpt-5.6-luna", "low", "eu", True, False),
            ("model", "gpt-5.6-terra", "low", "global", False, False),
            ("reasoning", "gpt-5.6-luna", "none", "global", False, False),
            ("store", "gpt-5.6-luna", "low", "global", False, True),
        )
        for name, model, effort, region, use_eu_endpoint, store_value in scenarios:
            with self.subTest(binding=name), tempfile.TemporaryDirectory() as directory:
                sample = [case(1)]
                transport = ProviderResponsesTransport(
                    model, [("substantial", "working_product")],
                    endpoint=(
                        "https://eu.api.openai.com/v1/responses"
                        if use_eu_endpoint else "https://api.openai.com/v1/responses"
                    ),
                )
                provider_class = (
                    StoreEnabledProvider if store_value
                    else OpenAIRichSemanticAssessmentProvider
                )
                provider = provider_class(
                    api_key="fixture-key-not-secret",
                    sleeper=lambda _seconds: None,
                    known_identity_literals=KNOWN_IDENTITY_LITERALS,
                    model=model,
                    reasoning_effort=effort,
                    transport=transport,
                    region=region,
                )
                valid_terra_transport = ProviderResponsesTransport(
                    "gpt-5.6-terra", [("substantial", "working_product")],
                )
                store = self.create_store(directory, sample)

                with self.assertRaisesRegex(PermissionError, "runtime binding"):
                    RichSemanticEvaluator(store).evaluate(
                        labeled_sample=sample,
                        runners={
                            "gpt-5.6-luna": provider,
                            "gpt-5.6-terra": OpenAIRichSemanticAssessmentProvider(
                                api_key="fixture-key-not-secret",
                                sleeper=lambda _seconds: None,
                                known_identity_literals=KNOWN_IDENTITY_LITERALS,
                                model="gpt-5.6-terra",
                                reasoning_effort="low",
                                transport=valid_terra_transport,
                                region="global",
                            ),
                        },
                    )

                self.assertEqual(transport.requests, 0)
                self.assertEqual(valid_terra_transport.requests, 0)
                self.assertEqual(list(store.attempts.glob("*.json")), [])

    def test_report_exposes_disagreements_usage_cost_and_human_review_only_results(self) -> None:
        sample = [case(1), case(2, builder="exploratory", maturity="prototype")]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna",
                        [("substantial", "working_product"), ("insufficient", "unknown")],
                        tokens=(1_000, 100),
                    ),
                    "gpt-5.6-terra": self.runner(
                        "gpt-5.6-terra",
                        [("substantial", "working_product"), ("exploratory", "prototype")],
                        tokens=(1_000, 100),
                    ),
                },
            )

            luna = report["models"][0]
            terra = report["models"][1]
            self.assertEqual(luna["builder_agreement_basis_points"], 5_000)
            self.assertEqual(luna["maturity_agreement_basis_points"], 5_000)
            self.assertEqual(luna["input_tokens"], 2_000)
            self.assertEqual(luna["output_tokens"], 200)
            self.assertEqual(luna["cost_usd_micros"], 3_200)
            self.assertEqual(len(luna["disagreements"]), 1)
            self.assertEqual(terra["joint_agreement_basis_points"], 10_000)
            self.assertEqual(report["recommended_model"], "gpt-5.6-terra")
            self.assertEqual(report["review_state"], "human_review_required")
            self.assertFalse(report["release_eligible"])
            self.assertEqual((store.root / "evaluation-report.json").stat().st_mode & 0o777, 0o600)
            for path in store.results.glob("*.json"):
                result = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(result["value"]["assessment"]["review_state"], "human_review_required")
                self.assertFalse(result["release_eligible"])

    def test_store_rejects_tampered_model_rows_in_protected_report(self) -> None:
        sample = [case(1)]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna",
                        [("substantial", "working_product")], tokens=(1, 1),
                    ),
                    "gpt-5.6-terra": self.runner(
                        "gpt-5.6-terra",
                        [("substantial", "working_product")], tokens=(1, 1),
                    ),
                },
            )
            tampered = {**report, "models": [{"unexpected": "direct-person-data"}]}

            with self.assertRaisesRegex(PermissionError, "model rows"):
                store.write_report(tampered)

            tampered_selection = {
                **report,
                "recommended_model": "gpt-5.6-terra",
                "selection_reason": "fabricated_selection",
            }
            with self.assertRaisesRegex(PermissionError, "selection"):
                store.write_report(tampered_selection)

            tampered_policy = {
                **report,
                "recommendation_policy_sha256": "0" * 64,
            }
            with self.assertRaisesRegex(PermissionError, "policy"):
                store.write_report(tampered_policy)

    def test_zero_gold_positive_support_fails_closed_even_when_scores_are_perfect(self) -> None:
        sample = [case(1, builder="insufficient", maturity="unknown")]
        bindings = approval_record(sample)["models"][:1]
        prediction = assessment(builder="insufficient", maturity="unknown")
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna", [prediction], tokens=(1, 1),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["partner_metric_precision_basis_points"], 10_000)
            self.assertEqual(model["partner_metric_recall_basis_points"], 10_000)
            self.assertEqual(model["partner_taxonomy_precision_basis_points"], 10_000)
            self.assertEqual(model["partner_taxonomy_recall_basis_points"], 10_000)
            self.assertEqual(model["mandatory_review_case_count"], 1)
            self.assertEqual(
                model["mandatory_review_coverage_basis_points"], 10_000,
            )
            self.assertEqual(model["material_public_error_case_count"], 0)
            self.assertEqual(model["correction_case_count"], 0)
            self.assertEqual(model["expected_human_escalation_case_count"], 1)
            self.assertEqual(model["impressive_agreement_basis_points"], 10_000)
            self.assertEqual(model["report_scalar_agreement_basis_points"], 10_000)
            self.assertEqual(model["report_scalar_minimum_basis_points"], 10_000)
            self.assertEqual(model["partner_metric_expected_positive_count"], 0)
            self.assertEqual(model["partner_taxonomy_expected_positive_count"], 0)
            self.assertEqual(model["evaluation_case_count"], 1)
            self.assertEqual(model["impressive_expected_positive_count"], 0)
            self.assertEqual(model["impressive_expected_negative_count"], 1)
            self.assertIsNone(report["recommended_model"])
            self.assertEqual(
                report["selection_reason"],
                "no_model_met_partner_taxonomy_gold_support_requirement",
            )

    def test_metric_family_requires_nonzero_gold_positive_support(self) -> None:
        prediction = assessment(builder="exploratory", maturity="prototype")
        prediction["technical_depth"] = "basic"
        prediction["semantic_taxonomy"] = semantic_taxonomy_for_assessment(
            prediction,
        )
        sample = [case(1)]
        sample[0]["label"] = label_from_assessment(prediction)
        bindings = approval_record(sample)["models"][:1]

        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna", [prediction], tokens=(1, 1),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["partner_metric_expected_positive_count"], 0)
            self.assertGreater(model["partner_taxonomy_expected_positive_count"], 0)
            self.assertIsNone(report["recommended_model"])
            self.assertEqual(
                report["selection_reason"],
                "no_model_met_partner_metric_gold_support_requirement",
            )

    def test_impressive_agreement_requires_positive_and_negative_gold_classes(self) -> None:
        sample = [case(1), case(2)]
        bindings = approval_record(sample)["models"][:1]
        predictions = [assessment(), assessment()]

        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna", predictions, tokens=(1, 1),
                    ),
                },
            )

            model = report["models"][0]
            self.assertEqual(model["impressive_expected_positive_count"], 2)
            self.assertEqual(model["impressive_expected_negative_count"], 0)
            self.assertEqual(model["impressive_agreement_basis_points"], 10_000)
            self.assertIsNone(report["recommended_model"])
            self.assertEqual(
                report["selection_reason"],
                "no_model_met_impressive_gold_class_diversity_requirement",
            )

    def test_store_rejects_fabricated_threshold_and_report_window(self) -> None:
        scenarios = (
            (
                "threshold",
                lambda report: {
                    **report,
                    "agreement_threshold_basis_points": 9_999,
                },
                "threshold",
            ),
            (
                "created",
                lambda report: {
                    **report,
                    "created_at": "2099-01-01T00:00:00Z",
                },
                "window",
            ),
            (
                "expires",
                lambda report: {
                    **report,
                    "expires_at": "2099-01-02T00:00:00Z",
                },
                "window",
            ),
        )
        for name, mutate, message in scenarios:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                sample = [case(1)]
                store = self.create_store(directory, sample)
                report = RichSemanticEvaluator(store).evaluate(
                    labeled_sample=sample,
                    runners={
                        "gpt-5.6-luna": self.runner(
                            "gpt-5.6-luna",
                            [("substantial", "working_product")],
                            tokens=(1, 1),
                        ),
                        "gpt-5.6-terra": self.runner(
                            "gpt-5.6-terra",
                            [("substantial", "working_product")],
                            tokens=(1, 1),
                        ),
                    },
                )

                with self.assertRaisesRegex(PermissionError, message):
                    store.write_report(mutate(report))

    def test_no_model_is_recommended_when_either_accuracy_threshold_is_missed(self) -> None:
        sample = [case(1), case(2), case(3), case(4), case(5)]
        predictions = [
            ("substantial", "working_product"),
            ("substantial", "working_product"),
            ("substantial", "working_product"),
            ("exploratory", "prototype"),
            ("exploratory", "prototype"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna", predictions, tokens=(10, 10),
                    ),
                    "gpt-5.6-terra": self.runner(
                        "gpt-5.6-terra", predictions, tokens=(10, 10),
                    ),
                },
            )

            self.assertIsNone(report["recommended_model"])
            self.assertEqual(
                report["selection_reason"],
                "no_model_met_impressive_agreement_threshold",
            )

    def test_equal_quality_ranks_lower_escalation_burden_before_lower_cost(self) -> None:
        sample = [
            case(1),
            case(2, builder="exploratory", maturity="prototype"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna",
                        [
                            assessment(confidence="low"),
                            assessment(
                                builder="exploratory", maturity="prototype",
                            ),
                        ],
                        tokens=(1, 1),
                    ),
                    "gpt-5.6-terra": self.runner(
                        "gpt-5.6-terra",
                        [
                            assessment(confidence="high"),
                            assessment(
                                builder="exploratory", maturity="prototype",
                            ),
                        ],
                        tokens=(10, 10),
                    ),
                },
            )

            luna, terra = report["models"]
            self.assertLess(luna["cost_usd_micros"], terra["cost_usd_micros"])
            self.assertEqual(luna["expected_human_escalation_case_count"], 1)
            self.assertEqual(terra["expected_human_escalation_case_count"], 0)
            self.assertEqual(report["recommended_model"], "gpt-5.6-terra")

    def test_no_model_is_recommended_when_quality_escalation_and_cost_are_tied(self) -> None:
        sample = [
            case(1),
            case(2, builder="exploratory", maturity="prototype"),
        ]
        bindings = approval_record(sample)["models"]
        bindings[1]["input_cost_per_million_usd_micros"] = 1_000_000
        bindings[1]["output_cost_per_million_usd_micros"] = 6_000_000
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample, models=bindings)
            terra = self.runner(
                "gpt-5.6-terra",
                [
                    ("substantial", "working_product"),
                    ("exploratory", "prototype"),
                ],
                tokens=(10, 10),
            )
            report = RichSemanticEvaluator(store).evaluate(
                labeled_sample=sample,
                runners={
                    "gpt-5.6-luna": self.runner(
                        "gpt-5.6-luna",
                        [
                            ("substantial", "working_product"),
                            ("exploratory", "prototype"),
                        ],
                        tokens=(10, 10),
                    ),
                    "gpt-5.6-terra": terra,
                },
            )

            self.assertIsNone(report["recommended_model"])
            self.assertEqual(
                report["selection_reason"],
                "models_tied_on_quality_escalation_and_cost",
            )

    def test_retry_attempts_are_reserved_before_runner_and_exhaustion_writes_no_result(self) -> None:
        sample = [case(1)]
        observed_attempts: list[int] = []
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)

            class FailingTransport:
                endpoint = "https://api.openai.com/v1/responses"

                def request(self, *, headers, body, timeout, max_bytes):
                    observed_attempts.append(len(list(store.attempts.glob("*.json"))))
                    raise RetryableEvaluationError("temporary provider failure")

            failing = OpenAIRichSemanticAssessmentProvider(
                api_key="fixture-key-not-secret",
                sleeper=lambda _seconds: None,
                known_identity_literals=KNOWN_IDENTITY_LITERALS,
                model="gpt-5.6-luna",
                reasoning_effort="low",
                transport=FailingTransport(),
                region="global",
            )

            with self.assertRaisesRegex(RuntimeError, "retry budget"):
                RichSemanticEvaluator(store).evaluate(
                    labeled_sample=sample,
                    runners={
                        "gpt-5.6-luna": failing,
                        "gpt-5.6-terra": self.runner(
                            "gpt-5.6-terra",
                            [("substantial", "working_product")], tokens=(1, 1),
                        ),
                    },
                )

            self.assertEqual(observed_attempts, [1, 2])
            self.assertEqual(len(list(store.attempts.glob("*.json"))), 2)
            self.assertEqual(list(store.results.glob("*.json")), [])
            self.assertFalse((store.root / "evaluation-report.json").exists())

    def test_transport_retries_cannot_exceed_reserved_evaluation_attempts(self) -> None:
        sample = [case(1)]
        project = sample[0]["evidence"]["projects"][0]
        project["description_excerpt"] = "workflow product"
        project["readme_excerpt"] = "workflow retries failures records decisions"
        observed_attempts: list[int] = []
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)
            success = ProviderResponsesTransport(
                "gpt-5.6-luna", [("substantial", "working_product")],
            )

            class TwoFailuresThenSuccessTransport:
                endpoint = "https://api.openai.com/v1/responses"

                def __init__(self) -> None:
                    self.requests = 0

                def request(self, *, headers, body, timeout, max_bytes):
                    self.requests += 1
                    observed_attempts.append(len(list(store.attempts.glob("*.json"))))
                    if self.requests <= 2:
                        return HttpResponse(500, {}, b"", self.endpoint)
                    return success.request(
                        headers=headers, body=body, timeout=timeout, max_bytes=max_bytes,
                    )

            transport = TwoFailuresThenSuccessTransport()
            runner = OpenAIRichSemanticAssessmentProvider(
                api_key="fixture-key-not-secret",
                sleeper=lambda _seconds: None,
                known_identity_literals=KNOWN_IDENTITY_LITERALS,
                model="gpt-5.6-luna",
                reasoning_effort="low",
                transport=transport,
                region="global",
            )

            with self.assertRaisesRegex(RuntimeError, "retry budget"):
                RichSemanticEvaluator(store).evaluate(
                    labeled_sample=sample,
                    runners={
                        "gpt-5.6-luna": runner,
                        "gpt-5.6-terra": self.runner(
                            "gpt-5.6-terra",
                            [("substantial", "working_product")], tokens=(1, 1),
                        ),
                    },
                )

            self.assertEqual(transport.requests, 2)
            self.assertEqual(observed_attempts, [1, 2])
            self.assertEqual(len(list(store.attempts.glob("*.json"))), 2)
            self.assertEqual(list(store.results.glob("*.json")), [])

    def test_wrong_model_version_or_non_human_review_assessment_is_rejected(self) -> None:
        sample = [case(1)]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)
            wrong_version = OpenAIRichSemanticAssessmentProvider(
                api_key="fixture-key-not-secret",
                sleeper=lambda _seconds: None,
                known_identity_literals=KNOWN_IDENTITY_LITERALS,
                model="gpt-5.6-luna",
                reasoning_effort="low",
                transport=ProviderResponsesTransport(
                    "floating-alias",
                    [("substantial", "working_product")],
                    tokens=(1, 1),
                ),
                region="global",
            )

            with self.assertRaisesRegex(RuntimeError, "metadata"):
                RichSemanticEvaluator(store).evaluate(
                    labeled_sample=sample,
                    runners={
                        "gpt-5.6-luna": wrong_version,
                        "gpt-5.6-terra": self.runner(
                            "gpt-5.6-terra",
                            [("substantial", "working_product")], tokens=(1, 1),
                        ),
                    },
                )

    def test_runtime_binding_must_match_endpoint_prompt_schema_reasoning_and_store_posture(self) -> None:
        sample = [case(1)]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)
            luna = self.runner(
                "gpt-5.6-luna",
                [("substantial", "working_product")], tokens=(1, 1),
            )

            class StoreEnabledProvider(OpenAIRichSemanticAssessmentProvider):
                @property
                def store(self) -> bool:
                    return True

            luna = StoreEnabledProvider(
                api_key="fixture-key-not-secret",
                sleeper=lambda _seconds: None,
                known_identity_literals=KNOWN_IDENTITY_LITERALS,
                model="gpt-5.6-luna",
                reasoning_effort="low",
                transport=luna.transport,
                region="global",
            )

            with self.assertRaisesRegex(PermissionError, "runtime binding"):
                RichSemanticEvaluator(store).evaluate(
                    labeled_sample=sample,
                    runners={
                        "gpt-5.6-luna": luna,
                        "gpt-5.6-terra": self.runner(
                            "gpt-5.6-terra",
                            [("substantial", "working_product")], tokens=(1, 1),
                        ),
                    },
                )

            self.assertEqual(list(store.attempts.glob("*.json")), [])

    def test_non_human_review_assessment_is_rejected(self) -> None:
        sample = [case(1)]
        with tempfile.TemporaryDirectory() as directory:
            store = self.create_store(directory, sample)

            class AutoAcceptedTransport(ProviderResponsesTransport):
                def request(self, *, headers, body, timeout, max_bytes):
                    response = super().request(
                        headers=headers, body=body, timeout=timeout, max_bytes=max_bytes,
                    )
                    envelope = json.loads(response.body)
                    unsafe = assessment()
                    unsafe["review_state"] = "accepted"
                    envelope["output"][0]["content"][0]["text"] = json.dumps(unsafe)
                    return HttpResponse(
                        response.status, response.headers,
                        json.dumps(envelope).encode("utf-8"), response.url,
                    )

            auto_accepted = OpenAIRichSemanticAssessmentProvider(
                api_key="fixture-key-not-secret",
                sleeper=lambda _seconds: None,
                known_identity_literals=KNOWN_IDENTITY_LITERALS,
                model="gpt-5.6-luna",
                reasoning_effort="low",
                transport=AutoAcceptedTransport(
                    "gpt-5.6-luna",
                    [
                        ("substantial", "working_product"),
                        ("substantial", "working_product"),
                    ],
                    tokens=(1, 1),
                ),
                region="global",
            )
            with self.assertRaisesRegex(RuntimeError, "retry budget"):
                RichSemanticEvaluator(store).evaluate(
                    labeled_sample=sample,
                    runners={
                        "gpt-5.6-luna": auto_accepted,
                        "gpt-5.6-terra": self.runner(
                            "gpt-5.6-terra",
                            [("substantial", "working_product")], tokens=(1, 1),
                        ),
                    },
                )


if __name__ == "__main__":
    unittest.main()
