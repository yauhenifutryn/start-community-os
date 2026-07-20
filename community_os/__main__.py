"""Command-line entry point for the local talent pipeline."""

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import asdict
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import tempfile


def _default_release_operator_root() -> str:
    """Return a persistent, clone-independent default for protected state."""

    configured = os.environ.get("XDG_DATA_HOME", "").strip()
    data_home = (
        Path(configured).expanduser()
        if configured
        else Path.home() / ".local" / "share"
    )
    return str(data_home / "start-community-os" / "operator")


def _validated_release_operator_root(
    value: str, *, allow_ephemeral: bool,
) -> str:
    """Reject system-temporary protected storage outside explicit test runs."""

    root = Path(value).expanduser().resolve(strict=False)
    temporary_roots = {
        Path(tempfile.gettempdir()).resolve(strict=False),
        Path("/tmp").resolve(strict=False),
        Path("/private/tmp").resolve(strict=False),
        Path("/var/tmp").resolve(strict=False),
        Path("/private/var/tmp").resolve(strict=False),
    }
    is_ephemeral = any(
        root == candidate or candidate in root.parents
        for candidate in temporary_roots
    )
    if is_ephemeral and not allow_ephemeral:
        raise ValueError(
            "release-operator root is ephemeral; choose a durable private path "
            "outside system temporary storage. --allow-ephemeral-root is for "
            "synthetic tests only and must not hold real participant evidence"
        )
    return str(root)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="community_os")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="Build a privacy-checked talent data room.")
    build.add_argument(
        "--config", default="config/events/example.synthetic.json",
        help="Event build configuration JSON.",
    )
    build.add_argument("--pdf", action="store_true", help="Also export the report as PDF.")
    cleanup = commands.add_parser("cleanup", help="Apply retention and opt-out cleanup rules.")
    cleanup.add_argument("--database", required=True, help="SQLite database to clean.")
    cleanup.add_argument(
        "--apply", action="store_true",
        help="Apply erasure. Without this flag, only report eligible rows.",
    )
    privacy_cleanup = commands.add_parser(
        "privacy-cleanup",
        help="Physically delete expired protected enrichment and cache payloads.",
    )
    privacy_cleanup.add_argument(
        "--root", default=_default_release_operator_root(),
        help="Protected release-operator storage root.",
    )
    privacy_cleanup.add_argument(
        "--event-config", required=True,
        help="Strict event release definition JSON.",
    )
    coresignal_cleanup = commands.add_parser(
        "coresignal-evaluation-cleanup",
        help="Delete expired internal-only Coresignal evaluation records.",
    )
    coresignal_cleanup.add_argument(
        "--root", required=True,
        help="Dedicated Coresignal career-evaluation storage root.",
    )
    coresignal_cleanup.add_argument(
        "--release-root", required=True,
        help="Release storage root used to verify physical isolation.",
    )
    github_semantic_cleanup = commands.add_parser(
        "github-semantic-evaluation-cleanup",
        help="Delete expired internal-only GitHub semantic evaluation records.",
    )
    github_semantic_cleanup.add_argument(
        "--root", required=True, help="Dedicated GitHub semantic evaluation storage root.",
    )
    github_semantic_cleanup.add_argument(
        "--release-root", required=True,
        help="Release storage root used to verify physical isolation.",
    )
    review = commands.add_parser(
        "review-identities",
        help="Export identity matches that require human review.",
    )
    review.add_argument("--database", required=True, help="SQLite database to inspect.")
    review.add_argument("--event-id", required=True, type=int, help="Event database ID.")
    review.add_argument("--output", required=True, help="Destination JSON file.")
    pdf = commands.add_parser("export-pdf", help="Export a generated HTML report to PDF.")
    pdf.add_argument("html", help="Generated HTML report.")
    pdf.add_argument("pdf", help="Destination PDF file.")
    partner = commands.add_parser(
        "render-partner",
        help="Render the concise partner report from validated aggregates.",
    )
    partner.add_argument("--contract", required=True, help="Validated talent-intelligence aggregate JSON.")
    partner.add_argument("--event-contract", required=True, help="Validated event-evidence aggregate JSON.")
    partner.add_argument("--html", required=True, help="Destination HTML file.")
    partner.add_argument("--pdf", help="Optional destination PDF file.")
    partner.add_argument(
        "--semantic-aggregate",
        help="Protected population-semantic aggregate JSON.",
    )
    partner.add_argument(
        "--semantic-context",
        help="Protected current release-context JSON for exact semantic binding checks.",
    )
    partner.add_argument(
        "--semantic-candidate", action="store_true",
        help="Render a local semantic candidate that remains publication-ineligible.",
    )
    partner.add_argument(
        "--semantic-approval",
        help="Protected signed semantic-release approval JSON bound to the exact candidate.",
    )
    partner.add_argument(
        "--semantic-approval-secret-env",
        help="Environment variable containing the local semantic approval verification secret.",
    )
    partner.add_argument(
        "--semantic-qa",
        help="Protected semantic release QA receipt bound by the approval.",
    )
    operator = commands.add_parser("operator", help="Launch the local Talent Data Room operator.")
    operator.add_argument("--port", type=int, default=8765, help="Local TCP port.")
    operator.add_argument("--output", default="output/operator", help="Aggregate output directory.")
    operator.add_argument("--no-open", action="store_true", help="Do not open a browser automatically.")
    operator.add_argument("--operator-label", help="Attributable label stored with review decisions.")
    release_operator = commands.add_parser("release-operator", help="Launch the authenticated event-configured release operator.")
    release_operator.add_argument(
        "--event-config",
        help=(
            "Strict event release definition JSON. When omitted, first-run setup "
            "creates and then reuses <root>/event-definition.json."
        ),
    )
    release_operator.add_argument(
        "--root", default=_default_release_operator_root(),
        help="Durable protected operator storage root outside the repository and system temporary directories.",
    )
    release_operator.add_argument(
        "--allow-ephemeral-root", action="store_true",
        help="Allow system-temporary storage for synthetic tests only; never use with real participant evidence.",
    )
    release_operator.add_argument("--port", type=int, default=8766, help="Local proxy-facing TCP port.")
    release_operator.add_argument("--host", default="127.0.0.1", choices=("127.0.0.1", "0.0.0.0"), help="Bind address; use all interfaces only behind the authenticated proxy.")
    release_operator.add_argument("--operator-code", default="privacy_lead", help="Machine-readable accountable owner code.")
    release_operator.add_argument("--allowed-email", action="append", help="Allowlisted colleague email; repeat as needed or set OPERATOR_ALLOWED_EMAILS.")
    release_operator.add_argument("--release-owner-email", action="append", help="Explicit final release-owner email; repeat as needed or set OPERATOR_RELEASE_OWNER_EMAILS.")
    release_operator.add_argument("--proxy-secret-env", default="OPERATOR_PROXY_SECRET", help="Environment variable containing the proxy shared secret.")
    release_operator.add_argument("--pseudonym-secret-env", default="OPERATOR_PSEUDONYM_SECRET", help="Environment variable containing the deterministic pseudonym HMAC secret.")
    release_operator.add_argument("--github-token-env", default="GITHUB_TOKEN", help="Optional managed GitHub token environment variable.")
    release_operator.add_argument("--coresignal-token-env", default="CORESIGNAL_API_TOKEN", help="Optional managed Coresignal token environment variable.")
    release_operator.add_argument(
        "--coresignal-career-evaluation-root",
        help="Optional dedicated protected root containing retained career-only Coresignal evidence.",
    )
    release_operator.add_argument("--openai-api-key-env", default="OPENAI_API_KEY", help="Managed OpenAI API key environment variable for the approved semantic stage.")
    release_operator.add_argument("--openai-model", default="gpt-5.6-terra", help="Semantic classification model identifier; moving latest aliases are rejected.")
    release_operator.add_argument(
        "--openai-reasoning-effort", default="medium",
        choices=("none", "low", "medium", "high"),
        help="Pinned Responses reasoning effort for rich semantic assessment.",
    )
    release_operator.add_argument(
        "--openai-input-cost-per-million-usd-micros", type=int,
        help="Explicit Sol input price in USD micros per million tokens for a production semantic run.",
    )
    release_operator.add_argument(
        "--openai-output-cost-per-million-usd-micros", type=int,
        help="Explicit Sol output price in USD micros per million tokens for a production semantic run.",
    )
    release_operator.add_argument("--approval-bundle", help="Protected controlled-release approval JSON; defaults under the operator root.")
    release_operator.add_argument("--open", action="store_true", help="Open the local URL in a browser.")
    release = commands.add_parser("real-release", help="Reproduce the verified one-time real talent report.")
    release.add_argument(
        "--event-config", required=True,
        help="Strict event release definition JSON.",
    )
    release.add_argument(
        "--event-approval", required=True,
        help="Protected event approval bound to the exact source snapshots.",
    )
    release.add_argument(
        "--exclusion-bindings",
        help="Protected raw-application-ID to approved-pseudonym bindings, required when exclusions exist.",
    )
    release.add_argument(
        "--pseudonym-secret-env",
        help="Environment variable containing the pseudonym HMAC secret required for exclusion binding verification.",
    )
    release.add_argument("--applications", required=True, help="Full application export CSV.")
    release.add_argument("--attendance", required=True, help="Final attendance supplement CSV.")
    release.add_argument("--preferences", required=True, help="Final track-preference workbook.")
    release.add_argument("--submissions", required=True, help="Final Devpost workbook.")
    release.add_argument("--override", required=True, help="Private reviewed override JSON.")
    release.add_argument("--output", required=True, help="Protected output root for release artifacts.")
    release.add_argument("--generated-at", help="Stable ISO generation timestamp for exact replay.")
    release.add_argument("--pdf", action="store_true", help="Also export the balanced A4 PDF.")
    release.add_argument(
        "--semantic-aggregate",
        help="Protected population-semantic aggregate JSON.",
    )
    release.add_argument(
        "--semantic-context",
        help="Protected current release-context JSON for exact semantic binding checks.",
    )
    release.add_argument(
        "--semantic-candidate", action="store_true",
        help="Generate a local semantic candidate for exact human release approval.",
    )
    release.add_argument(
        "--semantic-approval",
        help="Protected human semantic-release approval JSON bound to the exact candidate.",
    )
    release.add_argument(
        "--semantic-approval-secret-env",
        help="Environment variable containing the local semantic approval verification secret.",
    )
    release.add_argument(
        "--semantic-qa",
        help="Protected semantic release QA receipt bound by the human approval.",
    )
    audit = commands.add_parser("real-audit", help="Trace one protected source row through the real release.")
    audit.add_argument("--state", required=True, help="Private canonical operator-state JSON.")
    audit.add_argument("--source", required=True, choices=("application", "preference", "devpost"))
    audit.add_argument("--row-id", required=True, help="Stable source-row identifier.")
    return parser


def _load_cli_exclusion_bindings(path: str | None) -> dict[str, str]:
    """Load the protected raw-application to approved-pseudonym binding map."""
    if path is None:
        return {}

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("exclusion bindings contain a duplicate application ID")
            result[key] = value
        return result

    try:
        value = json.loads(
            Path(path).read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicates,
        )
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("exclusion bindings are missing or unreadable") from error
    if (
        not isinstance(value, dict)
        or len(value) > 100_000
        or any(
            not isinstance(application_id, str)
            or not application_id.strip()
            or not isinstance(subject_ref, str)
            or not subject_ref.strip()
            for application_id, subject_ref in value.items()
        )
        or len(set(value.values())) != len(value)
    ):
        raise ValueError("exclusion bindings are invalid")
    return {str(key): str(item) for key, item in value.items()}


def _verified_exclusion_pseudonym_secret(
    bindings: Mapping[str, str], *, environment_name: str | None,
) -> bytes | None:
    """Recompute every claimed subject reference without logging the secret."""

    if not bindings:
        if environment_name:
            raise ValueError(
                "--pseudonym-secret-env is only valid with --exclusion-bindings",
            )
        return None
    if not environment_name:
        raise ValueError(
            "exclusion bindings require --pseudonym-secret-env",
        )
    secret = os.environ.get(environment_name, "").encode("utf-8")
    if len(secret) < 16:
        raise ValueError(
            f"environment variable {environment_name} is required and must contain at least 16 bytes",
        )
    from community_os.enrichment.state import pseudonymous_id

    for application_id, subject_ref in bindings.items():
        expected = pseudonymous_id(
            application_id, secret=secret, key_version="v1",
        )
        if not hmac.compare_digest(subject_ref, expected):
            raise ValueError("exclusion binding pseudonym does not match")
    return secret


def _load_cli_semantic_summary(
    *,
    aggregate_path: str | None,
    candidate_mode: bool,
    approval_path: str | None,
    approval_secret: bytes | None,
):
    if aggregate_path is None:
        if candidate_mode or approval_path is not None:
            raise ValueError("semantic mode requires --semantic-aggregate")
        return None
    if candidate_mode == (approval_path is not None):
        raise ValueError(
            "semantic aggregate requires exactly one of --semantic-candidate or "
            "--semantic-approval",
        )
    if candidate_mode:
        from community_os.partner_semantic_projection import (
            load_protected_partner_semantic_candidate_summary,
        )

        return load_protected_partner_semantic_candidate_summary(aggregate_path)
    from datetime import UTC, datetime
    from community_os.partner_semantic_projection import load_partner_semantic_summary

    return load_partner_semantic_summary(
        aggregate_path,
        approval_path=approval_path,
        now=datetime.now(UTC),
        approval_secret=approval_secret,
    )


def _semantic_approval_secret(
    *, approval_path: str | None, environment_name: str | None,
) -> bytes | None:
    if approval_path is None:
        return None
    if not environment_name:
        raise ValueError(
            "approved semantic release requires --semantic-approval-secret-env",
        )
    value = os.environ.get(environment_name, "").encode("utf-8")
    if len(value) < 16:
        raise ValueError(
            f"environment variable {environment_name} is required and must contain at least 16 bytes",
        )
    return value


def _load_semantic_context(
    path: str | None, *, semantic_summary: object | None,
) -> dict[str, object] | None:
    if semantic_summary is None:
        if path is not None:
            raise ValueError("semantic context requires --semantic-aggregate")
        return None
    if path is None:
        raise ValueError("semantic mode requires --semantic-context")
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise PermissionError("semantic release context is missing or unsafe")
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError("semantic release context is unreadable") from error
    if not isinstance(value, dict):
        raise PermissionError("semantic release context is invalid")
    return value


def _verify_approved_semantic_outputs(
    summary: object,
    outputs: object,
    *,
    qa_path: str | None,
    aggregate_path: str | None,
    semantic_context: Mapping[str, object] | None,
) -> None:
    approval_sha256 = getattr(summary, "semantic_release_approval_sha256", None)
    if approval_sha256 is None:
        return
    if not isinstance(outputs, dict):
        raise PermissionError("approved semantic release outputs are invalid")
    bindings = dict(getattr(summary, "release_artifact_hashes", ()))
    required = {"html_sha256", "pdf_sha256", "qa_sha256", "report_candidate_sha256"}
    if set(bindings) != required:
        raise PermissionError("approved semantic release artifact bindings are incomplete")
    if qa_path is None or aggregate_path is None or semantic_context is None:
        raise PermissionError(
            "approved semantic release QA, aggregate, and context are required",
        )

    def file_sha256(path: object) -> str:
        source = Path(path)
        if source.is_symlink() or not source.is_file():
            raise PermissionError("approved semantic release artifact is missing or unsafe")
        return hashlib.sha256(source.read_bytes()).hexdigest()

    for key, binding_key in (("html", "html_sha256"), ("pdf", "pdf_sha256")):
        if key not in outputs or file_sha256(outputs[key]) != bindings[binding_key]:
            raise PermissionError(f"approved semantic release {key} hash drift")
    try:
        aggregate = json.loads(Path(aggregate_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError(
            "approved semantic release aggregate is unreadable",
        ) from error
    if not isinstance(aggregate, dict):
        raise PermissionError("approved semantic release aggregate is invalid")
    from community_os.partner_semantic_projection import (
        validate_partner_semantic_release_context,
    )
    from community_os.semantic_metrics import semantic_aggregate_sha256
    from community_os.semantic_release_qa import (
        build_semantic_release_qa_context,
        load_semantic_release_qa_receipt,
        load_semantic_release_qa_review_evidence,
    )

    validate_partner_semantic_release_context(summary, semantic_context)
    aggregate_bindings = aggregate.get("bindings")
    population = aggregate.get("population")
    if not isinstance(aggregate_bindings, dict) or not isinstance(population, dict):
        raise PermissionError("approved semantic release aggregate is invalid")
    review_evidence = load_semantic_release_qa_review_evidence(qa_path)
    qa_context = build_semantic_release_qa_context(
        event_approval_sha256=str(aggregate_bindings["event_approval_sha256"]),
        event_definition_sha256=str(aggregate_bindings["event_definition_sha256"]),
        event_key=str(aggregate_bindings["event_key"]),
        source_snapshot_sha256=str(aggregate_bindings["source_snapshot_sha256"]),
        population=population,
        run_sha256=str(aggregate_bindings["run_sha256"]),
        taxonomy_version=str(aggregate_bindings["taxonomy_version"]),
        aggregate_sha256=semantic_aggregate_sha256(aggregate),
        html_candidate_sha256=file_sha256(outputs["html"]),
        pdf_candidate_sha256=file_sha256(outputs["pdf"]),
        positive_claim_count=review_evidence["positive_claim_count"],
        required_review_case_count=review_evidence[
            "required_review_case_count"
        ],
        review_evidence_sha256=review_evidence["review_evidence_sha256"],
    )
    qa_receipt = load_semantic_release_qa_receipt(
        qa_path, expected_context=qa_context,
    )
    if qa_receipt.sha256 != bindings["qa_sha256"]:
        raise PermissionError("approved semantic release QA hash drift")
    from community_os.publication import artifact_set_sha256

    public_paths = tuple(Path(outputs[key]) for key in ("html", "pdf", "v1", "v3"))
    if artifact_set_sha256(public_paths) != bindings["report_candidate_sha256"]:
        raise PermissionError("approved semantic release candidate hash drift")


def _approved_partner_bundle_directory(
    html_path: Path, pdf_path: Path,
) -> Path:
    """Require a dedicated directory so the approved pair can swap as one set."""

    _assert_safe_path_components(html_path)
    _assert_safe_path_components(pdf_path)
    if html_path.name == pdf_path.name:
        raise ValueError("approved HTML and PDF outputs must have distinct names")
    if html_path.parent.resolve() != pdf_path.parent.resolve():
        raise ValueError(
            "approved HTML and PDF outputs must share the same dedicated directory",
        )
    destination = html_path.parent
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise ValueError("approved output directory is unsafe")
    if destination.exists():
        expected = {html_path.name, pdf_path.name}
        entries = tuple(destination.iterdir())
        if (
            {entry.name for entry in entries} != expected
            or any(entry.is_symlink() or not entry.is_file() for entry in entries)
        ):
            raise ValueError(
                "approved output directory must contain only the complete prior HTML/PDF pair",
            )
    return destination


def _assert_safe_path_components(path: Path) -> None:
    absolute = path.expanduser().absolute()
    for candidate in (absolute, *absolute.parents):
        if candidate.is_symlink():
            if candidate in {Path("/var"), Path("/tmp")}:
                continue
            raise PermissionError(f"local path contains a symlink: {candidate}")
        if candidate.exists() and candidate != absolute and not candidate.is_dir():
            raise PermissionError(
                f"local path contains a non-directory parent: {candidate}",
            )


def _validated_regular_input(path: str | Path, *, label: str) -> Path:
    source = Path(path)
    _assert_safe_path_components(source)
    if not source.is_file():
        raise PermissionError(f"{label} must be a regular local file")
    return source


def _validated_file_output(path: str | Path, *, label: str) -> Path:
    destination = Path(path)
    _assert_safe_path_components(destination)
    if destination.exists() and not destination.is_file():
        raise PermissionError(f"{label} must be a regular local file")
    return destination


def _temporary_output(destination: Path, *, suffix: str) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=suffix, dir=destination.parent,
    )
    os.close(descriptor)
    temporary = Path(name)
    temporary.unlink(missing_ok=True)
    return temporary


def _install_candidate_report(
    rendered: str, *, html_path: Path, pdf_path: Path | None,
    stable_timestamp: str,
) -> Path | None:
    """Generate completely in sibling temporary files, then atomically replace."""

    staged_html = _temporary_output(html_path, suffix=".html")
    staged_pdf = None if pdf_path is None else _temporary_output(pdf_path, suffix=".pdf")
    try:
        staged_html.write_text(rendered, encoding="utf-8")
        if staged_pdf is not None:
            from community_os.pdf_export import export_pdf

            export_pdf(
                staged_html, staged_pdf, stable_timestamp=stable_timestamp,
            )
            if staged_pdf.is_symlink() or not staged_pdf.is_file():
                raise PermissionError("PDF exporter did not produce a regular file")
        staged_html.replace(html_path)
        if staged_pdf is not None and pdf_path is not None:
            staged_pdf.replace(pdf_path)
            return pdf_path
        return None
    finally:
        staged_html.unlink(missing_ok=True)
        if staged_pdf is not None:
            staged_pdf.unlink(missing_ok=True)


def _export_pdf_atomically(
    html_path: Path, pdf_path: Path, *, stable_timestamp: str | None = None,
) -> Path:
    staged_pdf = _temporary_output(pdf_path, suffix=".pdf")
    try:
        from community_os.pdf_export import export_pdf

        export_pdf(html_path, staged_pdf, stable_timestamp=stable_timestamp)
        if staged_pdf.is_symlink() or not staged_pdf.is_file():
            raise PermissionError("PDF exporter did not produce a regular file")
        staged_pdf.replace(pdf_path)
        return pdf_path
    finally:
        staged_pdf.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.command == "build":
        from community_os.build import build_from_config

        result = build_from_config(arguments.config, include_pdf=arguments.pdf)
        print(json.dumps({
            "database": str(result.database_path),
            "html": str(result.html_path),
            "pdf": str(result.pdf_path) if result.pdf_path else None,
            "accepted_records": result.accepted_records,
            "rejected_records": result.rejected_records,
        }, separators=(",", ":")))
    elif arguments.command == "cleanup":
        from community_os.retention import cleanup_expired

        connection = sqlite3.connect(arguments.database)
        try:
            report = cleanup_expired(connection, apply=arguments.apply)
        finally:
            connection.close()
        print(json.dumps(asdict(report), separators=(",", ":")))
    elif arguments.command == "privacy-cleanup":
        from community_os.controlled_release import run_scheduled_privacy_cleanup
        from community_os.event_definition import load_event_definition

        print(json.dumps(
            run_scheduled_privacy_cleanup(
                arguments.root,
                event_definition=load_event_definition(arguments.event_config),
            ),
            separators=(",", ":"),
        ))
    elif arguments.command == "coresignal-evaluation-cleanup":
        from datetime import UTC, datetime
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationStore,
        )

        store = CoresignalCareerEvaluationStore(
            arguments.root, release_root=arguments.release_root,
            clock=lambda: datetime.now(UTC),
        )
        receipt = store.cleanup_expired()
        print(json.dumps(receipt, separators=(",", ":"), sort_keys=True))
    elif arguments.command == "github-semantic-evaluation-cleanup":
        from datetime import UTC, datetime
        from community_os.github_evaluation import cleanup_expired_github_evaluation

        receipt = cleanup_expired_github_evaluation(
            arguments.root, release_root=arguments.release_root,
            now=datetime.now(UTC),
        )
        print(json.dumps(receipt, separators=(",", ":"), sort_keys=True))
    elif arguments.command == "review-identities":
        from community_os.identity import unresolved_identity_candidates

        connection = sqlite3.connect(arguments.database)
        try:
            candidates = unresolved_identity_candidates(connection, arguments.event_id)
        finally:
            connection.close()
        minimized = [
            {
                "candidate_ref": f"candidate-{index:04d}",
                "reason_code": item["reason_code"],
                "suggested_person_id": item["suggested_person_id"],
            }
            for index, item in enumerate(candidates, start=1)
        ]
        destination = Path(arguments.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(minimized, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"output": str(destination), "candidates": len(minimized)}))
    elif arguments.command == "export-pdf":
        source = _validated_regular_input(arguments.html, label="HTML input")
        pdf_output = _validated_file_output(arguments.pdf, label="PDF output")
        destination = _export_pdf_atomically(source, pdf_output)
        print(json.dumps({"pdf": str(destination)}, separators=(",", ":")))
    elif arguments.command == "render-partner":
        from community_os.partner_report import render_partner_talent_report
        from community_os.report_contract import load_report_contract
        from community_os.talent_intelligence_contract import load_talent_intelligence_contract

        html_path = _validated_file_output(arguments.html, label="HTML output")
        pdf_path = (
            _validated_file_output(arguments.pdf, label="PDF output")
            if arguments.pdf else None
        )
        if pdf_path is not None and html_path.absolute() == pdf_path.absolute():
            raise ValueError("HTML and PDF outputs must be distinct files")
        semantic_summary = _load_cli_semantic_summary(
            aggregate_path=arguments.semantic_aggregate,
            candidate_mode=arguments.semantic_candidate,
            approval_path=arguments.semantic_approval,
            approval_secret=_semantic_approval_secret(
                approval_path=arguments.semantic_approval,
                environment_name=arguments.semantic_approval_secret_env,
            ),
        )
        semantic_context = _load_semantic_context(
            arguments.semantic_context,
            semantic_summary=semantic_summary,
        )
        if arguments.semantic_approval and not arguments.pdf:
            raise ValueError("approved semantic release requires --pdf for artifact parity")
        if arguments.semantic_approval and not arguments.semantic_qa:
            raise ValueError("approved semantic release requires --semantic-qa")
        talent_contract = load_talent_intelligence_contract(arguments.contract)
        event_contract = load_report_contract(arguments.event_contract)
        rendered = render_partner_talent_report(
            talent_contract,
            event_contract,
            semantic_summary=semantic_summary,
            semantic_context=semantic_context,
        )
        response = {"html": str(html_path), "pdf": None}
        if arguments.semantic_approval:
            if pdf_path is None:
                raise ValueError("approved semantic release requires --pdf")
            destination = _approved_partner_bundle_directory(html_path, pdf_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(
                prefix=f".{destination.name}.approved-partner-render-",
                dir=destination.parent,
            ) as temporary_directory:
                staging = Path(temporary_directory) / "release"
                staging.mkdir(mode=0o700)
                staged_html = staging / html_path.name
                staged_pdf = staging / pdf_path.name
                staged_html.write_text(rendered, encoding="utf-8")
                from community_os.pdf_export import export_pdf

                export_pdf(
                    staged_html,
                    staged_pdf,
                    stable_timestamp=talent_contract.metadata.generated_at,
                )
                staged_outputs = {
                    "html": staged_html,
                    "pdf": staged_pdf,
                    "v1": arguments.contract,
                    "v3": arguments.event_contract,
                }
                _verify_approved_semantic_outputs(
                    semantic_summary,
                    staged_outputs,
                    qa_path=arguments.semantic_qa,
                    aggregate_path=arguments.semantic_aggregate,
                    semantic_context=semantic_context,
                )
                from community_os.publication import _install_publication_set

                _install_publication_set(staging, destination)
                response["pdf"] = str(pdf_path)
        else:
            installed_pdf = _install_candidate_report(
                rendered, html_path=html_path, pdf_path=pdf_path,
                stable_timestamp=talent_contract.metadata.generated_at,
            )
            if installed_pdf is not None:
                response["pdf"] = str(installed_pdf)
        print(json.dumps(response, separators=(",", ":")))
    elif arguments.command == "operator":
        from community_os.operator import run_operator

        run_operator(
            port=arguments.port, output=arguments.output,
            open_browser=not arguments.no_open, operator_label=arguments.operator_label,
        )
    elif arguments.command == "release-operator":
        from community_os.event_definition import load_event_definition
        from community_os.release_operator import (
            OperatorAccessPolicy,
            run_event_setup_operator,
            run_release_operator,
        )

        operator_root = _validated_release_operator_root(
            arguments.root,
            allow_ephemeral=arguments.allow_ephemeral_root,
        )

        proxy_secret = os.environ.get(arguments.proxy_secret_env, "")
        if not proxy_secret:
            raise ValueError(f"environment variable {arguments.proxy_secret_env} is required")
        allowed_emails = arguments.allowed_email or [
            value.strip() for value in os.environ.get("OPERATOR_ALLOWED_EMAILS", "").split(",") if value.strip()
        ]
        if not allowed_emails:
            raise ValueError("operator colleague allowlist is required")
        release_owner_emails = arguments.release_owner_email or [
            value.strip()
            for value in os.environ.get("OPERATOR_RELEASE_OWNER_EMAILS", "").split(",")
            if value.strip()
        ]
        pseudonym_secret = os.environ.get(arguments.pseudonym_secret_env, "")
        if len(pseudonym_secret.encode("utf-8")) < 16:
            raise ValueError(f"environment variable {arguments.pseudonym_secret_env} is required and must contain at least 16 bytes")
        access_policy = OperatorAccessPolicy(
            allowed_emails=frozenset(allowed_emails),
            proxy_secret=proxy_secret,
            release_owner_emails=frozenset(release_owner_emails),
        )
        event_config = (
            Path(arguments.event_config)
            if arguments.event_config
            else Path(operator_root) / "event-definition.json"
        )
        if arguments.event_config is None and not event_config.exists():
            run_event_setup_operator(
                root=operator_root,
                access_policy=access_policy,
                operator_code=arguments.operator_code,
                pseudonym_secret=pseudonym_secret.encode("utf-8"),
                port=arguments.port,
                open_browser=arguments.open,
                host=arguments.host,
            )
            return 0

        from community_os.controlled_release import (
            ControlledReleaseRuntime,
            build_controlled_release_factory,
        )

        approval_bundle = Path(arguments.approval_bundle) if arguments.approval_bundle else (
            Path(operator_root) / "protected" / "controlled-release-approval.json"
        )
        event_definition = load_event_definition(event_config)
        stage_operation_factory = build_controlled_release_factory(ControlledReleaseRuntime(
            approval_bundle=approval_bundle,
            pseudonym_secret=pseudonym_secret.encode("utf-8"),
            event_definition=event_definition,
            github_token=os.environ.get(arguments.github_token_env) or None,
            coresignal_token=os.environ.get(arguments.coresignal_token_env) or None,
            coresignal_career_evaluation_root=(
                Path(arguments.coresignal_career_evaluation_root)
                if arguments.coresignal_career_evaluation_root else None
            ),
            openai_api_key=os.environ.get(arguments.openai_api_key_env) or None,
            openai_model=arguments.openai_model,
            openai_reasoning_effort=arguments.openai_reasoning_effort,
            openai_input_cost_per_million_usd_micros=(
                arguments.openai_input_cost_per_million_usd_micros
            ),
            openai_output_cost_per_million_usd_micros=(
                arguments.openai_output_cost_per_million_usd_micros
            ),
        ))
        run_release_operator(
            root=operator_root,
            access_policy=access_policy,
            operator_code=arguments.operator_code,
            pseudonym_secret=pseudonym_secret.encode("utf-8"),
            event_definition=event_definition,
            port=arguments.port,
            open_browser=arguments.open,
            host=arguments.host,
            approval_bundle=approval_bundle,
            stage_operation_factory=stage_operation_factory,
        )
    elif arguments.command == "real-release":
        from community_os.event_approval import load_event_approval
        from community_os.event_definition import load_event_definition
        from community_os.real_report import (
            _validate_release_output_root,
            build_real_release,
            sha256_file,
        )

        _validate_release_output_root(arguments.output, export_pdf=arguments.pdf)
        event_definition = load_event_definition(arguments.event_config)
        exclusion_bindings = _load_cli_exclusion_bindings(
            arguments.exclusion_bindings,
        )
        pseudonym_secret = _verified_exclusion_pseudonym_secret(
            exclusion_bindings,
            environment_name=arguments.pseudonym_secret_env,
        )
        source_paths = {
            "applications": arguments.applications,
            "attendance": arguments.attendance,
            "preferences": arguments.preferences,
            "submissions": arguments.submissions,
        }
        observed_source_hashes = {
            source.role: (
                sha256_file(source_paths[source.role])
                if source.role in source_paths else None
            )
            for source in event_definition.sources
        }
        excluded_subject_refs = tuple(sorted(exclusion_bindings.values()))
        event_approval = load_event_approval(
            arguments.event_approval,
            definition=event_definition,
            source_hashes=observed_source_hashes,
            excluded_subject_refs=excluded_subject_refs,
        )
        exclusion_set_sha256 = (
            hashlib.sha256(json.dumps(
                list(excluded_subject_refs), ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")).hexdigest()
            if excluded_subject_refs else None
        )

        semantic_summary = _load_cli_semantic_summary(
            aggregate_path=arguments.semantic_aggregate,
            candidate_mode=arguments.semantic_candidate,
            approval_path=arguments.semantic_approval,
            approval_secret=_semantic_approval_secret(
                approval_path=arguments.semantic_approval,
                environment_name=arguments.semantic_approval_secret_env,
            ),
        )
        semantic_context = _load_semantic_context(
            arguments.semantic_context,
            semantic_summary=semantic_summary,
        )
        if arguments.semantic_approval and not arguments.pdf:
            raise ValueError("approved semantic release requires --pdf for artifact parity")
        if arguments.semantic_approval and not arguments.semantic_qa:
            raise ValueError("approved semantic release requires --semantic-qa")
        build_arguments = {
            "applications_path": arguments.applications,
            "attendance_path": arguments.attendance,
            "preferences_path": arguments.preferences,
            "submissions_path": arguments.submissions,
            "override_path": arguments.override,
            "generated_at": arguments.generated_at,
            "export_pdf": arguments.pdf,
            "semantic_summary": semantic_summary,
            "semantic_context": semantic_context,
            "excluded_application_ids": frozenset(exclusion_bindings),
            "exclusion_set_sha256": exclusion_set_sha256,
            "event_definition": event_definition,
            "event_approval": event_approval,
            "excluded_subject_refs_by_application_id": exclusion_bindings,
            "pseudonym_secret": pseudonym_secret,
        }
        if arguments.semantic_approval:
            destination = Path(arguments.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(
                prefix=f".{destination.name}.approved-",
                dir=destination.parent,
            ) as temporary_directory:
                staging_parent = Path(temporary_directory)
                staging = staging_parent / "release"
                staged_outputs = build_real_release(
                    **build_arguments,
                    output_root=staging,
                )
                _verify_approved_semantic_outputs(
                    semantic_summary,
                    staged_outputs,
                    qa_path=arguments.semantic_qa,
                    aggregate_path=arguments.semantic_aggregate,
                    semantic_context=semantic_context,
                )
                relative_outputs = {
                    key: Path(value).relative_to(staging)
                    for key, value in staged_outputs.items()
                }
                from community_os.publication import _install_publication_set

                _install_publication_set(staging, destination)
                outputs = {
                    key: destination / relative
                    for key, relative in relative_outputs.items()
                }
        else:
            outputs = build_real_release(
                **build_arguments,
                output_root=arguments.output,
            )
        print(json.dumps({key: str(value) for key, value in outputs.items()}, separators=(",", ":")))
    elif arguments.command == "real-audit":
        from community_os.real_report import audit_row

        print(json.dumps(
            audit_row(arguments.state, source=arguments.source, row_id=arguments.row_id),
            ensure_ascii=False, indent=2,
        ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
