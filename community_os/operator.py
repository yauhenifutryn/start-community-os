"""Local-only browser operator for the final Talent Data Room exports."""

from __future__ import annotations

from datetime import UTC, datetime
import getpass
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import tempfile
from urllib.parse import parse_qs, urlparse
import webbrowser

from community_os.db import initialize
from community_os.operator_pipeline import (
    OperatorError, SourceSlot, build_report_payload, preflight_csv, preflight_xlsx,
    records_from_source, validate_distinct_inputs, write_outputs,
)
from community_os.operator_store import (
    aggregate_facts, decide_review, ensure_event, ingest_records, list_open_reviews,
    source_file_row_count,
)


MAX_UPLOAD_BYTES = 25 * 1024 * 1024


class OperatorState:
    def __init__(self, output: Path, operator_label: str):
        self.temporary = tempfile.TemporaryDirectory(prefix="community-os-operator-")
        self.uploads: dict[SourceSlot, Path] = {}
        self.results: dict[SourceSlot, object] = {}
        self.reviews: dict[str, str] = {}
        self.output = output
        self.output.mkdir(parents=True, exist_ok=True)
        self.connection = initialize(self.output / "operator.sqlite3")
        self.event_id = ensure_event(self.connection)
        self.operator_label = operator_label.strip()
        if not self.operator_label:
            raise OperatorError("operator label is required")
        self._load_persisted_status()

    def close(self) -> None:
        self.connection.close()
        self.temporary.cleanup()

    def _load_persisted_status(self) -> None:
        source_slots = {
            "luma_final": SourceSlot.LUMA,
            "track_preferences_final": SourceSlot.TRACK,
            "devpost_final": SourceSlot.DEVPOST,
        }
        for source_file_id, source_type, digest in self.connection.execute(
            """SELECT sf.id,sf.source_type,sf.file_sha256
               FROM source_file sf WHERE sf.event_id=? ORDER BY sf.id""",
            (self.event_id,),
        ):
            slot = source_slots.get(str(source_type))
            if slot:
                from community_os.operator_pipeline import PreflightResult

                count = source_file_row_count(
                    self.connection, int(source_file_id), str(source_type)
                )
                self.results[slot] = PreflightResult(slot.value, str(digest), count)

    def _ingest_ready_sources(self) -> None:
        if set(self.uploads) != set(SourceSlot):
            return
        observed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        source_types = {
            SourceSlot.LUMA: "luma_final",
            SourceSlot.TRACK: "track_preferences_final",
            SourceSlot.DEVPOST: "devpost_final",
        }
        for slot in (SourceSlot.LUMA, SourceSlot.TRACK, SourceSlot.DEVPOST):
            path = self.uploads[slot]
            result = self.results[slot]
            current = self.connection.execute(
                "SELECT file_sha256 FROM source_file WHERE event_id=? AND source_type=?",
                (self.event_id, source_types[slot]),
            ).fetchone()
            if current and current[0] != result.sha256:
                raise OperatorError(
                    f"{slot.value}: a different source version is already persisted; use a new operator database for a corrected final export"
                )
            ingest_records(
                self.connection, event_id=self.event_id,
                source_type=source_types[slot], digest=result.sha256,
                records=records_from_source(path, slot), observed_at=observed_at,
            )
        self._load_persisted_status()

    def store(self, slot: SourceSlot, body: bytes) -> object:
        suffix = ".csv" if slot is SourceSlot.LUMA else ".xlsx"
        destination = Path(self.temporary.name) / f"{slot.value}{suffix}"
        pending = destination.with_suffix(destination.suffix + ".pending")
        pending.write_bytes(body)
        result = preflight_csv(pending, slot) if slot is SourceSlot.LUMA else preflight_xlsx(pending, slot)
        source_type = {
            SourceSlot.LUMA: "luma_final",
            SourceSlot.TRACK: "track_preferences_final",
            SourceSlot.DEVPOST: "devpost_final",
        }[slot]
        persisted = self.connection.execute(
            "SELECT file_sha256 FROM source_file WHERE event_id=? AND source_type=?",
            (self.event_id, source_type),
        ).fetchone()
        if persisted and persisted[0] != result.sha256:
            pending.unlink(missing_ok=True)
            raise OperatorError(
                f"{slot.value}: a different source version is already persisted; use a new operator database for a corrected final export"
            )
        pending.replace(destination)
        candidate = {**self.uploads, slot: destination}
        validate_distinct_inputs(candidate)
        self.uploads[slot] = destination
        self.results[slot] = result
        self._ingest_ready_sources()
        return result

    def facts(self) -> dict[str, object]:
        missing = set(SourceSlot) - set(self.results)
        if missing:
            raise OperatorError("missing source slots: " + ", ".join(sorted(item.value for item in missing)))
        return aggregate_facts(self.connection, self.event_id)

    def open_review_count(self) -> int:
        return len(list_open_reviews(self.connection, self.event_id))

    def review_rows(self) -> list[dict[str, object]]:
        return list_open_reviews(self.connection, self.event_id)

    def decide(self, candidate: str, decision: str) -> None:
        try:
            review_id = int(candidate.removeprefix("candidate-"))
        except ValueError as error:
            raise OperatorError("invalid review candidate") from error
        decided_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        try:
            decide_review(
                self.connection, review_id=review_id, decision=decision,
                reviewer=self.operator_label, decided_at=decided_at,
            )
        except ValueError as error:
            raise OperatorError(str(error)) from error

    def generate(self) -> tuple[Path, Path]:
        facts = self.facts()
        generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        payload = build_report_payload(facts, open_review_count=self.open_review_count(), generated_at=generated_at)
        hashes = {slot.value: result.sha256 for slot, result in self.results.items()}
        counts = {key: int(facts[key]) for key in ("approved", "checked_in", "submitted_people")}
        return write_outputs(self.output, payload, source_hashes=hashes, counts=counts, warnings=[], generated_at=generated_at)


def _page(state: OperatorState) -> bytes:
    slots = []
    for slot in SourceSlot:
        result = state.results.get(slot)
        status = f"Validated: {result.row_count} rows, SHA-256 {result.sha256}" if result else "Waiting"
        slots.append(f'<section><h2>{escape(slot.value.replace("_", " ").title())}</h2><input type="file" data-slot="{slot.value}" accept="{'.csv' if slot is SourceSlot.LUMA else '.xlsx'}"><p>{escape(status)}</p></section>')
    review_html = ""
    if len(state.results) == 3:
        try:
            state.facts()
            rows = []
            for review in state.review_rows():
                key = f"candidate-{review['review_id']:04d}"
                actions = [("keep_separate", "Keep separate"), ("quarantine", "Quarantine")]
                if review["suggested_person_id"] is not None:
                    actions.insert(0, ("approve", "Approve link"))
                buttons = " ".join(f'<button data-candidate="{key}" data-decision="{decision}">{label}</button>' for decision, label in actions)
                suggestion = f' · suggested {escape(str(review["suggested_email"]))}' if review["suggested_email"] else ""
                rows.append(f'<li>{escape(key)} · {escape(str(review["candidate_name"]))} · {escape(str(review["candidate_email"]))} · {escape(str(review["source_type"]))} · {escape(str(review["reason_code"]))}{suggestion} {buttons}</li>')
            open_count = state.open_review_count()
            review_note = "Publication is blocked until all are resolved." if open_count else "All identity reviews are resolved."
            review_html = f'<section><h2>Identity review</h2><p>{open_count} open reviews. {review_note}</p><ul>{"".join(rows)}</ul><button id="generate">Generate validated outputs</button></section>'
        except OperatorError as error:
            review_html = f'<section class="error">{escape(str(error))}</section>'
    html = f'''<!doctype html><html><head><meta charset="utf-8"><title>Talent Data Room Operator</title><style>body{{font:16px system-ui;max-width:900px;margin:40px auto;color:#171729;background:#fcfbf7}}section{{border:1px solid #d5d4db;padding:20px;margin:16px 0}}button{{margin:4px;padding:8px}}.error{{color:#94252a}}</style></head><body><h1>Talent Data Room Operator</h1><p>Local only, three explicit source slots. Raw records are not shown.</p>{''.join(slots)}{review_html}<pre id="message"></pre><script>
for(const input of document.querySelectorAll('input[type=file]')) input.onchange=async()=>{{const response=await fetch('/upload?slot='+input.dataset.slot,{{method:'POST',headers:{{'Content-Type':'application/octet-stream'}},body:input.files[0]}});document.querySelector('#message').textContent=await response.text();if(response.ok) location.reload();}};
for(const button of document.querySelectorAll('[data-candidate]')) button.onclick=async()=>{{await fetch('/decision',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{candidate:button.dataset.candidate,decision:button.dataset.decision}})}});location.reload();}};
const generate=document.querySelector('#generate');if(generate) generate.onclick=async()=>{{const response=await fetch('/generate',{{method:'POST'}});document.querySelector('#message').textContent=await response.text();}};
</script></body></html>'''
    return html.encode("utf-8")


def run_operator(*, port: int = 8765, output: str | Path = "output/operator", open_browser: bool = True, operator_label: str | None = None) -> None:
    state = OperatorState(Path(output), operator_label or getpass.getuser())

    class Handler(BaseHTTPRequestHandler):
        def _reply(self, status: int, body: bytes, content_type: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            request_path = urlparse(self.path).path
            if request_path == "/favicon.ico":
                self.send_response(204)
                self.end_headers()
                return
            if request_path != "/":
                self._reply(404, b'{"error":"not found"}')
                return
            self._reply(200, _page(state), "text/html")

        def do_POST(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 0 or length > MAX_UPLOAD_BYTES:
                    raise OperatorError("request exceeds 25 MiB limit")
                path = urlparse(self.path)
                body = self.rfile.read(length)
                if path.path == "/upload":
                    slot_values = parse_qs(path.query).get("slot", [])
                    if len(slot_values) != 1:
                        raise OperatorError("missing source slot")
                    result = state.store(SourceSlot(slot_values[0]), body)
                    response = {"source": result.source, "rows": result.row_count, "sha256": result.sha256}
                elif path.path == "/decision":
                    request = json.loads(body)
                    state.decide(request.get("candidate", ""), request.get("decision", ""))
                    response = {"ok": True, "open_review_count": state.open_review_count()}
                elif path.path == "/generate":
                    report, manifest = state.generate()
                    response = {"report": str(report), "manifest": str(manifest)}
                else:
                    self._reply(404, b'{"error":"not found"}')
                    return
                self._reply(200, json.dumps(response).encode())
            except (OperatorError, ValueError, json.JSONDecodeError) as error:
                self._reply(400, json.dumps({"error": str(error)}).encode())

        def log_message(self, format: str, *args: object) -> None:
            print(f"operator {self.command} {urlparse(self.path).path} {args[1] if len(args) > 1 else ''}")

    server = HTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(url, flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        state.close()
