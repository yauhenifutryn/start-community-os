"""Build both talent-intelligence briefs from one validated contract."""

from __future__ import annotations

import argparse
from pathlib import Path

from community_os.pdf_export import export_pdf
from community_os.render import render_report
from community_os.talent_intelligence_contract import load_talent_intelligence_contract


def build_talent_briefs(
    contract_path: str | Path,
    *,
    output_root: str | Path,
    export_pdfs: bool = False,
) -> dict[str, Path]:
    """Validate once, then write independent VC and company report artifacts."""
    report = load_talent_intelligence_contract(contract_path)
    destination = Path(output_root)
    destination.mkdir(parents=True, exist_ok=True)
    outputs: dict[str, Path] = {}
    for audience in ("vc", "company"):
        html_path = destination / f"{audience}-brief.synthetic.html"
        html_path.write_text(
            render_report(report, audience=audience),
            encoding="utf-8",
        )
        outputs[f"{audience}_html"] = html_path

    if export_pdfs:
        for audience in ("vc", "company"):
            html_path = outputs[f"{audience}_html"]
            pdf_path = destination / f"{audience}-brief.synthetic.pdf"
            export_pdf(html_path, pdf_path)
            outputs[f"{audience}_pdf"] = pdf_path
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build VC and company talent briefs from one validated contract."
    )
    parser.add_argument("contract", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--pdf", action="store_true", help="Also export static A4 PDFs")
    arguments = parser.parse_args(argv)
    outputs = build_talent_briefs(
        arguments.contract,
        output_root=arguments.output,
        export_pdfs=arguments.pdf,
    )
    for key, path in outputs.items():
        print(f"{key}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
