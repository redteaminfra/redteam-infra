# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace


SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "import_confluence_domains.py"
SPEC = importlib.util.spec_from_file_location("import_confluence_domains", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
import_confluence_domains = importlib.util.module_from_spec(SPEC)
sys.modules["import_confluence_domains"] = import_confluence_domains
SPEC.loader.exec_module(import_confluence_domains)


def test_normalizes_confluence_dot_notation():
    assert import_confluence_domains.normalize_confluence_domain("example dot com") == "example.com"
    assert import_confluence_domains.normalize_confluence_domain("oracleopenworld dot co dot uk") == "oracleopenworld.co.uk"
    assert import_confluence_domains.normalize_confluence_domain("slackcdn dot com (cabal domain xfer!)") == "slackcdn.com"
    assert import_confluence_domains.normalize_confluence_domain("not-a-domain") == ""


def test_parses_relevant_tables_and_ignores_expiring_for_notes():
    rows = import_confluence_domains.parse_confluence_domain_rows(
        """
        <h1>Domains Used</h1>
        <table>
          <tr><th>Name</th><th>Registered On / By / Account</th><th>Status</th><th>Expiring</th></tr>
          <tr><td>f-6 dot cc</td><td>namecheap / operator / account</td><td>SK02</td><td>Dec 9, 2026</td></tr>
        </table>
        <h1>Domain Brainstorming</h1>
        <table>
          <tr><th>Name</th><th>Status</th><th>Purpose</th></tr>
          <tr><td>idea dot com</td><td>AVAILABLE</td><td>Phishing</td></tr>
        </table>
        """
    )

    assert len(rows) == 1
    assert rows[0].domain_name == "f-6.cc"
    assert rows[0].date_text == "Dec 9, 2026"
    assert import_confluence_domains.note_for_row(rows[0]) == "Confluence historical use: SK02"
    assert "2026" not in import_confluence_domains.note_for_row(rows[0])


def test_build_plan_updates_existing_domains_and_tracks_unmatched_unavailable():
    rows = [
        import_confluence_domains.ConfluenceDomainRow(
            "Owned Domains Waiting to be used",
            "known.example",
            "known dot example",
            "namecheap / operator / account",
            "phishing",
            "",
            [],
        ),
        import_confluence_domains.ConfluenceDomainRow(
            "Domains Used",
            "missing.example",
            "missing dot example",
            "namecheap / operator / account",
            "SK02",
            "",
            [],
        ),
    ]
    assets = {"known.example": SimpleNamespace(id="dom-known", notes="")}

    plan = import_confluence_domains.build_catalog_plan(rows, assets)

    assert [update.domain_name for update in plan.updates] == ["known.example"]
    assert plan.updates[0].after_notes == "Confluence waiting purpose: phishing"
    assert plan.skipped_unmatched == []
    assert [create.domain_name for create in plan.creates] == ["missing.example"]
    assert plan.creates[0].notes == (
        "Confluence historical use: SK02\n"
        "Confluence import: not present in current Namecheap inventory; track unavailable until reviewed."
    )


def test_note_merge_is_idempotent_for_repeated_rows():
    rows = [
        import_confluence_domains.ConfluenceDomainRow(
            "Domains Used",
            "f-6.cc",
            "f-6 dot cc",
            "namecheap / operator / account",
            "SK02",
            "Dec 9, 2026",
            [],
        ),
        import_confluence_domains.ConfluenceDomainRow(
            "Domains Used",
            "f-6.cc",
            "f-6 dot cc",
            "namecheap / operator / account",
            "SK02",
            "Dec 9, 2026",
            [],
        ),
    ]
    assets = {"f-6.cc": SimpleNamespace(id="dom-f6", notes="Existing note")}

    plan = import_confluence_domains.build_catalog_plan(rows, assets)

    assert len(plan.updates) == 1
    assert plan.creates == []
    assert plan.updates[0].after_notes == "Existing note\nConfluence historical use: SK02"
    assert plan.unchanged == ["f-6.cc"]
    assert plan.duplicate_domains == {"f-6.cc": 2}


def test_unmatched_duplicate_domain_creates_one_historical_record():
    rows = [
        import_confluence_domains.ConfluenceDomainRow(
            "Domains Forfeited",
            "gone.example",
            "gone dot example",
            "namecheap / operator / account",
            "expired",
            "",
            [],
        ),
        import_confluence_domains.ConfluenceDomainRow(
            "Domains Forfeited",
            "gone.example",
            "gone dot example",
            "namecheap / operator / account",
            "expired",
            "",
            [],
        ),
    ]

    plan = import_confluence_domains.build_catalog_plan(rows, {})

    assert [create.domain_name for create in plan.creates] == ["gone.example"]
    assert plan.unchanged == ["gone.example"]
    assert plan.duplicate_domains == {"gone.example": 2}
    assert "Confluence forfeited status: expired" in plan.creates[0].notes
    assert "track unavailable until reviewed" in plan.creates[0].notes


def test_brainstorming_rows_are_opt_in():
    html = """
    <h1>Domain Brainstorming</h1>
    <table>
      <tr><th>Name</th><th>Status</th><th>Purpose</th></tr>
      <tr><td>yum-repo dot com</td><td>PURCHASED</td><td>C2</td></tr>
    </table>
    """

    default_rows = import_confluence_domains.parse_confluence_domain_rows(html)
    included_rows = import_confluence_domains.parse_confluence_domain_rows(html, include_brainstorming=True)

    assert default_rows == []
    assert len(included_rows) == 1
    assert import_confluence_domains.note_for_row(included_rows[0]) == "Confluence brainstorming: PURCHASED; C2"
