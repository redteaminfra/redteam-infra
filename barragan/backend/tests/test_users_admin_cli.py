# Copyright (c) 2026, Oracle and/or its affiliates.
from pathlib import Path

from app.cli.users_admin import main
from app.core.bootstrap import initialize_database
from app.storage.database import db
from app.storage.models import TeamMemberModel


def test_breakglass_cli_bootstraps_active_team_and_reads_password_from_stdin(tmp_path: Path, monkeypatch, capsys):
    database_url = f"sqlite:///{tmp_path / 'admin.sqlite3'}"
    monkeypatch.setenv("BARRAGAN_ADMIN_DATABASE_URL", database_url)

    class Config:
        SQLALCHEMY_DATABASE_URI = database_url

    state = initialize_database(Config)
    with db.bind(state):
        db.session.add(TeamMemberModel(id="member-alice", username="alice", display_name="Alice", status="active"))
        db.session.commit()

    assert main(["--environment", "devtest", "bootstrap-active-team"]) == 0
    assert '"username": "alice"' in capsys.readouterr().out

    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("a long example_operator_three password\n"))
    assert main([
        "--environment", "devtest", "create", "example_operator_three",
        "--roles", "administrator,service_account",
        "--service-account",
        "--password-stdin", "--permanent",
    ]) == 0
    output = capsys.readouterr().out
    assert '"username": "example_operator_three"' in output
    assert "a long example_operator_three password" not in output
