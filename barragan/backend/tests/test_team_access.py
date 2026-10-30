# Copyright (c) 2026, Oracle and/or its affiliates.
import base64
import json
import subprocess
from pathlib import Path

import app.services.team_access as team_access
from app.domain import JobEvent
from app.services.team_access import TeamAccessValidationError, start_engagement_access_apply, _run_guarded_command
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.models import AuthenticationCredentialModel
from app.storage.database import db


PUBLIC_KEY = "ssh-ed25519 dGVzdC1wdWJsaWMta2V5 team-test"
REPO_ROOT = Path(__file__).resolve().parents[2]


def _isolated_known_hosts_root(monkeypatch, tmp_path):
    monkeypatch.setattr(team_access, "DEFAULT_KNOWN_HOSTS_ROOT", tmp_path / "known-hosts")


def test_team_access_command_runner_sets_proxycommand_shell(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr("app.services.team_access.subprocess.run", fake_run)

    result = _run_guarded_command(["ansible-playbook", "--version"], Path("/tmp"), runner=None)

    assert result.ok is True
    assert captured["kwargs"]["env"]["SHELL"] == "/bin/sh"
    assert captured["kwargs"]["cwd"] == Path("/tmp")


def test_global_team_member_defaults_to_redteam_volunteer(client):
    response = client.post(
        "/api/team",
        json={
            "username": "operator1",
            "displayName": "Operator One",
            "email": "operator1@example.invalid",
            "desiredUid": 6100,
        },
    )
    body = response.get_json()

    assert response.status_code == 201
    assert body["member"]["username"] == "operator1"
    assert body["member"]["desiredUid"] == 6100
    assert body["member"]["defaultInfraGroups"] == ["redteam", "volunteer"]
    assert body["member"]["globalRoles"] == ["operator"]


def test_global_team_rejects_private_key_material(client):
    member = client.post("/api/team", json={"username": "operator2"}).get_json()["member"]

    response = client.post(
        f"/api/team/{member['id']}/ssh-keys",
        json={
            "label": "bad",
            "publicKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nredacted\n-----END OPENSSH PRIVATE KEY-----",
        },
    )
    body = response.get_json()

    assert response.status_code == 400
    assert "private key" in body["errors"][0]


def test_global_team_ssh_key_can_be_updated(client):
    member = client.post("/api/team", json={"username": "operator_key_update"}).get_json()["member"]
    key = client.post(
        f"/api/team/{member['id']}/ssh-keys",
        json={"label": "old", "publicKey": PUBLIC_KEY},
    ).get_json()["sshKey"]
    replacement = "ssh-ed25519 cmVwbGFjZW1lbnQta2V5 team-replacement"

    response = client.patch(
        f"/api/team/{member['id']}/ssh-keys/{key['id']}",
        json={"label": "piv", "publicKey": replacement},
    )
    body = response.get_json()

    assert response.status_code == 200
    assert body["sshKey"]["label"] == "piv"
    assert body["sshKey"]["publicKey"] == replacement
    assert body["sshKey"]["fingerprint"] != key["fingerprint"]


def test_engagement_membership_inherits_and_overrides_infra_groups(client):
    member = client.post("/api/team", json={"username": "operator3"}).get_json()["member"]

    enroll_response = client.post(
        "/api/engagements/eng-of02-dev/team",
        json={"memberId": member["id"], "appPrivileges": ["view", "operate"]},
    )
    enroll_body = enroll_response.get_json()
    membership = enroll_body["membership"]

    assert enroll_response.status_code == 201
    assert membership["appPrivileges"] == ["view", "operate"]
    assert membership["infraGroupsOverride"] is None
    assert membership["effectiveInfraGroups"] == ["redteam", "volunteer"]
    assert membership["infrastructureState"] == "pending_enable"

    update_response = client.patch(
        f"/api/engagements/eng-of02-dev/team/{membership['id']}",
        json={"infraGroupsOverride": ["redteam", "core"], "appPrivileges": ["view", "administer"]},
    )
    update_body = update_response.get_json()

    assert update_response.status_code == 200
    assert update_body["membership"]["effectiveInfraGroups"] == ["redteam", "core"]
    assert update_body["membership"]["appPrivileges"] == ["view", "administer"]
    assert update_body["membership"]["infrastructureState"] == "pending_enable"

    inherit_response = client.patch(
        f"/api/engagements/eng-of02-dev/team/{membership['id']}",
        json={"inheritInfraGroups": True},
    )
    inherit_body = inherit_response.get_json()

    assert inherit_response.status_code == 200
    assert inherit_body["membership"]["infraGroupsOverride"] is None
    assert inherit_body["membership"]["effectiveInfraGroups"] == ["redteam", "volunteer"]


def test_deactivated_global_members_cannot_be_included_in_engagement(client):
    member = client.post("/api/team", json={"username": "operator_deactivated"}).get_json()["member"]
    client.post(f"/api/team/{member['id']}/deactivate")

    response = client.post("/api/engagements/eng-of02-dev/team", json={"memberId": member["id"]})
    body = response.get_json()

    assert response.status_code == 400
    assert "deactivated global team members" in body["errors"][0]


def test_membership_removal_preserves_history_and_sets_pending_disable(client):
    member = client.post("/api/team", json={"username": "operator_removed"}).get_json()["member"]
    membership = client.post("/api/engagements/eng-of02-dev/team", json={"memberId": member["id"]}).get_json()["membership"]

    response = client.delete(f"/api/engagements/eng-of02-dev/team/{membership['id']}")
    body = response.get_json()

    assert response.status_code == 200
    assert body["membership"]["status"] == "removed"
    assert body["membership"]["infraAccessEnabled"] is False
    assert body["membership"]["infrastructureState"] == "pending_disable"
    assert body["membership"]["removedAt"] is not None


def test_global_deactivation_marks_existing_engagement_memberships_pending_disable(client):
    member = client.post("/api/team", json={"username": "operator_offboard"}).get_json()["member"]
    membership = client.post("/api/engagements/eng-of02-dev/team", json={"memberId": member["id"]}).get_json()["membership"]

    client.post(f"/api/team/{member['id']}/deactivate")
    response = client.get("/api/engagements/eng-of02-dev/team")
    body = response.get_json()
    updated = next(candidate for candidate in body["memberships"] if candidate["id"] == membership["id"])

    assert response.status_code == 200
    assert updated["member"]["status"] == "deactivated"
    assert updated["infrastructureState"] == "pending_disable"


def test_reactivation_is_explicit_after_key_addition_and_preserves_identity(client):
    member = client.post("/api/team", json={"username": "operator_returning", "desiredUid": 6201}).get_json()["member"]
    membership = client.post("/api/engagements/eng-of02-dev/team", json={"memberId": member["id"]}).get_json()["membership"]
    old_key = client.post(f"/api/team/{member['id']}/ssh-keys", json={"publicKey": PUBLIC_KEY}).get_json()["sshKey"]
    retired = client.delete(f"/api/team/{member['id']}/ssh-keys/{old_key['id']}")
    assert retired.status_code == 200
    client.post(f"/api/team/{member['id']}/deactivate")
    keyed = client.post(f"/api/team/{member['id']}/ssh-keys", json={"publicKey": "ssh-ed25519 cmVwbGFjZW1lbnQta2V5 returning"}).get_json()["member"]
    assert keyed["status"] == "deactivated"
    assert keyed["deactivatedAt"] is not None

    response = client.patch(f"/api/team/{member['id']}", json={"status": "active"})
    assert response.status_code == 200
    restored = response.get_json()["member"]
    assert restored["id"] == member["id"]
    assert restored["desiredUid"] == 6201
    assert restored["status"] == "active"
    assert restored["deactivatedAt"] is None
    assert next(key for key in restored["sshKeys"] if key["id"] == old_key["id"])["status"] == "retired"
    workspace = client.get("/api/engagements/eng-of02-dev/team").get_json()
    restored_membership = next(row for row in workspace["memberships"] if row["id"] == membership["id"])
    assert restored_membership["infrastructureState"] == "pending_enable"


def test_access_plan_targets_core_hosts_and_excludes_sketch(client):
    member = client.post("/api/team", json={"username": "operator4"}).get_json()["member"]
    key_response = client.post(
        f"/api/team/{member['id']}/ssh-keys",
        json={"label": "piv", "publicKey": PUBLIC_KEY},
    )
    key_body = key_response.get_json()
    client.post(
        "/api/engagements/eng-of02-dev/team",
        json={
            "memberId": member["id"],
            "appPrivileges": ["view", "operate"],
            "infraGroupsOverride": ["redteam", "infra"],
        },
    )

    response = client.post("/api/engagements/eng-of02-dev/team/access-plan")
    body = response.get_json()
    plan = body["plan"]

    assert response.status_code == 201
    assert plan["targetHosts"] == ["homebase", "proxy01", "proxy02"]
    assert plan["sketchTargets"] == []
    assert plan["coreUsers"][0]["username"] == "operator4"
    assert plan["coreUsers"][0]["infraGroups"] == ["redteam", "infra"]
    assert plan["coreUsers"][0]["sshKeyFingerprints"] == [key_body["sshKey"]["fingerprint"]]


def test_access_apply_returns_validation_error_without_core_deployment(client):
    member = client.post("/api/team", json={"username": "operator5"}).get_json()["member"]
    client.post(f"/api/team/{member['id']}/ssh-keys", json={"label": "piv", "publicKey": PUBLIC_KEY})
    client.post("/api/engagements/eng-of02-dev/team", json={"memberId": member["id"]})

    response = client.post("/api/engagements/eng-of02-dev/team/access-apply", json={"requestedBy": "tester"})
    body = response.get_json()

    assert response.status_code == 400
    assert "connectionDetails" in body["errors"][0] or "ansible-playbook" in body["errors"][0]


def test_access_apply_runs_mocked_ansible_and_marks_memberships_enabled_disabled(client, tmp_path, monkeypatch):
    _isolated_known_hosts_root(monkeypatch, tmp_path)
    ansible_playbook = _fake_ansible_playbook(tmp_path)
    enabled_member = client.post("/api/team", json={"username": "operator_apply"}).get_json()["member"]
    disabled_member = client.post("/api/team", json={"username": "operator_disable"}).get_json()["member"]
    client.post(f"/api/team/{enabled_member['id']}/ssh-keys", json={"label": "piv", "publicKey": PUBLIC_KEY})
    client.post(f"/api/team/{disabled_member['id']}/ssh-keys", json={"label": "piv", "publicKey": "ssh-ed25519 ZGlzYWJsZWQtdGVzdC1rZXk= disabled"})
    enabled_membership = client.post("/api/engagements/eng-of02-dev/team", json={"memberId": enabled_member["id"]}).get_json()["membership"]
    disabled_membership = client.post("/api/engagements/eng-of02-dev/team", json={"memberId": disabled_member["id"]}).get_json()["membership"]
    client.delete(f"/api/engagements/eng-of02-dev/team/{disabled_membership['id']}")

    calls = []

    def runner(command, cwd):
        calls.append((command, cwd))
        return subprocess.CompletedProcess(command, 0, "changed=3", "")

    with client.application.storage_context():
        _seed_core_connection_details("eng-of02-dev")
        result = start_engagement_access_apply(
            "eng-of02-dev",
            requested_by="tester",
            runner=runner,
            env={"ANSIBLE_PLAYBOOK_PATH": str(ansible_playbook), "PATH": ""},
            workspace_root=tmp_path / "access-workspaces",
            background_runner=lambda task: task(),
        )

    assert result is not None
    assert result["status"] == "running"
    assert result["job"]["action"] == "engagement_access_apply"
    assert result["plan"]["liveApply"] is True
    with client.application.storage_context():
        stored_job = SqlAlchemyJobRepository().get(result["job"]["id"])
    assert stored_job is not None
    final_job = stored_job.to_detail().to_dict()
    assert final_job["status"] == "succeeded"
    assert any(event["message"] == "sketch targets omitted for OPSEC" for event in final_job["events"])
    assert len(calls) == 1
    command, cwd = calls[0]
    assert command[-1] == "ansible/apply_core_access.yml"
    inventory = (cwd / "ansible/inventory.ini").read_text(encoding="utf-8")
    vars_file = (cwd / "ansible/group_vars/core_access.yml").read_text(encoding="utf-8")
    playbook = (cwd / "ansible/apply_core_access.yml").read_text(encoding="utf-8")
    assert "[core_hosts]" in inventory
    assert "homebase ansible_host=203.0.113.10" in inventory
    assert "proxy01 ansible_host=10.0.2.11" in inventory
    assert "proxy02 ansible_host=10.0.2.12" in inventory
    assert f"UserKnownHostsFile={tmp_path}/known-hosts/eng-of02-dev-job-core-eng-of02-dev.known_hosts" in inventory
    assert "ProxyCommand" in inventory
    assert "\nmiddle" not in inventory
    assert "\nedge" not in inventory
    assert "operator_apply" in vars_file
    assert enabled_member["desiredUid"] == 6000
    assert '"desired_uid": 6000' in vars_file
    assert "operator_disable" in vars_file
    assert "Refuse to change existing operator UID without explicit remediation" in playbook
    assert 'uid: "{{ item.desired_uid if item.desired_uid is not none else omit }}"' in playbook
    assert "Ensure homebase VNC skeleton is available" in playbook
    assert "/etc/skel/.vnc/xstartup" in playbook
    assert "/etc/skel/.config/systemd/user/vncserver@.service" in playbook
    assert "Ensure active operator VNC directories exist on homebase" in playbook
    assert "Enable and start active operator VNC user services on homebase" in playbook
    assert 'when: inventory_hostname == "homebase"' in playbook
    assert "loginctl enable-linger" in playbook
    assert "display=\"$((uid - 6000 + 1))\"" in playbook
    assert "vncserver@${display}.service" in playbook
    # Exercise the rendered shell arithmetic with the saved automatic UID.
    display_line = next(line.strip() for line in playbook.splitlines() if line.strip().startswith('display="$((uid - 6000 + 1))"'))
    rendered_display = subprocess.run(["/bin/sh", "-c", f'uid={enabled_member["desiredUid"]}; {display_line}; printf "%s:%s" "$display" "$((5900 + display))"'], check=True, capture_output=True, text=True)
    assert rendered_display.stdout == "1:5901"
    assert "authorized_keys" in playbook
    team_body = client.get("/api/engagements/eng-of02-dev/team").get_json()
    memberships = {candidate["id"]: candidate for candidate in team_body["memberships"]}
    assert memberships[enabled_membership["id"]]["infrastructureState"] == "enabled"
    assert memberships[disabled_membership["id"]]["infrastructureState"] == "disabled"
    assert memberships[enabled_membership["id"]]["applyJobId"] == result["job"]["id"]


def test_access_apply_uses_only_deployed_proxy_for_one_proxy_core(client, tmp_path, monkeypatch):
    _isolated_known_hosts_root(monkeypatch, tmp_path)
    ansible_playbook = _fake_ansible_playbook(tmp_path)
    member = client.post("/api/team", json={"username": "operator_one_proxy"}).get_json()["member"]
    client.post(f"/api/team/{member['id']}/ssh-keys", json={"label": "piv", "publicKey": PUBLIC_KEY})
    client.post("/api/engagements/eng-of02-dev/team", json={"memberId": member["id"]})
    calls = []

    def runner(command, cwd):
        calls.append((command, cwd))
        return subprocess.CompletedProcess(command, 0, "changed=2", "")

    with client.application.storage_context():
        _seed_core_connection_details("eng-of02-dev", include_proxy02=False)
        result = start_engagement_access_apply(
            "eng-of02-dev",
            requested_by="tester",
            runner=runner,
            env={"ANSIBLE_PLAYBOOK_PATH": str(ansible_playbook), "PATH": ""},
            workspace_root=tmp_path / "access-workspaces",
            background_runner=lambda task: task(),
        )

    assert result is not None
    assert result["plan"]["targetHosts"] == ["homebase", "proxy01"]
    assert len(calls) == 1
    inventory = (calls[0][1] / "ansible/inventory.ini").read_text(encoding="utf-8")
    assert "homebase ansible_host=203.0.113.10" in inventory
    assert "proxy01 ansible_host=10.0.2.11" in inventory
    assert "proxy02" not in inventory
    with client.application.storage_context():
        stored_job = SqlAlchemyJobRepository().get(result["job"]["id"])
    assert stored_job is not None
    assert stored_job.events[0].data["inventoryTargets"] == ["homebase", "proxy01"]


def test_access_apply_returns_running_job_before_background_task_runs(client, tmp_path, monkeypatch):
    _isolated_known_hosts_root(monkeypatch, tmp_path)
    ansible_playbook = _fake_ansible_playbook(tmp_path)
    member = client.post("/api/team", json={"username": "operator_async"}).get_json()["member"]
    client.post(f"/api/team/{member['id']}/ssh-keys", json={"label": "piv", "publicKey": PUBLIC_KEY})
    membership = client.post("/api/engagements/eng-of02-dev/team", json={"memberId": member["id"]}).get_json()["membership"]
    background_tasks = []
    calls = []

    def runner(command, cwd):
        calls.append((command, cwd))
        return subprocess.CompletedProcess(command, 0, "changed=1", "")

    with client.application.storage_context():
        _seed_core_connection_details("eng-of02-dev")
        result = start_engagement_access_apply(
            "eng-of02-dev",
            requested_by="tester",
            runner=runner,
            env={"ANSIBLE_PLAYBOOK_PATH": str(ansible_playbook), "PATH": ""},
            workspace_root=tmp_path / "access-workspaces",
            background_runner=background_tasks.append,
        )

    assert result is not None
    assert result["status"] == "running"
    assert result["job"]["status"] == "running"
    assert background_tasks
    assert calls == []
    team_body = client.get("/api/engagements/eng-of02-dev/team").get_json()
    updated = next(candidate for candidate in team_body["memberships"] if candidate["id"] == membership["id"])
    assert updated["infrastructureState"] == "pending_enable"

    with client.application.storage_context():
        background_tasks[0]()

    assert len(calls) == 1
    team_body = client.get("/api/engagements/eng-of02-dev/team").get_json()
    updated = next(candidate for candidate in team_body["memberships"] if candidate["id"] == membership["id"])
    assert updated["infrastructureState"] == "enabled"


def test_access_apply_preserves_pending_state_when_ansible_fails(client, tmp_path, monkeypatch):
    _isolated_known_hosts_root(monkeypatch, tmp_path)
    ansible_playbook = _fake_ansible_playbook(tmp_path)
    member = client.post("/api/team", json={"username": "operator_failed"}).get_json()["member"]
    client.post(f"/api/team/{member['id']}/ssh-keys", json={"label": "piv", "publicKey": PUBLIC_KEY})
    membership = client.post("/api/engagements/eng-of02-dev/team", json={"memberId": member["id"]}).get_json()["membership"]

    def runner(command, cwd):
        return subprocess.CompletedProcess(command, 2, "", "failed")

    with client.application.storage_context():
        _seed_core_connection_details("eng-of02-dev")
        result = start_engagement_access_apply(
            "eng-of02-dev",
            requested_by="tester",
            runner=runner,
            env={"ANSIBLE_PLAYBOOK_PATH": str(ansible_playbook), "PATH": ""},
            workspace_root=tmp_path / "access-workspaces",
            background_runner=lambda task: task(),
        )

    assert result is not None
    assert result["status"] == "running"
    with client.application.storage_context():
        stored_job = SqlAlchemyJobRepository().get(result["job"]["id"])
    assert stored_job is not None
    assert stored_job.status == "failed"
    team_body = client.get("/api/engagements/eng-of02-dev/team").get_json()
    updated = next(candidate for candidate in team_body["memberships"] if candidate["id"] == membership["id"])
    assert updated["infrastructureState"] == "pending_enable"
    assert updated["applyJobId"] == result["job"]["id"]


def test_access_apply_rejects_pending_enable_without_active_ssh_key(client, tmp_path):
    ansible_playbook = _fake_ansible_playbook(tmp_path)
    member = client.post("/api/team", json={"username": "operator_nokey"}).get_json()["member"]
    client.post("/api/engagements/eng-of02-dev/team", json={"memberId": member["id"]})

    with client.application.storage_context():
        _seed_core_connection_details("eng-of02-dev")
        try:
            start_engagement_access_apply(
                "eng-of02-dev",
                requested_by="tester",
                runner=lambda command, cwd: subprocess.CompletedProcess(command, 0, "", ""),
                env={"ANSIBLE_PLAYBOOK_PATH": str(ansible_playbook), "PATH": ""},
                workspace_root=tmp_path / "access-workspaces",
            )
        except TeamAccessValidationError as exc:
            assert exc.errors == ["active infrastructure users need at least one active SSH public key: operator_nokey"]
        else:
            raise AssertionError("expected TeamAccessValidationError")


def _fake_ansible_playbook(tmp_path: Path) -> Path:
    executable = tmp_path / "ansible-playbook"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    return executable


def _seed_core_connection_details(engagement_id: str, *, include_proxy02: bool = True) -> None:
    connection_details = [
        {
            "role": "homebase",
            "displayName": "homebase-of02-dev",
            "publicIp": "203.0.113.10",
            "privateIp": "10.0.1.10",
            "sshUser": "opc",
        },
        {
            "role": "proxy",
            "displayName": "proxy01-of02-dev",
            "publicIp": "203.0.113.11",
            "privateIp": "10.0.2.11",
            "sshUser": "opc",
        },
    ]
    if include_proxy02:
        connection_details.append(
            {
                "role": "proxy",
                "displayName": "proxy02-of02-dev",
                "publicIp": "203.0.113.12",
                "privateIp": "10.0.2.12",
                "sshUser": "opc",
            }
        )
    SqlAlchemyJobRepository().save(
        StoredJobRun(
            id=f"job-core-{engagement_id}",
            action="pilot_standard_rti_guarded_execute",
            status="succeeded",
            target=f"engagement:{engagement_id}",
            target_type="engagement",
            target_id=engagement_id,
            requested_by="tester",
            input={"engagementId": engagement_id},
            artifact_refs=[],
            created_at="2026-06-24T00:00:00+00:00",
            started_at="2026-06-24T00:00:00+00:00",
            finished_at="2026-06-24T00:01:00+00:00",
            events=[
                JobEvent(
                    1,
                    "info",
                    "core connection details ready",
                    {
                        "connectionDetails": connection_details
                    },
                )
            ],
        )
    )


def test_unsupported_infrastructure_group_is_rejected(client):
    response = client.post(
        "/api/team",
        json={"username": "operator6", "defaultInfraGroups": ["redteam", "wheel"]},
    )
    body = response.get_json()

    assert response.status_code == 400
    assert "unsupported infrastructure group" in body["errors"][0]


def test_legacy_linux_group_names_are_rejected_as_global_roles(client):
    response = client.post(
        "/api/team",
        json={"username": "operator7", "globalRoles": ["redteam"]},
    )
    body = response.get_json()

    assert response.status_code == 400
    assert "unsupported global role" in body["errors"][0]


def test_users_json_import_previews_and_applies_conservative_updates(client):
    member = client.post(
        "/api/team",
        json={"username": "importuser", "displayName": "Old Name", "defaultInfraGroups": ["redteam", "volunteer"]},
    ).get_json()["member"]
    encoded_keys = base64.b64encode(PUBLIC_KEY.encode("utf-8")).decode("ascii")
    content = {
        "users": [
            {
                "uid": 6100,
                "username": "importuser",
                "name": "Imported User",
                "tags": ["redteam", "core", "infra"],
                "authorized_keys": encoded_keys,
            },
            {
                "uid": 6101,
                "username": "newuser",
                "name": "New User",
                "tags": ["redteam", "volunteer"],
                "authorized_keys": "",
            },
        ]
    }

    preview_response = client.post(
        "/api/team/import/preview",
        json={"format": "json", "fileName": "users.json", "content": json.dumps(content)},
    )
    preview = preview_response.get_json()["preview"]

    assert preview_response.status_code == 200
    assert preview["summary"]["creates"] == 1
    assert preview["summary"]["updates"] == 1
    assert preview["summary"]["keyAdditions"] == 1
    import_record = next(record for record in preview["records"] if record["username"] == "importuser")
    assert import_record["memberId"] == member["id"]
    assert import_record["desiredUid"] == 6100
    assert import_record["changes"] == ["displayName", "desiredUid", "defaultInfraGroups", "sshKeys"]
    assert "not deactivated" in preview["warnings"][0]

    apply_response = client.post(
        "/api/team/import/apply",
        json={"format": "json", "fileName": "users.json", "content": json.dumps(content)},
    )
    body = apply_response.get_json()

    assert apply_response.status_code == 202
    assert body["applied"]["created"] == ["newuser"]
    assert body["applied"]["updated"] == ["importuser"]
    assert body["applied"]["keyAdditions"] == 1
    members = {candidate["username"]: candidate for candidate in body["team"]["members"]}
    assert members["importuser"]["displayName"] == "Imported User"
    assert members["importuser"]["desiredUid"] == 6100
    assert members["importuser"]["defaultInfraGroups"] == ["redteam", "core", "infra"]
    assert len(members["importuser"]["sshKeys"]) == 1
    assert members["newuser"]["status"] == "deactivated"
    assert members["newuser"]["desiredUid"] == 6101


def test_users_yml_import_parses_generated_ansible_user_file(client):
    content = f"""
---
- name: Ensure users are configured
  hosts: all
  become: true
  tasks:
    - name: Add user yamluser
      ansible.builtin.user:
        name: yamluser
        comment: "Yaml User"
        shell: /bin/bash
        uid: 6200
        password: "*"
        state: present
        group: redteam
        groups: core, infra

    - name: Add ssh public key for yamluser
      ansible.posix.authorized_key:
        user: yamluser
        state: present
        exclusive: true
        key: |
          {PUBLIC_KEY}
"""

    preview_response = client.post(
        "/api/team/import/preview",
        json={"format": "yml", "fileName": "users.yml", "content": content},
    )
    preview = preview_response.get_json()["preview"]

    assert preview_response.status_code == 200
    assert preview["summary"]["creates"] == 1
    assert preview["summary"]["keyAdditions"] == 1
    record = preview["records"][0]
    assert record["username"] == "yamluser"
    assert record["displayName"] == "Yaml User"
    assert record["desiredUid"] == 6200
    assert record["defaultInfraGroups"] == ["redteam", "core", "infra"]


def test_team_import_rejects_duplicate_or_unsafe_uids(client):
    content = {
        "users": [
            {
                "uid": 6100,
                "username": "uidone",
                "name": "UID One",
                "tags": ["redteam"],
                "authorized_keys": "",
            },
            {
                "uid": 6100,
                "username": "uidtwo",
                "name": "UID Two",
                "tags": ["redteam"],
                "authorized_keys": "",
            },
            {
                "uid": 1001,
                "username": "systemuid",
                "name": "System UID",
                "tags": ["redteam"],
                "authorized_keys": "",
            },
        ]
    }

    preview_response = client.post(
        "/api/team/import/preview",
        json={"format": "json", "fileName": "users.json", "content": json.dumps(content)},
    )
    preview = preview_response.get_json()["preview"]

    assert preview_response.status_code == 200
    records = {record["username"]: record for record in preview["records"]}
    assert records["uidtwo"]["action"] == "invalid"
    assert "duplicate desired UID" in records["uidtwo"]["errors"][0]
    assert records["systemuid"]["action"] == "invalid"
    assert "between 6000 and 64999" in records["systemuid"]["errors"][0]


def test_team_import_marks_invalid_records_without_mutating(client):
    content = {
        "users": [
            {
                "uid": 6100,
                "username": "baduser",
                "name": "Bad User",
                "tags": ["wheel"],
                "authorized_keys": base64.b64encode(b"-----BEGIN OPENSSH PRIVATE KEY-----").decode("ascii"),
            }
        ]
    }

    apply_response = client.post(
        "/api/team/import/apply",
        json={"format": "json", "fileName": "users.json", "content": json.dumps(content)},
    )
    body = apply_response.get_json()

    assert apply_response.status_code == 202
    assert body["preview"]["summary"]["invalid"] == 1
    assert body["applied"]["skipped"][0]["username"] == "baduser"
    assert "unsupported infrastructure group" in body["applied"]["skipped"][0]["errors"][0]
    members = {candidate["username"] for candidate in body["team"]["members"]}
    assert "baduser" not in members


def test_current_spec_ssh_users_files_preview_successfully(client):
    users_json = (REPO_ROOT / "spec/ssh/users.json").read_text(encoding="utf-8")
    users_yml = (REPO_ROOT / "spec/ssh/users.yml").read_text(encoding="utf-8")

    json_response = client.post(
        "/api/team/import/preview",
        json={"format": "json", "fileName": "users.json", "content": users_json},
    )
    yml_response = client.post(
        "/api/team/import/preview",
        json={"format": "yml", "fileName": "users.yml", "content": users_yml},
    )
    json_preview = json_response.get_json()["preview"]
    yml_preview = yml_response.get_json()["preview"]

    assert json_response.status_code == 200
    assert yml_response.status_code == 200
    assert json_preview["summary"]["invalid"] == 0
    assert yml_preview["summary"]["invalid"] == 0
    assert json_preview["summary"]["creates"] >= yml_preview["summary"]["creates"] >= 1
    assert any(record["username"] == "example_operator" for record in json_preview["records"])
    assert any(record["username"] == "aluvshis" for record in yml_preview["records"])


def test_legacy_import_status_follows_file_keys_and_preserves_unlisted_members(client, monkeypatch):
    def no_host_work(*args, **kwargs):
        raise AssertionError("legacy import must not start host work")

    monkeypatch.setattr(team_access, "start_runtime_task", no_host_work)
    credentials_before = AuthenticationCredentialModel.query.count()
    member = client.post("/api/team", json={"username": "legacyuser"}).get_json()["member"]
    client.post(f"/api/team/{member['id']}/ssh-keys", json={"publicKey": PUBLIC_KEY})
    membership = client.post("/api/engagements/eng-of02-dev/team", json={"memberId": member["id"]}).get_json()["membership"]
    absent = client.post("/api/team", json={"username": "absentuser"}).get_json()["member"]
    body = {"format": "json", "content": json.dumps({"users": [{"username": "legacyuser"}]})}
    preview = client.post("/api/team/import/preview", json=body).get_json()["preview"]
    assert preview["records"][0]["status"] == "deactivated"
    assert "status" in preview["records"][0]["changes"]
    # Preview does not change persisted member status.
    assert next(row for row in client.get("/api/team").get_json()["members"] if row["id"] == member["id"])["status"] == "active"
    result = client.post("/api/team/import/apply", json=body).get_json()
    members = {row["id"]: row for row in result["team"]["members"]}
    assert members[member["id"]]["status"] == "deactivated"
    assert members[member["id"]]["deactivatedAt"] is not None
    assert len(members[member["id"]]["sshKeys"]) == 1
    assert members[member["id"]]["sshKeys"][0]["status"] == "active"
    assert members[absent["id"]]["status"] == "active"
    memberships = client.get("/api/engagements/eng-of02-dev/team").get_json()["memberships"]
    assert next(row for row in memberships if row["id"] == membership["id"])["infrastructureState"] == "pending_disable"
    repeat = client.post("/api/team/import/apply", json=body).get_json()
    assert repeat["applied"]["unchanged"] == ["legacyuser"]
    encoded = base64.b64encode(PUBLIC_KEY.encode()).decode()
    body["content"] = json.dumps({"users": [{"username": "legacyuser", "authorized_keys": encoded}]})
    result = client.post("/api/team/import/apply", json=body).get_json()
    assert result["preview"]["records"][0]["status"] == "active"
    restored = next(row for row in result["team"]["members"] if row["id"] == member["id"])
    assert restored["status"] == "active"
    assert restored["deactivatedAt"] is None
    assert len(restored["sshKeys"]) == 1
    assert result["applied"]["keyAdditions"] == 0
    assert AuthenticationCredentialModel.query.count() == credentials_before


def test_legacy_json_malformed_key_never_deactivates_existing_member(client):
    member = client.post("/api/team", json={"username": "invalidkey"}).get_json()["member"]
    for key in ["!!!!", base64.b64encode(b"not-an-ssh-key").decode(), base64.b64encode(PUBLIC_KEY.encode()).decode() + "!"]:
        result = client.post("/api/team/import/apply", json={"format": "json", "content": json.dumps({"users": [{"username": "invalidkey", "authorized_keys": key}]})}).get_json()
        assert result["preview"]["records"][0]["action"] == "invalid"
        assert result["preview"]["records"][0]["status"] is None
        assert result["applied"]["skipped"][0]["username"] == "invalidkey"
        assert next(row for row in result["team"]["members"] if row["id"] == member["id"])["status"] == "active"


def test_legacy_yml_missing_key_task_deactivates_and_invalid_key_is_rejected(client):
    content = """
- name: Ensure users are configured
  hosts: all
  tasks:
    - name: Add user inactiveuser
      ansible.builtin.user:
        name: inactiveuser
        group: redteam
        groups: volunteer
    - name: Add user badyamluser
      ansible.builtin.user:
        name: badyamluser
        group: redteam
        groups: volunteer
    - name: Add ssh public key for badyamluser
      ansible.posix.authorized_key:
        user: badyamluser
        key: 'not-an-ssh-key'
"""
    result = client.post("/api/team/import/apply", json={"format": "yml", "content": content}).get_json()
    records = {row["username"]: row for row in result["preview"]["records"]}
    assert records["inactiveuser"]["status"] == "deactivated"
    assert records["badyamluser"]["action"] == "invalid"
    assert records["badyamluser"]["status"] is None
    created = next(row for row in result["team"]["members"] if row["username"] == "inactiveuser")
    assert created["status"] == "deactivated"
    assert created["deactivatedAt"] is not None
    assert result["applied"]["skipped"][0]["username"] == "badyamluser"


def test_legacy_keyed_reactivation_does_not_enable_disabled_app_credential(client):
    member = client.post("/api/team", json={"username": "disabledlogin"}).get_json()["member"]
    deactivated = client.post(f"/api/team/{member['id']}/deactivate").get_json()["member"]
    assert deactivated["status"] == "deactivated"
    credential = AuthenticationCredentialModel(
        id="credential-disabled-import-test",
        team_member_id=member["id"],
        password_hash="disabled-test-fixture-hash",
        enabled=False,
    )
    db.session.add(credential)
    db.session.commit()
    credentials_before = AuthenticationCredentialModel.query.count()
    encoded = base64.b64encode(PUBLIC_KEY.encode()).decode()
    result = client.post("/api/team/import/apply", json={
        "format": "json",
        "content": json.dumps({"users": [{"username": "disabledlogin", "authorized_keys": encoded}]}),
    }).get_json()
    restored = next(row for row in result["team"]["members"] if row["id"] == member["id"])
    assert restored["status"] == "active"
    # Import changes member status, but neither creates nor enables login credentials.
    # An independently enabled credential remains subject to normal auth member checks.
    assert AuthenticationCredentialModel.query.count() == credentials_before
    stored = db.session.get(AuthenticationCredentialModel, "credential-disabled-import-test")
    assert stored.enabled is False
    assert stored.password_hash == "disabled-test-fixture-hash"
