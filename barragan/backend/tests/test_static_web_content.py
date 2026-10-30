# Copyright (c) 2026, Oracle and/or its affiliates.
import base64
import json
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.core.request_identity import RequestIdentity, bind_request_identity
from app.services import static_web_content as content
from app.services import web_static_service as service
from test_web_static_service import _FakeJobRepository, _core_jobs

STARTER = service.DEFAULT_INDEX_HTML.encode()


@pytest.fixture(autouse=True)
def local_redteam_group(monkeypatch):
    monkeypatch.setattr(content.grp, "getgrnam", lambda name: type("Group", (), {"gr_gid": os.getgid()})())


@pytest.fixture
def site(tmp_path):
    root = tmp_path / "web"
    root.mkdir()
    (root / ".barragan-stack.json").write_text(json.dumps(content.OWNER))
    directory = root / "site01" / "html"
    directory.mkdir(parents=True)
    return root, directory


def _request(root, action="preserve", files=None):
    return {"mode": "apply", "root": str(root), "site": "site01", "action": action,
            "fingerprint": content.inspect_content(root, "site01")["fingerprint"],
            "starter": base64.b64encode(STARTER).decode(), "files": files or [],
            "conflicts": str(root.parent / "private-conflicts")}


def test_empty_initializes_exclusively_and_rolls_back_only_own_index(site):
    root, directory = site
    request = _request(root)
    result = content.apply_content(request)
    assert result["outcome"] == "initialized"
    assert (directory / "index.html").read_bytes() == STARTER
    (directory / "upload.txt").write_text("concurrent operator asset")
    content.rollback_content({**request, **result})
    assert not (directory / "index.html").exists()
    assert (directory / "upload.txt").read_text() == "concurrent operator asset"


@pytest.mark.parametrize("index", [False, True])
def test_preserve_existing_assets_or_index_does_not_touch_bytes_or_attributes(site, index):
    root, directory = site
    (directory / "assets").mkdir()
    (directory / "assets" / "image").write_bytes(b"asset")
    if index:
        (directory / "index.html").write_bytes(b"operator index")
    before = {p: (p.stat().st_mode, p.stat().st_uid, p.stat().st_gid, p.stat().st_mtime_ns, p.read_bytes() if p.is_file() else None) for p in directory.rglob("*")}
    request = _request(root)
    assert content.inspect_content(root, "site01")["state"] == "existing"
    result = content.apply_content(request)
    assert result == {"action": "preserve", "outcome": "preserved", "writes": []}
    content.rollback_content({**request, **result})
    assert before == {p: (p.stat().st_mode, p.stat().st_uid, p.stat().st_gid, p.stat().st_mtime_ns, p.read_bytes() if p.is_file() else None) for p in directory.rglob("*")}
    assert (directory / "index.html").exists() == index


def test_restore_changes_only_index_and_rollback_restores_old_bytes(site):
    root, directory = site
    (directory / "index.html").write_bytes(b"operator content")
    (directory / "asset").write_bytes(b"asset")
    request = _request(root, "restore-starter")
    result = content.apply_content(request)
    assert (directory / "index.html").read_bytes() == STARTER
    (directory / "new-upload").write_bytes(b"new upload")
    content.rollback_content({**request, **result})
    assert (directory / "index.html").read_bytes() == b"operator content"
    assert (directory / "asset").read_bytes() == b"asset"
    assert (directory / "new-upload").read_bytes() == b"new upload"


def test_same_size_changed_bytes_require_fresh_review(site):
    root, directory = site
    (directory / "index.html").write_bytes(b"before")
    request = _request(root, "restore-starter")
    (directory / "index.html").write_bytes(b"after!")
    with pytest.raises(content.ContentError, match="changed since review"):
        content.apply_content(request)
    assert (directory / "index.html").read_bytes() == b"after!"


@pytest.mark.parametrize("kind", ["index-symlink", "ancestor-symlink", "unreadable", "fifo", "directory-index"])
def test_unsafe_paths_fail_closed(site, kind):
    root, directory = site
    outside = root.parent / "outside"
    outside.write_bytes(b"protected")
    if kind == "index-symlink":
        (directory / "index.html").symlink_to(outside)
    elif kind == "ancestor-symlink":
        directory.rmdir()
        target = root.parent / "target"
        target.mkdir()
        directory.symlink_to(target, target_is_directory=True)
    elif kind == "unreadable":
        (directory / "index.html").write_bytes(b"inaccessible")
        (directory / "index.html").chmod(0)
    elif kind == "fifo":
        os.mkfifo(directory / "pipe")
    else:
        (directory / "index.html").mkdir()
    with pytest.raises((content.ContentError, OSError)):
        content.apply_content(_request(root, "restore-starter"))
    assert outside.read_bytes() == b"protected"


def test_oversized_tree_and_unowned_root_are_not_empty(site, monkeypatch):
    root, directory = site
    (directory / "asset").write_bytes(b"abcd")
    monkeypatch.setattr(content, "MAX_BYTES", 3)
    with pytest.raises(content.ContentError):
        content.inspect_content(root, "site01")
    (root / ".barragan-stack.json").unlink()
    with pytest.raises(content.ContentError, match="ownership"):
        content.inspect_content(root, "site01")


def test_upload_between_check_and_write_is_preserved(site):
    root, directory = site
    request = _request(root)
    with pytest.raises(content.ContentError, match="before write"):
        content.apply_content(request, before_write=lambda: (directory / "index.html").write_bytes(b"upload"))
    assert (directory / "index.html").read_bytes() == b"upload"


def test_atomic_exclusive_create_does_not_overwrite_racing_index(site, monkeypatch):
    root, directory = site
    request = _request(root)
    original = content._replace
    def race(fd, name, data, expected, conflicts):
        (directory / "index.html").write_bytes(b"racing upload")
        return original(fd, name, data, expected, conflicts)
    monkeypatch.setattr(content, "_replace", race)
    with pytest.raises(FileExistsError):
        content.apply_content(request)
    assert (directory / "index.html").read_bytes() == b"racing upload"


def test_restore_exchange_conflict_recovers_displaced_operator_bytes(site, monkeypatch):
    root, directory = site
    (directory / "index.html").write_bytes(b"old reviewed")
    request = _request(root, "restore-starter")
    original = content._exchange
    calls = 0
    def race(fd, left, right):
        nonlocal calls
        calls += 1
        if calls == 1:
            (directory / "index.html").write_bytes(b"new operator upload")
        return original(fd, left, right)
    monkeypatch.setattr(content, "_exchange", race)
    with pytest.raises(content.ContentError, match="changed during replacement"):
        content.apply_content(request)
    assert (directory / "index.html").read_bytes() == b"new operator upload"


def test_rollback_refuses_to_replace_post_apply_operator_upload(site):
    root, directory = site
    (directory / "index.html").write_bytes(b"old reviewed")
    request = _request(root, "restore-starter")
    result = content.apply_content(request)
    (directory / "index.html").write_bytes(b"post-apply upload")
    with pytest.raises(content.ContentError, match="rollback preserved"):
        content.rollback_content({**request, **result})
    assert (directory / "index.html").read_bytes() == b"post-apply upload"


def test_explicit_publish_nested_files_is_compatible_and_reversible(site):
    root, directory = site
    (directory / "index.html").write_bytes(b"old index")
    (directory / "asset").write_bytes(b"keep")
    files = [{"path": "index.html", "data": base64.b64encode(b"published index").decode()}, {"path": "nested/page.html", "data": base64.b64encode(b"page").decode()}]
    request = _request(root, "publish", files)
    result = content.apply_content(request)
    assert (directory / "index.html").read_bytes() == b"published index"
    assert (directory / "nested/page.html").read_bytes() == b"page"
    content.rollback_content({**request, **result})
    assert (directory / "index.html").read_bytes() == b"old index"
    assert not (directory / "nested/page.html").exists()
    assert (directory / "asset").read_bytes() == b"keep"


@pytest.fixture
def reviewed_service(site, monkeypatch):
    root, directory = site
    monkeypatch.setattr(service, "get_engagement", lambda _: type("Engagement", (), {"name": "opaque"})())
    monkeypatch.setattr(service, "_inspect_remote_content", lambda intent, *_: {k: v for k, v in content.inspect_content(root, intent.site_name).items() if k != "entries"})
    monkeypatch.setattr("app.services.inbound_request_header_gate.load_active_https_request_header_gate_for_service", lambda *_args, **_kwargs: None)
    repo = _FakeJobRepository(_core_jobs())
    body = {"siteName": "site01", "domain": "opaque.example.invalid", "proxyId": "proxy01"}
    preview = service.preview_web_static_service_apply("eng-zy01", body, repository=repo)
    homebase, proxy = service._core_apply_hosts(repo, "eng-zy01", "proxy01")
    return repo, body, preview, homebase, proxy


def _authorize(reviewed_service, **changes):
    repo, body, preview, homebase, proxy = reviewed_service
    body = {**body, "contentReviewJobId": preview["contentReview"]["reviewJobId"], **changes}
    return service._authorize_content_apply(repo, "eng-zy01", service._intent_from_body("opaque", body), body, "operator", homebase, proxy, None)


def test_review_defaults_to_preserve_and_restore_requires_bound_review(reviewed_service):
    assert reviewed_service[2]["contentReview"]["defaultAction"] == "preserve"
    assert _authorize(reviewed_service).content_action == "preserve"
    assert _authorize(reviewed_service, contentAction="restore-starter").content_action == "restore-starter"
    with pytest.raises(service.WebStaticServiceValidationError):
        _authorize(reviewed_service, contentReviewJobId="")


@pytest.mark.parametrize("change", [{"siteName": "other"}, {"domain": "different.invalid"}, {"proxyId": "proxy02"}, {"indexHtml": "custom", "contentAction": "restore-starter"}])
def test_wrong_site_config_or_payload_cannot_reuse_review(reviewed_service, change):
    with pytest.raises(service.WebStaticServiceValidationError):
        _authorize(reviewed_service, **change)


def test_review_refuses_changed_files_expired_review_and_new_generation(reviewed_service, site):
    repo, _, preview, _, _ = reviewed_service
    (site[1] / "asset").write_bytes(b"upload")
    with pytest.raises(service.WebStaticServiceValidationError):
        _authorize(reviewed_service)
    (site[1] / "asset").unlink()
    review = repo.get(preview["contentReview"]["reviewJobId"])
    repo.save(replace(review, created_at=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()))
    with pytest.raises(service.WebStaticServiceValidationError):
        _authorize(reviewed_service)
    repo.save(review)
    core = repo.get("job-core")
    repo.save(replace(core, id="new-generation"))
    with pytest.raises(service.WebStaticServiceValidationError):
        _authorize(reviewed_service)


def test_authenticated_actor_overrides_forged_requested_by():
    identity = RequestIdentity("member", "real_operator", ("administrator",), "session")
    with bind_request_identity(identity):
        assert service._content_actor("forged") == "real_operator"
    assert service._content_actor("forged") == "operator"


def test_generated_helper_runs_inspection_apply_and_rollback_with_private_journal(site, tmp_path):
    import subprocess
    import sys
    root, directory = site
    (directory / "index.html").write_bytes(b"operator original")
    private = tmp_path / "operation"
    private.mkdir(mode=0o700)
    request = {**_request(root, "restore-starter"), "receipt": str(private / "receipt.json")}
    script = Path(content.__file__)
    def run(mode):
        config = private / f"{mode}.json"
        config.write_text(json.dumps({**request, "mode": mode}))
        bootstrap = "import grp,os,runpy,sys; grp.getgrnam=lambda name:grp.getgrgid(os.getgid()); sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name='__main__')"
        return subprocess.run([sys.executable, "-c", bootstrap, str(script), str(config)], capture_output=True, text=True)
    inspected = run("inspect")
    assert inspected.returncode == 0
    assert "operator original" not in inspected.stdout
    applied = run("apply")
    assert applied.returncode == 0, applied.stdout + applied.stderr
    assert "writes" not in json.loads(applied.stdout)
    assert (private / "receipt.json").stat().st_mode & 0o777 == 0o600
    assert (directory / "index.html").read_bytes() == STARTER
    (directory / "new-asset").write_bytes(b"keep upload")
    restored = run("rollback")
    assert restored.returncode == 0, restored.stdout + restored.stderr
    assert (directory / "index.html").read_bytes() == b"operator original"
    assert (directory / "new-asset").read_bytes() == b"keep upload"


def test_failed_rollback_retains_original_privately(site):
    root, directory = site
    (directory / "index.html").write_bytes(b"operator original")
    request = _request(root, "restore-starter")
    result = content.apply_content(request)
    (directory / "index.html").write_bytes(b"new upload")
    with pytest.raises(content.ContentError):
        content.rollback_content({**request, **result})
    retained = Path(request["conflicts"])
    assert retained.stat().st_mode & 0o777 == 0o700
    assert [p.read_bytes() for p in retained.iterdir()] == [b"operator original"]
    assert (directory / "index.html").read_bytes() == b"new upload"


def test_rendered_transaction_checks_before_mutation_and_excludes_content_backup(reviewed_service):
    import yaml
    _, _, preview, homebase, proxy = reviewed_service
    intent = _authorize(reviewed_service)
    workspace = service.render_web_static_apply_workspace(intent=intent, homebase=homebase, proxy=proxy)
    play = yaml.safe_load(workspace.playbook.content)[0]
    transaction = next(task for task in play["tasks"] if task["name"] == "Apply selected Static Web runtime transactionally")
    names = [task.get("name") for task in transaction["block"]]
    assert names.index("Recheck reviewed content before runtime mutation") < names.index("Snapshot exact selected runtime files") < names.index("Ensure Docker service is running")
    snapshot = next(task for task in transaction["block"] if task.get("name") == "Snapshot exact selected runtime files")["ansible.builtin.shell"]["cmd"]
    assert "'/opt/web/site01'" not in snapshot
    assert "'/opt/web/site01/html'" not in snapshot
    assert "'/opt/web/site01/conf'" in snapshot
    assert "'/opt/web/site01/tls-conf'" in snapshot
    create_dirs = next(task for task in transaction["block"] if task.get("name") == "Create Barragan web directories")
    assert all("/html" not in value for value in create_dirs["loop"])
    assert names.index("Record Barragan proxy-stack ownership") < names.index("Apply reviewed Static Web content policy")
    config = json.loads(next(a.content for a in workspace.sensitive_artifacts if a.target == "helpers/apply.json"))
    assert config["fingerprint"] == preview["contentReview"]["fingerprint"]
    assert config["action"] == "preserve"


def test_new_files_use_redteam_group_and_rollback_restores_original_attributes(site, monkeypatch):
    root, directory = site
    group_lookups = []
    def local_group(name):
        group_lookups.append(name)
        return type("Group", (), {"gr_gid": os.getgid()})()
    monkeypatch.setattr(content.grp, "getgrnam", local_group)
    request = _request(root)
    result = content.apply_content(request)
    index = directory / "index.html"
    assert index.stat().st_gid == os.getgid()
    assert index.stat().st_mode & 0o777 == 0o664
    assert "redteam" in group_lookups
    content.rollback_content({**request, **result})
    index.write_bytes(b"original")
    index.chmod(0o640)
    prior = index.stat()
    request = _request(root, "restore-starter")
    result = content.apply_content(request)
    assert index.stat().st_mode & 0o777 == 0o664
    content.rollback_content({**request, **result})
    restored = index.stat()
    assert index.read_bytes() == b"original"
    assert (restored.st_uid, restored.st_gid, restored.st_mode & 0o777) == (prior.st_uid, prior.st_gid, prior.st_mode & 0o777)


@pytest.mark.parametrize("post_apply", ["delete", "symlink", "unreadable"])
def test_inaccessible_post_apply_index_keeps_all_prior_bytes(site, post_apply):
    root, directory = site
    index = directory / "index.html"
    index.write_bytes(b"operator original")
    request = _request(root, "restore-starter")
    result = content.apply_content(request)
    outside = root.parent / "protected"
    outside.write_bytes(b"outside")
    if post_apply == "delete":
        index.unlink()
    elif post_apply == "symlink":
        index.unlink()
        index.symlink_to(outside)
    else:
        index.chmod(0)
    with pytest.raises(content.ContentError, match="retained prior bytes"):
        content.rollback_content({**request, **result})
    assert b"operator original" in [p.read_bytes() for p in Path(request["conflicts"]).iterdir()]
    assert outside.read_bytes() == b"outside"
    if post_apply == "delete":
        assert not index.exists()
    elif post_apply == "symlink":
        assert index.is_symlink()
    else:
        assert index.stat().st_mode & 0o777 == 0


def test_multi_file_rollback_conflict_retains_every_prior_version(site):
    root, directory = site
    (directory / "index.html").write_bytes(b"old index")
    (directory / "asset").write_bytes(b"old asset")
    files = [{"path": name, "data": base64.b64encode(b"published").decode()} for name in ("index.html", "asset")]
    request = _request(root, "publish", files)
    result = content.apply_content(request)
    (directory / "asset").unlink()
    with pytest.raises(content.ContentError, match="retained prior bytes"):
        content.rollback_content({**request, **result})
    retained = [p.read_bytes() for p in Path(request["conflicts"]).iterdir()]
    assert b"old index" in retained and b"old asset" in retained
    assert (directory / "index.html").read_bytes() == b"old index"
    assert not (directory / "asset").exists()


def test_durable_action_outcome_and_private_journal_retention(reviewed_service):
    import yaml
    _, _, _, homebase, proxy = reviewed_service
    intent = _authorize(reviewed_service, contentAction="restore-starter")
    assert intent.to_dict()["contentAction"] == "restore-starter"
    assert intent.to_dict()["contentReviewJobId"]
    workspace = service.render_web_static_apply_workspace(intent=intent, homebase=homebase, proxy=proxy)
    play = yaml.safe_load(workspace.playbook.content)[0]
    transaction = next(t for t in play["tasks"] if t.get("name") == "Apply selected Static Web runtime transactionally")
    cleanup = next(t for t in transaction["always"] if t.get("ansible.builtin.file", {}).get("path") == "{{ content_operation_root }}")
    assert "static_content_rollback.rc" in cleanup["when"]
    assert "BARRAGAN_STATIC_CONTENT_OUTCOME=" in workspace.playbook.content
    assert service._content_outcome('"msg": "BARRAGAN_STATIC_CONTENT_OUTCOME=restored-starter"') == "restored-starter"
    assert service._content_rollback_outcome('"msg": "BARRAGAN_STATIC_CONTENT_ROLLBACK_RC=0"') == "verified"
    assert service._content_rollback_outcome('"msg": "BARRAGAN_STATIC_CONTENT_ROLLBACK_RC=1"') == "failed"


def test_failed_first_apply_retains_ownership_and_upload_for_fresh_review(reviewed_service, tmp_path):
    import subprocess
    import sys
    import yaml
    _, _, _, homebase, proxy = reviewed_service
    workspace = service.render_web_static_apply_workspace(intent=_authorize(reviewed_service), homebase=homebase, proxy=proxy)
    play = yaml.safe_load(workspace.playbook.content)[0]
    block = next(t for t in play["tasks"] if t.get("name") == "Apply selected Static Web runtime transactionally")
    snapshot = next(t for t in block["block"] if t.get("name") == "Snapshot exact selected runtime files")["ansible.builtin.shell"]["cmd"]
    restore = next(t for t in block["rescue"] if t.get("name") == "Restore exact selected runtime files")["ansible.builtin.shell"]["cmd"]
    fresh = tmp_path / "new-web"
    operation = tmp_path / "rollback"
    def execute(command):
        code = command.split("python3 - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        code = code.replace("/opt/web", str(fresh)).replace(play["vars"]["content_operation_root"] + "/runtime-backup", str(operation))
        subprocess.run([sys.executable, "-c", code], check=True)
    execute(snapshot)
    content_dir = fresh / "site01/html"
    content_dir.mkdir(parents=True)
    (fresh / "site01/conf").mkdir()
    (fresh / ".barragan-stack.json").write_text(json.dumps(content.OWNER))
    (content_dir / "operator-upload").write_bytes(b"keep me")
    execute(restore)
    assert (content_dir / "operator-upload").read_bytes() == b"keep me"
    assert content.inspect_content(fresh, "site01")["state"] == "existing"


def test_new_content_directories_remain_operator_writable_under_restrictive_umask(site):
    root, directory = site
    directory.rmdir()
    original_mask = os.umask(0o077)
    try:
        result = content.apply_content(_request(root))
        assert result["outcome"] == "initialized"
        assert directory.stat().st_mode & 0o777 == 0o775
        assert directory.stat().st_gid == os.getgid()
        request = _request(root, "publish", [{"path": "assets/images/logo.txt", "data": base64.b64encode(b"image").decode()}])
        content.apply_content(request)
        for path in [directory / "assets", directory / "assets/images"]:
            assert path.stat().st_mode & 0o777 == 0o775
            assert path.stat().st_gid == os.getgid()
    finally:
        os.umask(original_mask)


def _protected_content_files(site):
    root, directory = site
    paths = [directory / 'index.html', directory / 'asset',
             root / 'sibling' / 'html' / 'index.html', root.parent / 'outside']
    for number, path in enumerate(paths):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f'protected-{number}'.encode())
        path.chmod(0o640)
    return paths


def _content_file_snapshot(paths, *, timestamps=True):
    result = {}
    for path in paths:
        info = path.stat()
        attributes = (info.st_mode, info.st_uid, info.st_gid)
        if timestamps:
            attributes += (info.st_mtime_ns,)
        result[path] = (path.read_bytes(), attributes)
    return result


@pytest.mark.parametrize('invalid_site', ['', '../outside', '/outside', 'nested/site', 'nested\\site'])
def test_invalid_site_rejects_without_changing_selected_sibling_or_outside_files(site, invalid_site):
    root, _ = site
    paths = _protected_content_files(site)
    before = _content_file_snapshot(paths)
    tree = set(root.parent.rglob('*'))
    request = {**_request(root), 'site': invalid_site}
    with pytest.raises(content.ContentError, match='invalid site path'):
        content.apply_content(request)
    assert _content_file_snapshot(paths) == before
    assert set(root.parent.rglob('*')) == tree


@pytest.mark.parametrize('kind', ['absolute', 'parent-traversal', 'bad-base64'])
def test_invalid_publish_entry_preserves_files_and_creates_no_destinations(site, kind):
    root, _ = site
    paths = _protected_content_files(site)
    before = _content_file_snapshot(paths)
    tree = set(root.parent.rglob('*'))
    entry = {'path': 'new-file', 'data': base64.b64encode(b'write').decode()}
    if kind == 'absolute':
        entry['path'] = str(root.parent / 'outside')
    elif kind == 'parent-traversal':
        entry['path'] = '../../sibling/html/index.html'
    else:
        entry['data'] = 'not valid base64!'
    with pytest.raises((content.ContentError, ValueError)):
        content.apply_content(_request(root, 'publish', [entry]))
    assert _content_file_snapshot(paths) == before
    assert set(root.parent.rglob('*')) == tree


def test_malformed_second_publish_entry_rolls_back_first_without_touching_other_files(site):
    root, _ = site
    paths = _protected_content_files(site)
    before = _content_file_snapshot(paths, timestamps=False)
    untouched = _content_file_snapshot(paths[1:])
    tree = set(root.parent.rglob('*'))
    entries = [{'path': 'index.html', 'data': base64.b64encode(b'explicit replacement').decode()},
               {'path': 'new-file', 'data': 'not valid base64!'}]
    with pytest.raises(ValueError):
        content.apply_content(_request(root, 'publish', entries))
    # Rollback restores bytes/mode/ownership, not original index timestamps.
    assert _content_file_snapshot(paths, timestamps=False) == before
    assert _content_file_snapshot(paths[1:]) == untouched
    assert set(root.parent.rglob('*')) == tree


def test_equal_length_edit_with_restored_mtime_still_requires_fresh_review(site):
    root, directory = site
    paths = _protected_content_files(site)
    index = directory / 'index.html'
    index.write_bytes(b'before')
    request = _request(root, 'restore-starter')
    prior = index.stat()
    index.write_bytes(b'after!')
    os.utime(index, ns=(prior.st_atime_ns, prior.st_mtime_ns))
    assert index.stat().st_size == prior.st_size
    assert index.stat().st_mtime_ns == prior.st_mtime_ns
    before = _content_file_snapshot(paths)
    with pytest.raises(content.ContentError, match='changed since review'):
        content.apply_content(request)
    assert _content_file_snapshot(paths) == before
    # ctime changes too; this is mtime-preserved rejection, not hash-only proof.
