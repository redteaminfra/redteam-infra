# Copyright (c) 2026, Oracle and/or its affiliates.
"""The local operator guide is generated within the owned-stack transaction."""
import json

import yaml

from app.services.web_static_service import (
    WebStaticCoreHost, _intent_from_body, render_web_static_apply_workspace,
)


def _all_tasks(tasks):
    for task in tasks:
        yield task
        for key in ("block", "rescue", "always"):
            yield from _all_tasks(task.get(key, []))


def test_web_directory_guide_scope_mounts_and_ownership_order():
    intent = _intent_from_body("example", {"siteName": "independent-site", "domain": "www.example.invalid"})
    homebase = WebStaticCoreHost("homebase", "203.0.113.10", "user", "/keys/core", "", "/tmp/known")
    proxy = WebStaticCoreHost("proxy01", "192.168.2.11", "user", "/keys/core", "user@203.0.113.10", "/tmp/known")
    workspace = render_web_static_apply_workspace(intent=intent, homebase=homebase, proxy=proxy)
    tasks = list(_all_tasks(yaml.safe_load(workspace.playbook.content)[0]["tasks"]))
    names = [task.get("name", "") for task in tasks]
    task = tasks[names.index("Create web directory guide")]
    copy = task["ansible.builtin.copy"]
    assert copy["dest"] == "/opt/web/README.md"
    assert copy["owner"] == "root" and copy["group"] == "redteam"
    assert copy["mode"] == "0644"
    assert copy["force"] is False and copy["follow"] is False
    assert names.index("Refuse to mutate an unowned shared front stack") < names.index("Create web directory guide")
    assert names.index("Record Barragan proxy-stack ownership") < names.index("Create web directory guide")
    text = copy["content"]
    for value in ("/opt/web/<site>/html/", "/opt/web/<site>/conf/", "/opt/web/<site>/tls-conf/",
                  "/opt/web/sites/<site>.compose.yml", "/var/www/html/<site>/", "/etc/nginx/conf.d/",
                  "/usr/local/openresty/nginx/conf/nginx.conf", "/etc/openresty/http/",
                  "/etc/openresty/tls/", "/etc/openresty/streams/", "edge/middle transport",
                  "not necessarily its DNS hostname", "Apply can publish supplied content", "/dropbox"):
        assert value in text
    for private in (intent.site_name, intent.domain, homebase.ansible_host, proxy.ansible_host,
                    "/keys/core", "WI-", "DevTest", "worktree"):
        assert private not in text
    # The guide participates in the existing exact-path backup/restore boundary.
    assert "'/opt/web/README.md'" in workspace.playbook.content
    assert "Restore exact selected runtime files" in names
    # It is not published as a file in a site's document root.
    assert all(not artifact.target.endswith("README.md") for artifact in workspace.content_files)
    assert json.loads(workspace.manifest.content)["service"]["siteName"] == "independent-site"
