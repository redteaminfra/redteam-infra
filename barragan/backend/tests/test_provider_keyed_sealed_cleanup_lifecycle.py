# Copyright (c) 2026, Oracle and/or its affiliates.
"""Example fixture: sealed HTTP cleanup through the complete canonical SQL flow.

Runs only on Linux with the reviewed offline Terraform prerequisite. Provider
catalogs, command outputs and SSH are simulated by the existing canonical flow;
all cleanup state writers/readers, claims, authority and restart checks are real.
"""
import json
import http.client
import urllib.request
import subprocess
import sys

import pytest

from app.services import web_static_service as web
from app.services import infra_orientation
from app.services import inbound_channel_apply as inbound
from app.services import provider_keyed_published_initial_cleanup_authority as authority
from app.storage.service_repository import SqlAlchemyEngagementServiceRepository
from test_provider_keyed_real_core_canonical_generation import (
    test_real_keyed_core_plan_is_persisted_and_reviewed_after_restart as canonical_flow,
)


@pytest.mark.skipif(sys.platform != "linux", reason="reviewed Terraform release is Linux-only")
def test_sealed_static_web_and_failed_http_complete_real_sql_cleanup_and_restart(tmp_path, monkeypatch):
    phases=[]
    # Fail at the first omitted external seam, before a network attempt. The
    # explicit fake transports below and in the canonical flow remain active.
    def no_default_http(*_args,**_kwargs):
        pytest.fail("offline fixture attempted an unmocked default HTTP(S) transport")
    monkeypatch.setattr(urllib.request,"urlopen",no_default_http)
    monkeypatch.setattr(http.client.HTTPConnection,"connect",no_default_http)
    monkeypatch.setattr(http.client.HTTPSConnection,"connect",no_default_http)
    # Unrelated INFRA.md refresh is outside this cleanup contract. Suppress its
    # scheduler before the first core fixture creates background work, avoiding
    # shared known-host files; no cleanup state writer/reader is replaced.
    monkeypatch.setattr(infra_orientation,"enqueue_infra_orientation_refresh",lambda *_a,**_kw: None)
    monkeypatch.setattr(web,"DEFAULT_KNOWN_HOSTS_ROOT",tmp_path/"static-known-hosts")
    def actual_producers(*,jobs,core,initial,chains):
        binary=tmp_path/"external-command-fixture"/"ansible-playbook"
        binary.parent.mkdir();binary.write_text("#!/bin/sh\nexit 99\n");binary.chmod(0o700)
        chain=chains[0]
        body={"proxyId":chain.assigned_proxy,"siteName":"example","domain":"example.invalid",
              "internalPort":8081}
        engagement_id=core.input["engagementId"]
        actor=core.requested_by
        calls=[]
        def site_runner(command,cwd):
            calls.append(tuple(command[:1]))
            if command[0]=="ssh":
                return subprocess.CompletedProcess(command,0,json.dumps({"state":"empty","fingerprint":"a"*64}),"")
            assert command[0]==str(binary) and cwd is not None
            return subprocess.CompletedProcess(command,0,"ok","")
        preview=web.preview_web_static_service_apply(engagement_id,body,requested_by=actor,
            repository=jobs,runner=site_runner)
        body.update(contentAction="preserve",contentReviewJobId=preview["job"]["id"])
        applied=web.apply_web_static_service(engagement_id,body,requested_by=actor,repository=jobs,
            runner=site_runner,env={"ANSIBLE_PLAYBOOK_BIN":str(binary)},workspace_root=tmp_path/"static-workspace")
        assert applied["job"]["status"]=="succeeded"
        service=SqlAlchemyEngagementServiceRepository().get(engagement_id,applied["service"]["serviceId"])
        assert service.status=="Configured" and service.apply_job_id==applied["job"]["id"]
        phases.append("actual-static-preview-and-apply")
        core_rows=authority._core_details(core)
        proxy=next(row for row in core_rows if row["role"]=="proxy" and row["displayName"].startswith(chain.assigned_proxy))
        middle=next(row for row in chain.nodes if row["role"]=="middle")
        edge=next(row for row in chain.nodes if row["role"]=="edge")
        channel={"channelId":"example-http","domain":"example.invalid","protocol":"HTTP","mode":"http-openresty",
            "externalPort":"80","internalPort":"80","proxy":proxy["displayName"],
            "middle":middle["hostname"],"edge":edge["hostname"],"terminatesOn":proxy["displayName"],
            "service":"Static Web","serviceType":"web-static","serviceId":service.service_id,
            "chainId":chain.chain_id}
        result=inbound.start_inbound_channel_apply(engagement_id,channel["channelId"],
            confirmation="apply-inbound-"+channel["channelId"],requested_by=actor,repository=jobs,
            channel=channel,env={"ANSIBLE_PLAYBOOK_BIN":str(binary)},workspace_root=tmp_path/"http-workspace",
            runner=lambda *_a,**_kw: pytest.fail("source-rejected HTTP must not contact hosts"),
            background_runner=lambda task:task())
        failed=jobs.get(result["job"]["id"])
        assert failed.status=="failed" and len(failed.events)==4
        assert failed.events[-1].message=="inbound channel provider ingress sync failed"
        # Prove the producer output is acceptable before any teardown writer.
        authority._attempt(failed,core,initial,core_rows,chains,jobs.list_for_engagement(engagement_id))
        phases.append("actual-failed-http-apply")
        return service.service_id
    canonical_flow(tmp_path,monkeypatch,"worker_success_initial_published_fixture",
                   published_cleanup_hook=actual_producers)
    assert phases==["actual-static-preview-and-apply","actual-failed-http-apply"]
