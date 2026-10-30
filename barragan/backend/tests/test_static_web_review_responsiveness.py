# Copyright (c) 2026, Oracle and/or its affiliates.
"""Remote review checks run outside the event loop with runtime context intact."""
import asyncio
import threading

import httpx2 as httpx
import pytest

from app.asgi import create_app
from app.core.config import TestConfig
from app.core.request_identity import RequestIdentity, bind_request_identity, current_request_identity
from app.storage.database import db


@pytest.mark.parametrize('suffix,function,status', [
    ('apply-preview', 'preview_web_static_service_apply', 201),
    ('', 'start_web_static_service_apply', 202),
])
def test_static_web_remote_preparation_offloads_event_loop(tmp_path, monkeypatch, suffix, function, status):
    class LocalConfig(TestConfig):
        DATA_DIR = tmp_path / 'data'
        ENGAGEMENT_REPOS_ROOT = tmp_path / 'engagements'
    app = create_app(LocalConfig)
    calling_thread = threading.get_ident()
    seen = []

    def prepare(*args, **kwargs):
        seen.append((threading.get_ident(), current_request_identity()))
        assert db.engine is app.state.database.engine
        return {'job': {'id': 'review-fixture'}, 'contentReview': {'state': 'existing'}}

    monkeypatch.setattr('app.asgi.' + function, prepare)
    monkeypatch.setattr('app.asgi.engagement_capability_workspace', lambda *a, **k: {})
    identity = RequestIdentity('fixture', 'operator', ('admin',), 'test-session')

    async def exercise():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url='http://test') as client:
            with bind_request_identity(identity):
                return await client.post('/api/engagements/example/capabilities/static-web/sites' + ('/' + suffix if suffix else ''), json={})

    response = asyncio.run(exercise())
    assert response.status_code == status
    assert len(seen) == 1
    assert seen[0][0] != calling_thread
    assert seen[0][1] == identity
