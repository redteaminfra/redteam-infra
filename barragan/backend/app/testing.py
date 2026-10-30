# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import asyncio
import atexit
from typing import Any

import httpx2 as httpx


_LOOP = asyncio.new_event_loop()
atexit.register(_LOOP.close)


class CompatibilityResponse:
    """Response adapter for the pre-FastAPI test suite during test migration."""

    def __init__(self, response) -> None:
        self._response = response

    def get_json(self) -> Any:
        return self._response.json()

    @property
    def data(self) -> bytes:
        return self._response.content

    def __getattr__(self, name: str) -> Any:
        return getattr(self._response, name)


class CompatibilityTestClient:
    """Flask-style test calls backed entirely by FastAPI's TestClient."""

    def __init__(self, application) -> None:
        self.application = application
        self.cookies = httpx.Cookies()

    def request(self, method: str, path: str, **kwargs: Any) -> CompatibilityResponse:
        query_string = kwargs.pop("query_string", None)
        if query_string is not None:
            kwargs["params"] = query_string
        content_type = kwargs.pop("content_type", None)
        if content_type:
            kwargs.setdefault("headers", {})["content-type"] = content_type
        kwargs.pop("follow_redirects", None)
        async def send():
            transport = httpx.ASGITransport(app=self.application)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
                cookies=self.cookies,
            ) as client:
                response = await client.request(method.upper(), path, **kwargs)
                self.cookies.update(response.cookies)
                return response

        response = _LOOP.run_until_complete(send())
        return CompatibilityResponse(response)

    def open(self, path: str, *, method: str = "GET", **kwargs: Any) -> CompatibilityResponse:
        return self.request(method, path, **kwargs)

    def get(self, path: str, **kwargs: Any) -> CompatibilityResponse:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> CompatibilityResponse:
        return self.request("POST", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> CompatibilityResponse:
        return self.request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> CompatibilityResponse:
        return self.request("DELETE", path, **kwargs)
