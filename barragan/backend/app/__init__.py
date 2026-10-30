# Copyright (c) 2026, Oracle and/or its affiliates.
def create_app(*args, **kwargs):
    from app.asgi import create_app as create_fastapi_app

    return create_fastapi_app(*args, **kwargs)


__all__ = ["create_app"]
