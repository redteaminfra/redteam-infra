# Copyright (c) 2026, Oracle and/or its affiliates.
from contextlib import contextmanager

from app.storage.database import DatabaseState, db


@contextmanager
def storage_context(target):
    if isinstance(target, DatabaseState):
        with db.bind(target):
            yield
        return
    with target.storage_context():
        yield
