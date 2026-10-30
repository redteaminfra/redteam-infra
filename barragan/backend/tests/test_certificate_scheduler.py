# Copyright (c) 2026, Oracle and/or its affiliates.
from datetime import datetime, timezone

from app.services.certificate_scheduler import _due


def test_certificate_becomes_due_at_final_third_of_lifetime():
    certificate = {
        "type": "letsencrypt",
        "managedBy": "barragan",
        "status": "Issued",
        "issuedAt": "2026-01-01T00:00:00+00:00",
        "expiresAt": "2026-04-01T00:00:00+00:00",
    }

    assert not _due(certificate, datetime(2026, 3, 1, 23, 59, tzinfo=timezone.utc))
    assert _due(certificate, datetime(2026, 3, 2, 0, 0, tzinfo=timezone.utc))


def test_certificate_scheduler_ignores_unmanaged_and_active_jobs():
    now = datetime(2026, 3, 15, tzinfo=timezone.utc)
    base = {
        "type": "letsencrypt",
        "managedBy": "barragan",
        "status": "Issued",
        "issuedAt": "2026-01-01T00:00:00+00:00",
        "expiresAt": "2026-04-01T00:00:00+00:00",
    }

    assert not _due({**base, "managedBy": "operator"}, now)
    assert not _due({**base, "status": "Renewing"}, now)
    assert not _due({**base, "expiresAt": "unknown"}, now)
