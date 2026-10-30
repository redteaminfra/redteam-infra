# Copyright (c) 2026, Oracle and/or its affiliates.
"""Request-local reporting copies; stored ownership and receipts stay immutable."""
from copy import deepcopy

from app.services.provider_keyed_inspector_retirement_receipt import inspector_cleanup_resolved


def reported_provider_resource(record, engagement_jobs):
    projected = deepcopy(record.provider_resource_dict())
    if (type(projected.get('metadata')) is dict and projected['metadata'].get('cleanupRequired') is True
            and inspector_cleanup_resolved(record, engagement_jobs)):
        projected['metadata']['cleanupRequired'] = False
    return projected
