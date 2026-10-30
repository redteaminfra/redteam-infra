# Copyright (c) 2026, Oracle and/or its affiliates.
import unittest

from app.asgi import create_app as create_fastapi_app
from app.api.contract import route_keys
from app.core.config import TestConfig

class BackendRouteContractParityTests(unittest.TestCase):
    def test_fastapi_routes_match_api_contract(self):
        app = create_fastapi_app(TestConfig)
        fastapi_routes = {
            (method, route.path)
            for route in app.routes
            if route.path.startswith("/api/")
            for method in route.methods
        }

        self.assertEqual(fastapi_routes, route_keys())
if __name__ == "__main__":
    unittest.main()
