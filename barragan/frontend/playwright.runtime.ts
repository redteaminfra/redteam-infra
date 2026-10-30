/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { join } from "node:path";
import { tmpdir } from "node:os";

export const baseURL = process.env.BARRAGAN_E2E_BASE_URL ?? "http://127.0.0.1:5173";
export const authStatePath = process.env.BARRAGAN_E2E_AUTH_STATE ?? join(tmpdir(), "barragan-playwright-auth.json");
