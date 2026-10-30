/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { describe, expect, it } from "vitest";

import { apiUrl } from "./client";

describe("apiUrl", () => {
  it("keeps relative API paths when no base URL is configured", () => {
    expect(apiUrl("/api/health")).toBe("/api/health");
  });
});
