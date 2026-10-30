/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { unlink } from "node:fs/promises";

import { authStatePath } from "../playwright.runtime";

export default async function globalTeardown() {
  await unlink(authStatePath).catch(() => undefined);
}
