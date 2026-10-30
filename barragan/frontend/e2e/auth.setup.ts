/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { request } from "@playwright/test";
import { chmod, readFile, stat, writeFile } from "node:fs/promises";

import { authStatePath, baseURL } from "../playwright.runtime";

export default async function globalSetup() {
  const context = await request.newContext({ baseURL });
  const session = await context.get("/api/auth/session");
  const discovery = await session.json() as { authRequired?: boolean };
  let csrfToken = "";
  if (discovery.authRequired) {
    const passwordPath = process.env.BARRAGAN_CODY_PASSWORD_FILE ?? `${process.env.HOME}/.sec/barragan_example_operator_three`;
    const metadata = await stat(passwordPath);
    if ((metadata.mode & 0o777) !== 0o600) throw new Error("Example Operator password file must have mode 0600");
    const password = (await readFile(passwordPath, "utf8")).replace(/[\r\n]+$/, "");
    const login = await context.post("/api/auth/login", { data: { username: "example_operator_three", password } });
    if (!login.ok()) throw new Error(`Example Operator login failed (${login.status()})`);
    csrfToken = String((await login.json() as { csrfToken?: string }).csrfToken ?? "");
    if (!csrfToken) throw new Error("Example Operator login did not return a CSRF token");
  }
  const state = await context.storageState();
  if (csrfToken) {
    state.origins = [{
      origin: new URL(baseURL).origin,
      localStorage: [{ name: "barragan.csrf-token", value: csrfToken }]
    }];
  }
  await writeFile(authStatePath, JSON.stringify(state), { encoding: "utf8", mode: 0o600 });
  await chmod(authStatePath, 0o600);
  await context.dispose();
}
