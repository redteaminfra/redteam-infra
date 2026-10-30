/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { apiClient, type TeamMember, type TeamWorkspace, type TeamImportPreview } from "../api/client";
import { GlobalTeamPage } from "./App";

const member = (username: string, desiredUid: number | null): TeamMember => ({
  id: `user-${username}`, username, desiredUid, displayName: username, email: "",
  status: "active", defaultInfraGroups: ["redteam"], globalRoles: ["operator"], sshKeys: [],
  createdAt: "2026-10-27T12:00:00Z", updatedAt: "2026-10-27T12:00:00Z", deactivatedAt: null
});
const workspace = (members: TeamMember[]): TeamWorkspace => ({
  members, supportedInfraGroups: ["redteam", "volunteer"], defaultInfraGroups: ["redteam"], supportedAppPrivileges: []
});

afterEach(() => vi.restoreAllMocks());

describe("Global Team persistent UIDs", () => {
  it("sends a blank create UID and displays only the returned persistent assignment, including after reload", async () => {
    const saved = member("newoperator", 7107);
    vi.spyOn(apiClient, "team").mockResolvedValue(workspace([member("existing", 6002)]));
    const create = vi.spyOn(apiClient, "createTeamMember").mockResolvedValue({ member: saved });
    const { unmount } = render(<GlobalTeamPage />);
    await screen.findByText("UID 6002");
    fireEvent.click(screen.getByRole("button", { name: "Create Member" }));
    const panel = screen.getByLabelText("Create team member");
    expect(within(panel).getByText(/Leave blank to assign a persistent UID automatically/)).toBeInTheDocument();
    expect(within(panel).getByLabelText("Team member desired UID")).toHaveValue(null);
    fireEvent.change(within(panel).getByLabelText("Team member username"), { target: { value: "newoperator" } });
    fireEvent.click(within(panel).getByRole("button", { name: "Create Member" }));
    await screen.findByText("UID 7107");
    expect(create).toHaveBeenCalledWith(expect.objectContaining({ username: "newoperator", desiredUid: null }));
    expect(screen.queryByText("UID 6003")).not.toBeInTheDocument();
    unmount();
    vi.mocked(apiClient.team).mockResolvedValue(workspace([saved]));
    render(<GlobalTeamPage />);
    expect(await screen.findByText("UID 7107")).toBeInTheDocument();
  });

  it("explains blank edits preserve the assignment and sends null without guessing a replacement", async () => {
    const saved = member("operator", 6124);
    vi.spyOn(apiClient, "team").mockResolvedValue(workspace([saved]));
    const update = vi.spyOn(apiClient, "updateTeamMember").mockResolvedValue({ member: saved });
    render(<GlobalTeamPage />);
    await screen.findByText("UID 6124");
    fireEvent.click(screen.getByRole("button", { name: "Configure" }));
    expect(screen.getByText(/Leave blank to keep UID 6124/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Team member desired UID"), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Save Member" }));
    await waitFor(() => expect(update).toHaveBeenCalledWith(saved.id, expect.objectContaining({ desiredUid: null })));
    await waitFor(() => expect(screen.queryByLabelText("Configure team member")).not.toBeInTheDocument());
    expect(screen.getByText("UID 6124")).toBeInTheDocument();
  });

  it("keeps legacy missing assignments explicit rather than promising automatic repair", async () => {
    vi.spyOn(apiClient, "team").mockResolvedValue(workspace([member("legacy", null)]));
    render(<GlobalTeamPage />);
    expect(await screen.findByText("UID needs reconciliation")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Configure" }));
    expect(screen.getByText(/No UID is assigned.*reviewed reconciliation/)).toBeInTheDocument();
    expect(screen.queryByText(/Leave blank to assign a persistent UID automatically/)).not.toBeInTheDocument();
  });

  it("previews automatic creation separately from preserved existing UIDs, then shows the assigned import result", async () => {
    const existing = member("existing", 6100);
    const legacy = member("legacy", null);
    const saved = member("newoperator", 7204);
    vi.spyOn(apiClient, "team").mockResolvedValue(workspace([existing, legacy]));
    const preview: TeamImportPreview = {
      format: "json", fileName: "users.json", warnings: [],
      summary: { creates: 1, updates: 0, unchanged: 2, invalid: 0, keyAdditions: 0 },
      records: ["newoperator", "existing", "legacy"].map((username, index) => ({
        sourceIndex: index + 1, username, displayName: username, desiredUid: null, defaultInfraGroups: [], sshKeys: [],
        errors: [], action: index === 0 ? "create" : "unchanged", memberId: index === 0 ? "" : `user-${username}`,
        changes: [], keyAdditions: 0, existingKeyCount: 0
      }))
    };
    vi.spyOn(apiClient, "previewTeamImport").mockResolvedValue({ preview });
    vi.spyOn(apiClient, "applyTeamImport").mockResolvedValue({ preview,
      applied: { created: [saved.username], updated: [], unchanged: [existing.username, legacy.username], skipped: [], keyAdditions: 0 },
      team: workspace([existing, legacy, saved]) });
    render(<GlobalTeamPage />);
    await screen.findByText("UID 6100");
    fireEvent.click(screen.getByRole("button", { name: "Import Users" }));
    expect(screen.getByText(/For existing members, blank UIDs preserve their assignments/)).toBeInTheDocument();
    const file = new File(["{}"], "users.json", { type: "application/json" });
    Object.defineProperty(file, "text", { value: () => Promise.resolve("{}") });
    fireEvent.change(screen.getByLabelText("Users import file"), { target: { files: [file] } });
    fireEvent.click(await screen.findByRole("button", { name: "Preview Changes" }));
    const table = await screen.findByLabelText("Users import preview");
    expect(within(table).getByText("Assigned on apply")).toBeInTheDocument();
    expect(within(table).getByText("6100")).toBeInTheDocument();
    expect(within(table).getByText("Needs reconciliation")).toBeInTheDocument();
    expect(within(table).queryByText("not set")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Apply Changes" }));
    expect(await screen.findByText("UID 7204")).toBeInTheDocument();
    expect(within(table).getByText("7204")).toBeInTheDocument();
    expect(within(table).queryByText("Assigned on apply")).not.toBeInTheDocument();
  });
});
