/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import { apiClient, BarraganApiError, SketchChainRecord, SketchProviderCatalog } from "../api/client";
import { MixedAppendReview } from "./App";

afterEach(() => vi.restoreAllMocks());

const catalogs = { digitalocean: {
  provider: "digitalocean", status: "ready", regions: [
    {id: "sfo3", label: "San Francisco", available: true},
    {id: "nyc3", label: "New York", available: true}],
  sizes: [{id: "s-1vcpu-1gb", label: "1 GB", available: true, regions: ["sfo3", "nyc3"]}],
  defaults: {region: "sfo3", size: "s-1vcpu-1gb"}
} as SketchProviderCatalog };

const chains = [
  { chainId: "chain-do", middleProvider: "digitalocean", edgeProvider: "digitalocean",
    edgeRegion: "sfo3", edgeSize: "s-1vcpu-1gb" },
  { chainId: "chain-linode", middleProvider: "linode", edgeProvider: "linode",
    edgeRegion: "us-east", edgeSize: "g6-nanode-1" }
] as SketchChainRecord[];

it("reviews the two opposite-provider edges and offers one Apply", async () => {
  const read = vi.spyOn(apiClient, "mixedAppendPlanReview").mockResolvedValue({
    review: { available: true, status: "ready" }
  });
  const create = vi.spyOn(apiClient, "createMixedAppendPlanReview").mockResolvedValue({
    review: { available: true, status: "planning", planStatus: "running" }
  });
  const apply = vi.spyOn(apiClient, "applyMixedAppendPlanReview").mockResolvedValue({
    review: { available: true, status: "apply_sealed", planStatus: "succeeded" }
  });
  const first = render(<MixedAppendReview engagementId="eng-a" chains={chains} catalogs={catalogs} />);
  const reviewButton = await screen.findByRole("button", { name: "Review both edge additions" });
  expect(screen.getByText(/before configuring independent channels/)).toBeTruthy();
  fireEvent.click(reviewButton);
  await waitFor(() => expect(create).toHaveBeenCalledWith("eng-a", {
    digitalocean: { selectedChainId: "chain-linode", edgeRegion: "sfo3", edgeSize: "s-1vcpu-1gb" },
    linode: { selectedChainId: "chain-do", edgeRegion: "us-east", edgeType: "g6-nanode-1" }
  }));
  expect(screen.queryByRole("button", { name: /Apply both/ })).toBeNull();
  first.unmount();
  read.mockResolvedValue({ review: { available: true, status: "planning",
    planStatus: "succeeded", applyAvailable: true, reviewSha256: "a".repeat(64),
    reviewSummary: { schema: "mixed-append-pair-review-summary-v1",
      providerOrder: ["digitalocean", "linode"],
      plans: [
        { provider: "digitalocean", selectedChainId: "chain-linode", edgeRegion: "sfo3",
          edgeSizeOrType: "s-1vcpu-1gb", newEdgeAddress: 'digitalocean_droplet.edge["sfo3-02"]',
          savedPlanSha256: "b".repeat(64) },
        { provider: "linode", selectedChainId: "chain-do", edgeRegion: "us-east",
          edgeSizeOrType: "g6-nanode-1", newEdgeAddress: 'linode_instance.edge["us-east-02"]',
          savedPlanSha256: "c".repeat(64) }
      ], outcome: "add one edge per provider; retain all existing nodes" } } });
  render(<MixedAppendReview engagementId="eng-a" chains={chains} catalogs={catalogs} />);
  expect(await screen.findByText(/retain all existing nodes/)).toBeTruthy();
  expect(screen.getByText(/Paired edge plan: ready for review/)).toBeTruthy();
  expect(screen.queryByText(/Paired edge update: succeeded/)).toBeNull();
  fireEvent.click(await screen.findByRole("button", { name: "Apply both reviewed edge additions" }));
  await waitFor(() => expect(apply).toHaveBeenCalledWith("eng-a", "a".repeat(64)));
});

it.each([
  ["planning", "queued", undefined, "Paired edge plan: queued"],
  ["planning", "running", undefined, "Paired edge plan: running"],
  ["planning", "failed", undefined, "Paired edge plan: failed"],
  ["apply_sealed", "succeeded", "applying first provider", "Paired edge update: applying first provider"],
  ["apply_sealed", "succeeded", "proving new edges", "Paired edge update: proving new edges"],
  ["apply_sealed", "succeeded", undefined, "Paired edge update: awaiting progress"],
  ["attention", "succeeded", "provider Apply failed; cleanup review required", "Paired edge update: provider Apply failed; cleanup review required"]
])("distinguishes plan and update status for %s/%s/%s", async (status, planStatus, applyStage, expected) => {
  vi.spyOn(apiClient, "mixedAppendPlanReview").mockResolvedValue({ review: {
    available: true, status, planStatus, applyStage
  } });
  render(<MixedAppendReview engagementId="eng-a" chains={chains} catalogs={catalogs} />);
  expect(await screen.findByText(expected)).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Apply both reviewed edge additions" })).toBeNull();
});


it("retries the persisted paired choices after a pre-command failure", async () => {
  const saved = {
    digitalocean: { selectedChainId: "chain-linode", edgeRegion: "nyc3", edgeSize: "saved-small" },
    linode: { selectedChainId: "chain-do", edgeRegion: "us-west", edgeType: "saved-type" }
  };
  vi.spyOn(apiClient, "mixedAppendPlanReview").mockResolvedValue({ review: {
    available: true, status: "planning", planStatus: "failed", retryAvailable: true,
    retryChoices: saved, parentJobId: "same-parent", planJobId: "same-child"
  }});
  const create = vi.spyOn(apiClient, "createMixedAppendPlanReview").mockResolvedValue({ review: {
    available: true, status: "planning", planStatus: "queued", retryAvailable: false
  }});
  const rendered = render(<MixedAppendReview engagementId="eng-a" chains={chains} catalogs={catalogs} />);
  fireEvent.click(await screen.findByRole("button", { name: "Retry Review" }));
  await waitFor(() => expect(create).toHaveBeenCalledWith("eng-a", saved));
  expect(screen.queryByRole("button", { name: "Apply both reviewed edge additions" })).toBeNull();
  rendered.unmount();
});

it("resumes only expired provider proof using the same approved review", async () => {
  const digest = "d".repeat(64);
  const read = vi.spyOn(apiClient, "mixedAppendPlanReview").mockResolvedValue({review: {
    available: true, status: "apply_sealed", applyStage: "waiting for provider proof",
    reviewSha256: digest, proofResumeAvailable: false
  }});
  const apply = vi.spyOn(apiClient, "applyMixedAppendPlanReview").mockResolvedValue({review: {
    available: true, status: "apply_sealed", applyStage: "waiting for provider proof",
    reviewSha256: digest, proofResumeAvailable: false
  }});
  const active = render(<MixedAppendReview engagementId="eng-a" chains={chains} catalogs={catalogs} />);
  expect(await screen.findByText(/waiting for provider proof/)).toBeTruthy();
  expect(screen.queryByRole("button", {name: "Resume proof"})).toBeNull();
  active.unmount();
  read.mockResolvedValue({review: {
    available: true, status: "apply_sealed", applyStage: "waiting for provider proof",
    reviewSha256: digest, proofResumeAvailable: true, attention: true
  }});
  const expired = render(<MixedAppendReview engagementId="eng-a" chains={chains} catalogs={catalogs} />);
  fireEvent.click(await screen.findByRole("button", {name: "Resume proof"}));
  await waitFor(() => expect(apply).toHaveBeenCalledWith("eng-a", digest));
  await waitFor(() => expect(screen.queryByRole("button", {name: "Resume proof"})).toBeNull());
  expect(screen.queryByRole("button", {name: "Apply both reviewed edge additions"})).toBeNull();
  expired.unmount();
});


it("keeps unsupported selection visible and requires an explicit compatible region", async () => {
  vi.spyOn(apiClient, "mixedAppendPlanReview").mockResolvedValue({review: {available: true, status: "ready"}});
  const create = vi.spyOn(apiClient, "createMixedAppendPlanReview").mockResolvedValue({review: {available: true, status: "planning"}});
  const compatible = {digitalocean: {...catalogs.digitalocean, sizes: [{...catalogs.digitalocean.sizes[0], regions: ["nyc3"]}]}};
  render(<MixedAppendReview engagementId="eng-a" chains={chains} catalogs={compatible} />);
  const review = await screen.findByRole("button", {name: "Review both edge additions"});
  expect(review).toBeDisabled();
  expect(screen.getByRole("combobox", {name: "DigitalOcean append edge region"})).toHaveValue("sfo3");
  expect(screen.getByRole("option", {name: /San Francisco/})).toBeDisabled();
  fireEvent.click(review);
  expect(create).not.toHaveBeenCalled();
  fireEvent.change(screen.getByRole("combobox", {name: "DigitalOcean append edge region"}), {target: {value: "nyc3"}});
  expect(review).toBeEnabled();
  fireEvent.click(review);
  await waitFor(() => expect(create).toHaveBeenCalledWith("eng-a", {
    digitalocean: {selectedChainId: "chain-linode", edgeRegion: "nyc3", edgeSize: "s-1vcpu-1gb"},
    linode: {selectedChainId: "chain-do", edgeRegion: "us-east", edgeType: "g6-nanode-1"}
  }));
});

it("blocks missing compatibility data and stale catalog changes without replacing intent", async () => {
  vi.spyOn(apiClient, "mixedAppendPlanReview").mockResolvedValue({review: {available: true, status: "ready"}});
  const view = render(<MixedAppendReview engagementId="eng-a" chains={chains} catalogs={catalogs} />);
  expect(await screen.findByRole("button", {name: "Review both edge additions"})).toBeEnabled();
  view.rerender(<MixedAppendReview engagementId="eng-a" chains={chains} catalogs={{}} />);
  expect(screen.getByRole("button", {name: "Review both edge additions"})).toBeDisabled();
  expect(screen.getByText(/compatibility information is unavailable/)).toBeTruthy();
  expect(screen.getByRole("combobox", {name: "DigitalOcean append edge region"})).toHaveValue("sfo3");
});


it("shows sanitized backend availability errors without changing the selected size", async () => {
  vi.spyOn(apiClient, "mixedAppendPlanReview").mockResolvedValue({review: {available: true, status: "ready"}});
  vi.spyOn(apiClient, "createMixedAppendPlanReview").mockRejectedValue(new BarraganApiError(400, "Review failed", {
    errors: ["The inherited DigitalOcean edge size is unavailable in the selected region. No append started."]
  }));
  render(<MixedAppendReview engagementId="eng-a" chains={chains} catalogs={catalogs} />);
  fireEvent.click(await screen.findByRole("button", {name: "Review both edge additions"}));
  expect(await screen.findByRole("alert")).toHaveTextContent("No append started.");
  expect(screen.getByText(/Existing edge sizes/)).toHaveTextContent("s-1vcpu-1gb");
});
