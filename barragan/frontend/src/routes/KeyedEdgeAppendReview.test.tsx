/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import { apiClient, SketchChainRecord } from "../api/client";
import { KeyedEdgeAppendReview } from "./App";

afterEach(() => vi.restoreAllMocks());

it("reviews one DevTest edge plan and offers one Apply action", async () => {
  const chain = { chainId: "chain-a", edgeRegion: "sfo3", edgeSize: "s-1vcpu-1gb" } as SketchChainRecord;
  vi.spyOn(apiClient, "keyedEdgeAppendPlanReview").mockResolvedValue({
    review: { available: true, status: "ready" }
  });
  const create = vi.spyOn(apiClient, "createKeyedEdgeAppendPlanReview").mockResolvedValue({
    review: { available: true, status: "planning", planStatus: "queued", parentJobId: "job-a" }
  });
  const discard = vi.spyOn(apiClient, "discardKeyedEdgeAppendPlanReview").mockResolvedValue({
    review: { available: true, status: "unapplied_reconciled", planStatus: "succeeded" }
  });
  const apply = vi.spyOn(apiClient, "applyKeyedEdgeAppendPlanReview").mockResolvedValue({
    review: { available: true, status: "awaiting_apply", planStatus: "succeeded",
      applyRequested: true, planSha256: "a".repeat(64) }
  });
  const view = render(<KeyedEdgeAppendReview engagementId="eng-a" chain={chain} />);
  fireEvent.click(await screen.findByRole("button", { name: "Review one edge append" }));
  await waitFor(() => expect(create).toHaveBeenCalledWith("eng-a", "chain-a"));
  expect(screen.queryByRole("button", { name: /apply/i })).toBeNull();
  view.rerender(<KeyedEdgeAppendReview engagementId="eng-a" chain={chain} />);
  // A subsequent poll reports the reviewed saved plan.
  vi.mocked(apiClient.keyedEdgeAppendPlanReview).mockResolvedValue({
    review: { available: true, status: "awaiting_apply", planStatus: "succeeded",
      applyAvailable: true, newEdgeAddress: 'digitalocean_droplet.edge["sfo3-03"]',
      planSha256: "a".repeat(64) }
  });
  view.unmount();
  const reviewed = render(<KeyedEdgeAppendReview engagementId="eng-a" chain={chain} />);
  fireEvent.click(await screen.findByRole("button", { name: "Apply reviewed edge plan" }));
  await waitFor(() => expect(apply).toHaveBeenCalledWith("eng-a", "chain-a", "a".repeat(64)));
  expect(screen.queryByRole("button", { name: "Apply reviewed edge plan" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Discard review" })).toBeNull();
  reviewed.unmount();
  render(<KeyedEdgeAppendReview engagementId="eng-a" chain={chain} />);
  fireEvent.click(await screen.findByRole("button", { name: "Discard review" }));
  await waitFor(() => expect(discard).toHaveBeenCalledWith("eng-a", "chain-a"));
});

it("waits for a failed review claim before offering the existing discard action", async () => {
  const chain = { chainId: "chain-a" } as SketchChainRecord;
  const review = vi.spyOn(apiClient, "keyedEdgeAppendPlanReview").mockResolvedValue({
    review: { available: true, status: "planning", planStatus: "failed",
      failedReviewDiscardState: "waiting" }
  });
  const discard = vi.spyOn(apiClient, "discardKeyedEdgeAppendPlanReview").mockResolvedValue({
    review: { available: true, status: "unapplied_reconciled", planStatus: "failed" }
  });
  const waiting = render(<KeyedEdgeAppendReview engagementId="eng-a" chain={chain} />);
  expect(await screen.findByText(/Waiting for the review worker claim/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Discard failed review" })).toBeNull();
  waiting.unmount();
  review.mockResolvedValue({ review: { available: true, status: "planning",
    planStatus: "failed", failedReviewDiscardState: "ready" } });
  render(<KeyedEdgeAppendReview engagementId="eng-a" chain={chain} />);
  fireEvent.click(await screen.findByRole("button", { name: "Discard failed review" }));
  await waitFor(() => expect(discard).toHaveBeenCalledWith("eng-a", "chain-a"));
});

it("offers no-GO recovery only after the Apply claim expires", async () => {
  const chain = { chainId: "chain-a" } as SketchChainRecord;
  const read = vi.spyOn(apiClient, "keyedEdgeAppendPlanReview").mockResolvedValue({
    review: { available: true, status: "attention", planStatus: "succeeded",
      applyRequested: true, failedApplyRecoveryState: "waiting" }
  });
  const recover = vi.spyOn(apiClient, "recoverNoGoKeyedEdgeAppendApply").mockResolvedValue({
    review: { available: true, status: "unapplied_reconciled", planStatus: "succeeded" }
  });
  const waiting = render(<KeyedEdgeAppendReview engagementId="eng-a" chain={chain} />);
  expect(await screen.findByText(/Waiting for the Apply worker claim/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Recover unstarted edge Apply" })).toBeNull();
  waiting.unmount();
  read.mockResolvedValue({ review: { available: true, status: "no_go_cleaning",
    planStatus: "succeeded", failedApplyRecoveryState: "ready" } });
  render(<KeyedEdgeAppendReview engagementId="eng-a" chain={chain} />);
  fireEvent.click(await screen.findByRole("button", { name: "Recover unstarted edge Apply" }));
  await waitFor(() => expect(recover).toHaveBeenCalledWith("eng-a", "chain-a"));
});

it("cancels only an aged, unstarted append review", async () => {
  const chain = { chainId: "chain-a" } as SketchChainRecord;
  const read = vi.spyOn(apiClient, "keyedEdgeAppendPlanReview").mockResolvedValue({
    review: { available: true, status: "planning", planStatus: "queued",
      unscheduledReviewCancelState: "waiting" }
  });
  const discard = vi.spyOn(apiClient, "discardKeyedEdgeAppendPlanReview").mockResolvedValue({
    review: { available: true, status: "ready" }
  });
  const waiting = render(<KeyedEdgeAppendReview engagementId="eng-a" chain={chain} />);
  expect(await screen.findByText(/Waiting briefly to confirm/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Cancel unstarted review" })).toBeNull();
  waiting.unmount();
  read.mockResolvedValue({ review: { available: true, status: "planning",
    planStatus: "queued", unscheduledReviewCancelState: "ready" } });
  render(<KeyedEdgeAppendReview engagementId="eng-a" chain={chain} />);
  fireEvent.click(await screen.findByRole("button", { name: "Cancel unstarted review" }));
  await waitFor(() => expect(discard).toHaveBeenCalledWith("eng-a", "chain-a"));
});

it("offers publication-only recovery after the completed job claim expires", async () => {
  const chain = { chainId: "chain-a" } as SketchChainRecord;
  const read = vi.spyOn(apiClient, "keyedEdgeAppendPlanReview").mockResolvedValue({
    review: { available: true, status: "attention", planStatus: "succeeded",
      publicationRecoveryState: "waiting" }
  });
  const recover = vi.spyOn(apiClient, "recoverKeyedEdgeAppendPublication").mockResolvedValue({
    review: { available: true, status: "awaiting_publication", planStatus: "succeeded" }
  });
  const waiting = render(<KeyedEdgeAppendReview engagementId="eng-a" chain={chain} />);
  expect(await screen.findByText(/Waiting for the completed edge job claim/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Resume proved edge publication" })).toBeNull();
  waiting.unmount();
  read.mockResolvedValue({ review: { available: true, status: "attention",
    planStatus: "succeeded", publicationRecoveryState: "ready" } });
  render(<KeyedEdgeAppendReview engagementId="eng-a" chain={chain} />);
  fireEvent.click(await screen.findByRole("button", { name: "Resume proved edge publication" }));
  await waitFor(() => expect(recover).toHaveBeenCalledWith("eng-a", "chain-a"));
});
