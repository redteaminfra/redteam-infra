/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { cleanup } from "@testing-library/react";
import { InferenceProxySettings } from "./InferenceProxySettings";

afterEach(cleanup);

it("keeps IAM outside installation and shows compartment-scoped operator policies", () => {
  const save = vi.fn();
  const change = vi.fn();
  render(<InferenceProxySettings configuration={{ region: "us-chicago-1", compartmentId: "ocid1.compartment.oc1..fixture", port: 8787 }}
    selected disabled={false} saving={false} changed onSave={save} onChange={change} onToggle={vi.fn()} />);
  expect(screen.getByText(/never changes IAM policies/)).toBeInTheDocument();
  expect(screen.getByText(/not verified by service installation/)).toBeInTheDocument();
  const policy = screen.getByText(/Allow dynamic-group.*generative-ai-model/);
  expect(policy).toHaveTextContent("in compartment id ocid1.compartment.oc1..fixture");
  expect(policy).not.toHaveTextContent("manage");
  expect(policy).not.toHaveTextContent("in tenancy");
  expect(screen.getByText("instance.id = '<homebase-instance-ocid>'")).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("OCI inference region"), { target: { value: "us-ashburn-1" } });
  expect(change).toHaveBeenCalledWith(expect.objectContaining({ region: "us-ashburn-1" }));
  fireEvent.click(screen.getByRole("button", { name: "Save capability changes" }));
  expect(save).toHaveBeenCalledOnce();
  expect(screen.queryByRole("button", { name: /apply.*polic|create.*group/i })).not.toBeInTheDocument();
});

it("requires valid configuration before saving a selected service, without assuming compute compartment", () => {
  const props = { configuration: { region: "", compartmentId: "", port: 8787 }, selected: true, disabled: false,
    saving: false, changed: true, onSave: vi.fn(), onChange: vi.fn(), onToggle: vi.fn() };
  const view = render(<InferenceProxySettings {...props} />);
  expect(screen.getByRole("button", { name: "Save capability changes" })).toBeDisabled();
  expect(screen.getByText(/need not be the compute compartment/)).toBeInTheDocument();
  view.rerender(<InferenceProxySettings {...props} configuration={{ region: "us-chicago-1", compartmentId: "ocid1.compartment.oc1..fixture", port: 80 }} />);
  expect(screen.getByRole("button", { name: "Save capability changes" })).toBeDisabled();
  view.rerender(<InferenceProxySettings {...props} configuration={{ region: "us-chicago-1", compartmentId: "ocid1.compartment.x", port: 8787 }} />);
  expect(screen.getByRole("button", { name: "Save capability changes" })).toBeDisabled();
  view.rerender(<InferenceProxySettings {...props} configuration={{ region: `${"a".repeat(32)}-${"b".repeat(32)}`, compartmentId: "ocid1.compartment.oc1..fixture", port: 8787 }} />);
  expect(screen.getByRole("button", { name: "Save capability changes" })).toBeDisabled();
  view.rerender(<InferenceProxySettings {...props} selected={false} />);
  expect(screen.getByRole("button", { name: "Save capability changes" })).toBeEnabled();
  expect(screen.getByText(/does not uninstall/)).toBeInTheDocument();
});

const configured = { region: "us-chicago-1", compartmentId: "ocid1.compartment.oc1..fixture", port: 8787 };
const settingsProps = { configuration: configured, selected: true, disabled: false, saving: false, changed: false,
  onSave: vi.fn(), onChange: vi.fn(), onToggle: vi.fn() };
const checked = {
  configuration: configured,
  status: "checked" as const, bindingFingerprint: "a".repeat(64),
  homebaseIdentity: { coreDeploymentId: "job-core-current", instanceId: "ocid1.instance.oc1.us-sanjose-1.fixture" },
  observation: { checkedAt: "2026-10-30T15:00:00Z", localReady: true,
    discoveryStatus: "discovery_unavailable", lastRefreshAt: null, modelCount: 0,
    errorCode: "oci_not_authorized_or_not_found", inferenceVerified: false as const },
  job: null, errors: []
};

it("uses verified current Homebase identity and separates no-access readiness from inference", () => {
  const check = vi.fn();
  render(<InferenceProxySettings {...settingsProps} serviceStatus={checked} onCheck={check} />);
  expect(screen.getByText("instance.id = 'ocid1.instance.oc1.us-sanjose-1.fixture'")).toBeInTheDocument();
  expect(screen.getByText(/OCI reported not authorized or not found/)).toBeInTheDocument();
  expect(screen.getByText(/A healthy service or available model catalog does not prove/)).toHaveTextContent("Not verified");
  fireEvent.click(screen.getByRole("button", { name: "Check service and OCI discovery" }));
  expect(check).toHaveBeenCalledOnce();
});

it("can show catalog recovery without claiming verified inference", () => {
  const view = render(<InferenceProxySettings {...settingsProps} serviceStatus={checked} onCheck={vi.fn()} />);
  view.rerender(<InferenceProxySettings {...settingsProps} serviceStatus={{ ...checked,
    observation: { ...checked.observation, discoveryStatus: "catalog_available", modelCount: 3,
      lastRefreshAt: "2026-10-30T15:02:00Z", errorCode: null } }} onCheck={vi.fn()} />);
  expect(screen.getByText(/Model catalog available \(3 models\)/)).toBeInTheDocument();
  expect(screen.queryByText(/OCI reported not authorized or not found/)).not.toBeInTheDocument();
  expect(screen.getByText(/A healthy service or available model catalog does not prove/)).toHaveTextContent("Not verified");
});

it("does not present saved observations as proof for an unsaved draft", () => {
  render(<InferenceProxySettings {...settingsProps} changed configuration={{ ...configured, port: 8788 }} serviceStatus={checked} onCheck={vi.fn()} />);
  expect(screen.getByRole("button", { name: "Check service and OCI discovery" })).toBeDisabled();
  expect(screen.queryByText(/OCI reported not authorized or not found/)).not.toBeInTheDocument();
  expect(screen.getByText(/Save and Apply your capability changes before checking/)).toBeInTheDocument();
  expect(screen.getByLabelText("Inference Proxy loopback port")).toHaveValue(8788);
});

it("does not enable checks for missing bindings or while a job runs", () => {
  const view = render(<InferenceProxySettings {...settingsProps} serviceStatus={{ ...checked, status: "blocked", bindingFingerprint: null, observation: null, homebaseIdentity: null, errors: ["Current Homebase is unavailable."] }} onCheck={vi.fn()} />);
  expect(screen.getByText("Current Homebase is unavailable.")).toBeInTheDocument();
  expect(screen.getByText("instance.id = '<homebase-instance-ocid>'")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Check service and OCI discovery" })).toBeDisabled();
  view.rerender(<InferenceProxySettings {...settingsProps} serviceStatus={{ ...checked, status: "checking", observation: null }} onCheck={vi.fn()} />);
  expect(screen.getByRole("status")).toHaveTextContent("Checking the Homebase service");
  expect(screen.getByRole("button", { name: "Check service and OCI discovery" })).toBeDisabled();
});

it("blocks a current binding whose saved settings differ from the visible form", () => {
  render(<InferenceProxySettings {...settingsProps} serviceStatus={{ ...checked, configuration: { ...configured, region: "us-ashburn-1" } }} onCheck={vi.fn()} />);
  expect(screen.getByText(/Configuration changed elsewhere/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Check service and OCI discovery" })).toBeDisabled();
  expect(screen.queryByText(/OCI reported not authorized or not found/)).not.toBeInTheDocument();
  expect(screen.getByLabelText("OCI inference region")).toHaveValue("us-chicago-1");
});
