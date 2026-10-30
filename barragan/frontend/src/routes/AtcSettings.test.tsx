/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { AtcSettings, defaultAtcConfiguration } from "./AtcSettings";

afterEach(cleanup);
const base = { selected: true, disabled: false, saving: false, changed: true,
  onToggle: vi.fn(), onSave: vi.fn(), onChange: vi.fn() };
it("requires explicit first-operator identity before saving a selected ATC", () => {
  const view = render(<AtcSettings {...base} configuration={defaultAtcConfiguration()} />);
  expect(screen.getByRole("button", { name: "Save capability changes" })).toBeDisabled();
  const config = { operatorId: "human/example_operator_three", operatorName: "Example Operator", port: 8790 };
  view.rerender(<AtcSettings {...base} configuration={config} />);
  expect(screen.getByRole("button", { name: "Save capability changes" })).toBeEnabled();
  fireEvent.change(screen.getByLabelText("ATC first operator name"), { target: { value: "Operator" } });
  expect(base.onChange).toHaveBeenCalledWith({ ...config, operatorName: "Operator" });
  fireEvent.click(screen.getByRole("button", { name: "Save capability changes" }));
  expect(base.onSave).toHaveBeenCalled();
  expect(screen.getByText(/Separate agent credentials/)).toBeInTheDocument();
  expect(screen.getByText(/does not support Ubuntu 24.04/)).toBeInTheDocument();
  expect(screen.queryByLabelText(/password|token/i)).not.toBeInTheDocument();
});
it("rejects reserved ports and control characters in identity, but permits deselection", () => {
  const config = { operatorId: "human/example_operator_three", operatorName: "Example Operator", port: 15432 };
  const view = render(<AtcSettings {...base} configuration={config} />);
  expect(screen.getByRole("button", { name: "Save capability changes" })).toBeDisabled();
  view.rerender(<AtcSettings {...base} configuration={{ ...config, port: 8790, operatorName: "Example Operator\nOTHER=unsafe" }} />);
  expect(screen.getByRole("button", { name: "Save capability changes" })).toBeDisabled();
  for (const operatorName of ["Example Operator\tOther", "Example Operator\x7fOther"]) {
    view.rerender(<AtcSettings {...base} configuration={{ ...config, port: 8790, operatorName }} />);
    expect(screen.getByRole("button", { name: "Save capability changes" })).toBeDisabled();
  }
  view.rerender(<AtcSettings {...base} selected={false} configuration={defaultAtcConfiguration()} />);
  expect(screen.getByRole("button", { name: "Save capability changes" })).toBeEnabled();
  expect(screen.getByText(/does not uninstall ATC or delete/)).toBeInTheDocument();
});
it("does not save while a capability operation is busy", () => {
  render(<AtcSettings {...base} disabled configuration={{ operatorId: "human/example_operator_three", operatorName: "Example Operator", port: 8790 }} />);
  expect(screen.getByRole("button", { name: "Save capability changes" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Disable Capability" })).toBeDisabled();
});
