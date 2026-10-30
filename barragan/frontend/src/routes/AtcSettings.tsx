/* Copyright (c) 2026, Oracle and/or its affiliates. */
import type { AtcConfiguration } from "../api/client";

export const defaultAtcConfiguration = (): AtcConfiguration => ({ operatorId: "", operatorName: "", port: 8790 });

export function AtcSettings({ configuration, onChange, disabled, selected, onToggle, onSave, saving, changed }: {
  configuration: AtcConfiguration;
  onChange: (value: AtcConfiguration) => void;
  disabled: boolean;
  selected: boolean;
  onToggle: () => void;
  onSave: () => void;
  saving: boolean;
  changed: boolean;
}) {
  const valid = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(configuration.operatorId) &&
    configuration.operatorName.trim() === configuration.operatorName && configuration.operatorName.length > 0 &&
    configuration.operatorName.length <= 128 && !/[\x00-\x1f\x7f]/.test(configuration.operatorName) &&
    Number.isInteger(configuration.port) && configuration.port >= 1024 && configuration.port <= 65535 &&
    ![15432, 17474, 17687].includes(configuration.port);
  return <>
    <p>Install ATC on an Ubuntu 22.04 Homebase for this engagement. The current release does not support Ubuntu 24.04. Its API and website listen locally; use an SSH tunnel to Homebase for browser access. No public channel is created.</p>
    <div className="service-form-grid atc-settings-grid">
      <label><span>First operator ID</span>
        <input aria-label="ATC first operator ID" value={configuration.operatorId} disabled={disabled}
          onChange={(event) => onChange({ ...configuration, operatorId: event.target.value })} />
        <small>Choose the initial human operator's ATC identifier. Separate agent credentials are configured later.</small>
      </label>
      <label><span>First operator name</span>
        <input aria-label="ATC first operator name" value={configuration.operatorName} disabled={disabled}
          onChange={(event) => onChange({ ...configuration, operatorName: event.target.value })} />
      </label>
      <label><span>Loopback port</span>
        <input aria-label="ATC loopback port" type="number" min={1024} max={65535} value={configuration.port || ""} disabled={disabled}
          onChange={(event) => onChange({ ...configuration, port: Number(event.target.value) })} />
        <small>Default 8790. Use a different port from other Homebase services.</small>
      </label>
    </div>
    <p>ATC prepares the initial operator's protected client file on Homebase. Database records and keys survive same-release repair. Graph and inference services are not configured by this selection.</p>
    <p>Save these settings, then use Apply saved changes to install. Disabling the selection does not uninstall ATC or delete its records. Changing an existing identity or listener requires a separate migration.</p>
    <div className="form-actions atc-settings-actions">
      <button className="secondary-action" type="button" disabled={disabled} onClick={onToggle}>{selected ? "Disable Capability" : "Enable Capability"}</button>
      <button className="primary-action" type="button" disabled={disabled || saving || !changed || (selected && !valid)} onClick={onSave}>{saving ? "Saving..." : "Save capability changes"}</button>
    </div>
  </>;
}
