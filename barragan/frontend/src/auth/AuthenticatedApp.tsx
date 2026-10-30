/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { FormEvent, useEffect, useRef, useState } from "react";

import { apiClient, AuthSession, BarraganApiError, DashboardInventory } from "../api/client";
import { App } from "../routes/App";

type AuthState = "checking" | "bypass" | "signed-out" | "signed-in" | "error";

export function AuthenticatedApp() {
  const [state, setState] = useState<AuthState>("checking");
  const [session, setSession] = useState<AuthSession | null>(null);
  const [message, setMessage] = useState("");
  const [changingPassword, setChangingPassword] = useState(false);
  const [prefetchedDashboard, setPrefetchedDashboard] = useState<DashboardInventory | null>(null);
  const bootstrapRequestsRef = useRef<{
    session: ReturnType<typeof apiClient.authSession>;
    dashboard: Promise<DashboardInventory | null>;
  } | null>(null);
  const bootstrapAppliedRef = useRef(false);

  useEffect(() => {
    let active = true;
    if (!bootstrapRequestsRef.current) {
      bootstrapRequestsRef.current = {
        session: apiClient.authSession(),
        dashboard: apiClient.dashboard().then((response) => response.dashboard).catch(() => null)
      };
    }
    const requests = bootstrapRequestsRef.current;
    const applyOnce = (apply: () => void) => {
      if (!active || bootstrapAppliedRef.current) return;
      bootstrapAppliedRef.current = true;
      apply();
    };
    requests.session
      .then((result) => {
        const allowed = (!result.authRequired || (result.authenticated && Boolean(result.user))) && !result.mustChangePassword;
        if (!allowed) {
          applyOnce(() => {
            setSession(result);
            setPrefetchedDashboard(null);
            setState(result.authRequired && result.authenticated ? "signed-in" : "signed-out");
          });
          return;
        }
        void requests.dashboard.then((dashboard) => {
          applyOnce(() => {
            setSession(result);
            setPrefetchedDashboard(dashboard);
            setState(!result.authRequired ? "bypass" : "signed-in");
          });
        });
      })
      .catch(() => {
        applyOnce(() => {
          setPrefetchedDashboard(null);
          setState("signed-out");
        });
      });
    return () => { active = false; };
  }, []);

  if (state === "checking") {
    return <AuthFrame title="Opening Barragan"><p>Checking your session…</p></AuthFrame>;
  }

  if (state === "bypass") return <App prefetchedDashboard={prefetchedDashboard} />;

  if (state === "signed-in" && session?.user && !session.mustChangePassword && !changingPassword) {
    return (
      <App currentUser={session.user} prefetchedDashboard={prefetchedDashboard} onChangePassword={() => setChangingPassword(true)} onSignOutAll={() => {
            void apiClient.logoutAll().finally(() => {
              setPrefetchedDashboard(null);
              setSession(null);
              setState("signed-out");
            });
          }} onSignOut={() => {
            void apiClient.logout().finally(() => {
              setPrefetchedDashboard(null);
              setSession(null);
              setState("signed-out");
            });
          }} />
    );
  }

  if (state === "signed-in" && session && (session.mustChangePassword || changingPassword)) {
    return <PasswordChange session={session} onCancel={!session.mustChangePassword ? () => setChangingPassword(false) : undefined} onLogout={() => {
      void apiClient.logout().finally(() => {
        setPrefetchedDashboard(null);
        setSession(null);
        setState("signed-out");
      });
    }} onChanged={(result) => {
      setSession(result);
      setChangingPassword(false);
      setMessage("Password changed. Your account is ready.");
    }} />;
  }

  return <Login message={message} onAuthenticated={(result) => {
    setPrefetchedDashboard(null);
    setSession(result);
    setState("signed-in");
    setMessage("");
  }} />;
}

function Login({ message, onAuthenticated }: { message: string; onAuthenticated: (session: AuthSession) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [working, setWorking] = useState(false);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setWorking(true);
    setError("");
    apiClient.login(username, password)
      .then(onAuthenticated)
      .catch((reason: unknown) => setError(authErrorMessage(reason, "Sign-in failed.")))
      .finally(() => setWorking(false));
  };

  return (
    <AuthFrame title="Sign in to Barragan">
      {message ? <p className="auth-success" role="status">{message}</p> : null}
      {error ? <p className="auth-error" role="alert">{error}</p> : null}
      <form className="auth-form" onSubmit={submit}>
        <label>Username<input autoComplete="username" autoFocus required value={username} onChange={(event) => setUsername(event.target.value)} /></label>
        <label>Password<input autoComplete="current-password" required type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
        <button disabled={working} type="submit">{working ? "Signing in…" : "Sign in"}</button>
      </form>
    </AuthFrame>
  );
}

function PasswordChange({ session, onChanged, onLogout, onCancel }: {
  session: AuthSession;
  onChanged: (session: AuthSession) => void;
  onLogout: () => void;
  onCancel?: () => void;
}) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState("");
  const [working, setWorking] = useState(false);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const policyError = permanentPasswordPolicyError(newPassword);
    if (policyError) {
      setError(policyError);
      return;
    }
    if (newPassword !== confirmation) {
      setError("The new passwords do not match.");
      return;
    }
    setWorking(true);
    setError("");
    apiClient.changePassword(currentPassword, newPassword)
      .then(onChanged)
      .catch((reason: unknown) => setError(authErrorMessage(reason, "Password change failed.")))
      .finally(() => setWorking(false));
  };

  return (
    <AuthFrame title={session.mustChangePassword ? "Choose a permanent password" : "Change your password"}>
      <p className="auth-intro">{session.mustChangePassword ? `Welcome, ${session.user?.username}. Change the temporary password before continuing.` : "Changing your password signs out your other Barragan sessions."}</p>
      {error ? <p className="auth-error" role="alert">{error}</p> : null}
      <form className="auth-form" onSubmit={submit}>
        <label>Temporary password<input autoComplete="current-password" required type="password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} /></label>
        <label>New password<input autoComplete="new-password" minLength={10} required type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} /></label>
        <label>Confirm new password<input autoComplete="new-password" minLength={10} required type="password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label>
        <small>Use 10–128 characters. Spaces and Unicode are welcome.</small>
        <button disabled={working} type="submit">{working ? "Changing password…" : "Change password"}</button>
        {onCancel ? <button className="auth-secondary" onClick={onCancel} type="button">Cancel</button> : null}
        <button className="auth-secondary" onClick={onLogout} type="button">Sign out</button>
      </form>
    </AuthFrame>
  );
}

export function permanentPasswordPolicyError(password: string): string {
  const characterCount = Array.from(password).length;
  if (characterCount < 10) return "Password must be at least 10 characters.";
  if (characterCount > 128) return "Password must be at most 128 characters.";
  return "";
}

function AuthFrame({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <main className="auth-page">
      <section className="auth-panel">
        <div className="auth-brand"><span>B</span><div><strong>Barragan</strong><small>RTI Control Plane</small></div></div>
        <h1>{title}</h1>
        {children}
      </section>
    </main>
  );
}

function authErrorMessage(reason: unknown, fallback: string): string {
  return reason instanceof BarraganApiError ? reason.message : fallback;
}
