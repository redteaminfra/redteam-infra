/* Copyright (c) 2026, Oracle and/or its affiliates. */
import React from "react";
import ReactDOM from "react-dom/client";

import { AuthenticatedApp } from "./auth/AuthenticatedApp";
import "./styles/global.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <AuthenticatedApp />
  </React.StrictMode>
);
