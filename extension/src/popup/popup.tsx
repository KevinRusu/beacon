import React from "react";
import { createRoot } from "react-dom/client";
import "./popup.css";
import App from "./App";
import { applyTheme, readTheme } from "./theme";

// Before the first render, so the popup never paints light and then flips.
applyTheme(readTheme());

const root = document.getElementById("root")!;
createRoot(root).render(<App />);
