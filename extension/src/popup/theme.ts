// POPUP THEME
//
// Unlike the other preferences (isEnabled, aiEnabled) this one lives in
// localStorage rather than chrome.storage.local, for one reason: it must be
// readable *synchronously*. The theme class has to be on <html> before React
// paints, otherwise the popup renders light and then flips to dark — a visible
// flash every single time it opens, because chrome.storage.local is async.
//
// That trade is safe here because the theme is popup-only presentation state:
// the background worker and content script never read it. MV3's CSP forbids
// inline scripts in popup.html, so applying it at the top of popup.tsx (before
// createRoot().render()) is the earliest hook available.

const KEY = "theme";

export type Theme = "light" | "dark";

// First run has no stored value, so follow the OS instead of assuming light.
export function readTheme(): Theme {
    const stored = localStorage.getItem(KEY);
    if (stored === "light" || stored === "dark") return stored;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

// Both classes are set explicitly. Tailwind keys off .dark, while .light is
// what lets an explicit "light" choice override the prefers-color-scheme
// fallback in popup.css.
export function applyTheme(theme: Theme): void {
    const root = document.documentElement;
    root.classList.toggle("dark", theme === "dark");
    root.classList.toggle("light", theme === "light");
}

export function saveTheme(theme: Theme): void {
    localStorage.setItem(KEY, theme);
}
