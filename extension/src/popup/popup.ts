// POPUP CONTROLLER
//
// This file runs whenever the user clicks the Beacon icon in the toolbar.
// It communicates only with the background service worker — never directly
// with the page — because the popup cannot touch the page's DOM.
//
// Flow:
//   1. Popup opens → ask background for the stored result for this tab
//   2. Background responds with { result, pageData } or { error: "not found" }
//   3. Display the result (score, verdict, explanation, findings list)
//   4. Enable the "Check this page" button only if score >= 4

import type { HeuristicResult, ExtractedPageData } from "../types/heuristics";

// Protocols Chrome does not inject content scripts into. The popup must show a
// distinct message on these pages because the content script will never have
// run, so no result is ever stored for the tab.
const RESTRICTED_PROTOCOLS = new Set([
    "chrome:",
    "chrome-extension:",
    "edge:",
    "about:",
    "view-source:",
    "file:",
]);

function isRestrictedUrl(url: string): boolean {
    try {
        return RESTRICTED_PROTOCOLS.has(new URL(url).protocol);
    } catch {
        return false;
    }
}

// –– Element references ––
// document.getElementById returns HTMLElement | null.
// We cast each one to the specific element type we know it is so TypeScript
// lets us use element-specific properties (e.g. .disabled on a button).

const scanButton      = document.getElementById("scan-button")      as HTMLButtonElement;
const resultsDiv      = document.getElementById("results")          as HTMLDivElement;
const scoreCircle     = document.getElementById("score-circle")     as HTMLDivElement;
const scoreNumber     = document.getElementById("score-number")     as HTMLSpanElement;
const verdictText     = document.getElementById("verdict-text")     as HTMLParagraphElement;
const verdictUrl      = document.getElementById("verdict-url")      as HTMLParagraphElement;
const explanationText = document.getElementById("explanation-text") as HTMLParagraphElement;
const findingsSection = document.getElementById("findings-section") as HTMLDivElement;
const findingsList    = document.getElementById("findings-list")    as HTMLUListElement;
const errorDiv        = document.getElementById("error")            as HTMLDivElement;
const errorMessage    = document.getElementById("error-message")    as HTMLParagraphElement;

// –– Helper: extract readable domain from a full URL ––

function getDomain(url: string): string {
    try {
        return new URL(url).hostname;
    } catch {
        return url;
    }
}

// –– Show error state ––
// Displays an error message in the popup.

function showError(message: string): void {
    resultsDiv.classList.add("hidden");
    errorDiv.classList.remove("hidden");
    errorMessage.textContent = message;
}

// –– Show heuristic result ––
// Takes the HeuristicResult from the background and updates every UI element.

function showHeuristicResult(result: HeuristicResult, url: string): void {
    errorDiv.classList.add("hidden");
    resultsDiv.classList.remove("hidden");

    // Score circle: update number and background colour. The verdict value
    // doubles as the CSS class suffix (safe / uncertain / scam).
    scoreNumber.textContent = result.score.toString();
    scoreCircle.classList.remove("score-safe", "score-uncertain", "score-scam");
    scoreCircle.classList.add("score-" + result.verdict);

    // Verdict text is lowercase in the model; CSS text-transform: capitalize
    // renders it as "Safe" / "Uncertain" / "Scam" in the popup.
    verdictText.textContent = result.verdict;
    verdictText.classList.remove("verdict-safe", "verdict-uncertain", "verdict-scam");
    verdictText.classList.add("verdict-" + result.verdict);

    // Show the domain of the page at the time of analysis.
    verdictUrl.textContent = getDomain(url);

    // Plain-language explanation.
    explanationText.textContent = result.explanation;

    // Findings list: show only if there is something to report.
    if (result.findings.length > 0) {
        findingsSection.classList.remove("hidden");
        findingsList.innerHTML = "";
        for (const finding of result.findings) {
            const li = document.createElement("li");
            li.textContent = finding;
            findingsList.appendChild(li);
        }
    } else {
        findingsSection.classList.add("hidden");
    }

    // Enable "Check this page" (Tier 2) only when heuristics flagged the page.
    // score < 4 means verdict is "Safe" — no need for deeper analysis.
    scanButton.disabled = result.score < 4;
}

// –– Load result on popup open ––
// DOMContentLoaded fires as soon as the popup HTML is parsed.
// We immediately ask the background for the stored result for the active tab.

document.addEventListener("DOMContentLoaded", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs[0];

        if (!tab?.id) {
            showError("Could not identify the current tab.");
            return;
        }

        // Chrome does not inject content scripts on chrome:// / file:// / etc.
        // Show a clearer message instead of the generic "not analysed" error.
        if (isRestrictedUrl(tab.url ?? "")) {
            showError("Beacon cannot analyse this page type.");
            return;
        }

        // Ask the background service worker for the stored analysis result.
        // The background responds with { result, pageData } or { error: "..." }.
        chrome.runtime.sendMessage(
            { action: "getResult", tabId: tab.id },
            (response: { result?: HeuristicResult; pageData?: ExtractedPageData; error?: string }) => {
                // chrome.runtime.lastError is set if the background didn't respond
                // (e.g. it was just installed and hasn't run yet).
                if (chrome.runtime.lastError) {
                    showError("Beacon is starting up. Reload the page and try again.");
                    return;
                }

                if (response?.error || !response?.result) {
                    showError("Page not analysed yet. Refresh the page and try again.");
                    return;
                }

                // Use the URL captured at analysis time rather than the current tab URL.
                // On SPAs the tab URL can change after the analysis ran, so pageData.url
                // is more accurate for the domain shown in the popup.
                const analysedUrl = response.pageData?.url ?? tab.url ?? "";
                showHeuristicResult(response.result, analysedUrl);
            }
        );
    });
});

// –– "Check this page" button — Tier 2 (not implemented yet) ––
// This button is only enabled when heuristics produce a score >= 4.
// Clicking it will eventually call the API for a deeper AI analysis.

scanButton.addEventListener("click", () => {
    // TODO (Tier 2): send page text to POST /v1/check and show the AI result
    alert("Deep analysis coming soon!");
});
