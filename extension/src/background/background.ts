// BACKGROUND SERVICE WORKER
//
// A Chrome extension has three isolated worlds that can't share memory directly:
//   content script (runs inside the page)
//   popup (runs when the user opens the extension)
//   background service worker (this file — runs behind the scenes)
//
// The background worker acts as a shared storage hub between the other two,
// and is the ONLY place that talks to the Beacon API over the network —
// the popup and content script never fetch.
//
// Message flow:
//
//   content.ts  ->  { action: "storeResult", result, pageData }  →  background.ts
//                       (sent once automatically on every page load)
//
//   popup.ts    ->  { action: "getResult", tabId }               →  background.ts
//   background.ts  ->  { result, pageData, aiResult? }  OR  { error: "not found" }  →  popup.ts
//
//   popup.ts    ->  { action: "checkWithAI", tabId }             →  background.ts
//   background.ts  ->  { aiResult }  OR  { error }               →  popup.ts
//                       (result is also cached, so it survives popup close/reopen)
//
//   popup.ts    ->  { action: "setEnabled", enabled: boolean }   →  background.ts
//   popup.ts    ->  { action: "getEnabled" }                     →  background.ts
//   background.ts  ->  { enabled: boolean }                      →  popup.ts

import type { HeuristicResult, ExtractedPageData } from "../types/heuristics";
import type { AnalyzeResponse } from "../types/api";

// StoredEntry is the only shape not exported from the shared types file.
interface StoredEntry {
    result: HeuristicResult;
    pageData: ExtractedPageData;
    aiResult?: AnalyzeResponse;
}

// –– Storage ––
// chrome.storage.session persists for the lifetime of the browser session and
// survives Chrome suspending the service worker to save resources.
// Key pattern: "tab_<tabId>" → StoredEntry JSON.
//
// chrome.storage.local persists across browser restarts and is used for
// user preferences like the "Enable Beacon" toggle.

// –– Tier 2 API call ––
// Builds the wire payload in exactly one place. Score convention: everything
// is a SAFETY score (10 = safe, 0 = scam) — the extension's internal score,
// the heuristic_score request field, and the safety_score response field all
// use the same scale. Nothing is inverted anywhere.
// Field truncations mirror the server-side caps in api/schemas.py.
// No auth header: the API has no client secret (see api/auth.py); the server
// checks the request Origin and rate-limits instead.

async function checkWithAI(stored: StoredEntry): Promise<AnalyzeResponse> {
    const { result, pageData } = stored;
    const resp = await fetch(`${__API_BASE_URL__}/v1/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            url: pageData.url.slice(0, 2048),
            text: pageData.textContent.slice(0, 1500),
            heuristic_score: result.score,
            context: "page_body",
            title: pageData.title.slice(0, 300),
            meta_description: pageData.metaDescription.slice(0, 500),
            heuristic_verdict: result.verdict,
            heuristic_findings: result.findings.slice(0, 20).map((f) => f.slice(0, 300)),
        }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return (await resp.json()) as AnalyzeResponse;
}

// –– Message listener ––
// chrome.runtime.onMessage fires whenever content.ts or popup.ts calls
// chrome.runtime.sendMessage(). We read message.action to decide what to do.

chrome.runtime.onMessage.addListener(
    (
        message: {
            action: string;
            result?: HeuristicResult;
            pageData?: ExtractedPageData;
            tabId?: number;
            enabled?: boolean;
        },
        sender: chrome.runtime.MessageSender,
        sendResponse: (response: unknown) => void
    ) => {
        if (message.action === "storeResult") {
            // Content script finished heuristics and is handing us the result.
            // Skip storing if the user has disabled Beacon.
            const tabId = sender.tab?.id;
            if (tabId !== undefined && message.result && message.pageData) {
                (async () => {
                    const prefs = await chrome.storage.local.get("isEnabled");
                    const isEnabled = prefs["isEnabled"] !== false; // default true
                    if (!isEnabled) {
                        sendResponse({ success: false });
                        return;
                    }
                    const entry: StoredEntry = {
                        result: message.result!,
                        pageData: message.pageData!,
                    };
                    await chrome.storage.session.set({ [`tab_${tabId}`]: entry });
                    console.log(`[Beacon] stored result for tab ${tabId}`, message.result);
                    sendResponse({ success: true });
                })();
            } else {
                sendResponse({ success: false });
            }
            return true;
        }

        if (message.action === "getResult") {
            // Popup opened and wants the stored result for a given tab.
            if (message.tabId !== undefined) {
                const key = `tab_${message.tabId}`;
                (async () => {
                    const data = await chrome.storage.session.get(key);
                    const stored = data[key] as StoredEntry | undefined;
                    if (stored) {
                        sendResponse(stored); // { result, pageData, aiResult? }
                    } else {
                        sendResponse({ error: "not found" });
                    }
                })();
            } else {
                sendResponse({ error: "not found" });
            }
            return true;
        }

        if (message.action === "checkWithAI") {
            // Popup asked for a Tier 2 (LLM) analysis of a tab's stored result.
            // Running the fetch here means it completes even if the popup closes,
            // and the cached aiResult is there when the popup reopens.
            if (message.tabId === undefined) {
                sendResponse({ error: "not found" });
                return true;
            }
            const key = `tab_${message.tabId}`;
            (async () => {
                const data = await chrome.storage.session.get(key);
                const stored = data[key] as StoredEntry | undefined;
                if (!stored) {
                    sendResponse({ error: "not found" });
                    return;
                }
                try {
                    const aiResult = await checkWithAI(stored);
                    await chrome.storage.session.set({ [key]: { ...stored, aiResult } });
                    sendResponse({ aiResult });
                } catch (e) {
                    console.warn("[Beacon] AI check failed:", e);
                    sendResponse({ error: "unavailable" });
                }
            })();
            return true;
        }

        if (message.action === "getEnabled") {
            (async () => {
                const prefs = await chrome.storage.local.get("isEnabled");
                const isEnabled = prefs["isEnabled"] !== false; // default true
                sendResponse({ enabled: isEnabled });
            })();
            return true;
        }

        if (message.action === "setEnabled") {
            const enabled = message.enabled !== false;
            (async () => {
                await chrome.storage.local.set({ isEnabled: enabled });
                // When disabling, clear all stored tab results so the popup
                // won't show stale data from before the extension was paused.
                if (!enabled) {
                    const all = await chrome.storage.session.get(null);
                    const tabKeys = Object.keys(all).filter((k) => k.startsWith("tab_"));
                    if (tabKeys.length > 0) {
                        await chrome.storage.session.remove(tabKeys);
                    }
                }
                sendResponse({ success: true });
            })();
            return true;
        }

        return false;
    }
);

// –– Tab cleanup ––
// When a tab closes, remove its stored entry so session storage doesn't grow forever.

chrome.tabs.onRemoved.addListener(async (tabId: number) => {
    await chrome.storage.session.remove(`tab_${tabId}`);
});