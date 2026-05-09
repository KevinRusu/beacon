// BACKGROUND SERVICE WORKER
//
// A Chrome extension has three isolated worlds that can't share memory directly:
//   content script (runs inside the page)
//   popup (runs when the user opens the extension)
//   background service worker (this file — runs behind the scenes)
//
// The background worker acts as a shared storage hub between the other two.
// It receives analysis results from the content script and holds them so the
// popup can retrieve them later, even if the popup opens after the page loaded.
//
// Message flow:
//
//   content.ts  ->  { action: "storeResult", result, pageData }  →  background.ts
//                       (sent once automatically on every page load)
//
//   popup.ts    ->  { action: "getResult", tabId }               →  background.ts
//   background.ts  ->  { result, pageData }  OR  { error: "not found" }  →  popup.ts

// –– Local type declarations ––
// Background service workers built as IIFE scripts can't use ES module imports
// at runtime, so we redeclare the minimal shapes we need here.
// Keep in sync with src/types/heuristics.ts.

type Verdict = "Safe" | "Uncertain" | "Likely Scam";
type HeuristicSource = "content" | "url" | "combined";

interface HeuristicResult {
    score: number;
    verdict: Verdict;
    explanation: string;
    findings: string[];
    source: HeuristicSource;
}

interface Link {
    text: string;
    href: string;
}

interface ExtractedPageData {
    url: string;
    title: string;
    metaDescription: string;
    textContent: string;
    links: Link[];
}

interface StoredEntry {
    result: HeuristicResult;
    pageData: ExtractedPageData;
}

// –– Storage ––
// A Map that holds one analysis result per open tab.
// Key   = Chrome tab ID (a number Chrome assigns to each tab).
// Value = the HeuristicResult + page data produced by the content script.
//
// Note: this Map lives in memory only. If Chrome kills the service worker to
// save resources, the Map is cleared. For production, use chrome.storage.session.

const tabResults = new Map<number, StoredEntry>();

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
        },
        sender: chrome.runtime.MessageSender,
        sendResponse: (response: unknown) => void
    ) => {
        if (message.action === "storeResult") {
            // Content script finished heuristics and is handing us the result.
            // sender.tab.id tells us which tab sent the message.
            const tabId = sender.tab?.id;
            if (tabId !== undefined && message.result && message.pageData) {
                tabResults.set(tabId, {
                    result: message.result,
                    pageData: message.pageData,
                });
                console.log(`[Beacon] stored result for tab ${tabId}`, message.result);
            }
            sendResponse({ success: true });
            return true;
        }

        if (message.action === "getResult") {
            // Popup opened and wants the stored result for a given tab.
            const stored = message.tabId !== undefined
                ? tabResults.get(message.tabId)
                : undefined;

            if (stored) {
                sendResponse(stored); // { result, pageData }
            } else {
                sendResponse({ error: "not found" });
            }
            return true;
        }

        return false;
    }
);

// –– Tab cleanup ––
// When a tab closes, remove its stored entry so memory doesn't grow forever.

chrome.tabs.onRemoved.addListener((tabId: number) => {
    tabResults.delete(tabId);
});
