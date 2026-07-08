// CONTENT SCRIPT
//
// This file runs automatically on every webpage the user visits.
// Chrome injects it based on the rule in manifest.json.
//
// Responsibilities:
//   (1) Extract structured data from the page (URL, title, text, links)
//   (2) Run both heuristics (URL + content) and combine the results
//   (3) Send the combined result to the background service worker for storage
//   (4) Listen for "scanPage" messages from the popup (kept for debugging)

import type { HeuristicResult, ExtractedPageData, Link, FormInfo } from "../types/heuristics";
import { analyzeContent, toVerdict } from "../heuristics/contentHeuristics";
import { analyzeUrl }                from "../heuristics/urlHeuristics";
import { analyzeLinks }              from "../heuristics/linkHeuristics";

// –– Trusted aggregator bypass ––
// Search engines, encyclopedias, and social platforms aggregate content from
// across the web. Their pages legitimately contain ad copy and user-generated
// text that can match scam-phrase patterns (e.g. "limited time offer" in a
// Google Shopping ad). When we're on one of these known-safe domains AND the
// URL itself raised zero suspicion, content and link analysis add no signal —
// they only produce false positives — so we skip them entirely.

const TRUSTED_AGGREGATORS: string[] = [
    "google.com",
    "bing.com",
    "duckduckgo.com",
    "yahoo.com",
    "wikipedia.org",
    "reddit.com",
    "youtube.com",
    "twitter.com",
    "x.com",
];

function isTrustedAggregator(url: string): boolean {
    try {
        const hostname = new URL(url).hostname.toLowerCase();
        return TRUSTED_AGGREGATORS.some(
            d => hostname === d || hostname.endsWith(`.${d}`)
        );
    } catch {
        return false;
    }
}

// –– Data extraction ––
// Reads the current page's DOM and returns a structured snapshot.

function extractPageData(): ExtractedPageData {
    const url = window.location.href;
    const title: string = document.title;

    // Meta description: sites use this to summarise their content.
    // Often contains scammy language in phishing pages.
    const metaDescription: string =
        document.querySelector('meta[name="description"]')?.getAttribute("content") ?? "";

    // Prefer a semantic content area if the page has one.
    const mainElement: HTMLElement | null =
        document.querySelector("main") ||
        document.querySelector("article") ||
        document.querySelector<HTMLElement>('[role="main"]');

    const rawText: string = mainElement
        ? mainElement.innerText
        : document.body?.innerText ?? "";

    // Cap at 5,000 chars to keep the payload small.
    const textContent: string = rawText.trim().substring(0, 5000);

    // Collect up to 100 links that have visible text and a real URL.
    const linkElements = document.querySelectorAll("a[href]");
    const links: Link[] = Array.from(linkElements)
        .map((el) => ({
            text: (el.textContent ?? "").trim(),
            href: el.getAttribute("href") ?? "",
        }))
        .filter(
            (link) =>
                link.text.length > 0 &&
                (link.href.startsWith("http://") || link.href.startsWith("https://"))
        )
        .slice(0, 100);

    // Collect <form> elements with absolute action URLs — used to detect
    // cross-domain credential submission (passwords sent to attacker's server).
    const forms: FormInfo[] = Array.from(document.querySelectorAll("form"))
        .map((form) => {
            const raw = form.getAttribute("action") ?? "";
            let action = raw;
            if (raw && !raw.startsWith("http")) {
                try { action = new URL(raw, window.location.href).href; } catch { action = ""; }
            }
            return {
                action,
                hasPasswordField: form.querySelector('input[type="password"]') !== null,
            };
        })
        .filter((f) => f.action.startsWith("http"))
        .slice(0, 20);

    // Concatenate text from all interactive CTAs (pipe-separated).
    // Weighted higher than body text in content rules because these are
    // intentional calls-to-action crafted by the page author.
    const buttonText = Array.from(
        document.querySelectorAll<HTMLElement>(
            'button, input[type="submit"], input[type="button"], [role="button"]'
        )
    )
        .map((el) => {
            const text = el.textContent?.trim() ?? "";
            const value = el instanceof HTMLInputElement ? el.value.trim() : "";
            return text || value;
        })
        .filter((t) => t.length > 0)
        .join(" | ");

    // Collect alt texts of images that match known security-badge brand names.
    // Phishing pages place fake Norton/McAfee/etc. images to appear trustworthy.
    const BADGE_BRANDS = ["norton", "mcafee", "digicert", "comodo", "trustwave"];
    const badgeAltTexts = Array.from(document.querySelectorAll("img[alt]"))
        .map((img) => img.getAttribute("alt") ?? "")
        .filter((alt) => BADGE_BRANDS.some((b) => alt.toLowerCase().includes(b)));

    // Capture text from any immediately visible modal or dialog.
    // Scam pages often show prize/urgency overlays on load.
    const overlayEl = ((): HTMLElement | null => {
        const openDialog = document.querySelector<HTMLElement>("dialog[open]");
        if (openDialog) return openDialog;
        return (
            Array.from(
                document.querySelectorAll<HTMLElement>('[role="dialog"], [aria-modal="true"]')
            ).find((el) => el.offsetHeight > 50) ?? null
        );
    })();
    const overlayText = overlayEl?.innerText?.trim().substring(0, 500) ?? "";

    return { url, title, metaDescription, textContent, links, forms, buttonText, badgeAltTexts, overlayText };
}

// –– Result combination ––
// Takes the output of two heuristics (URL + content) and merges them into
// a single HeuristicResult. This lets the popup always deal with one object,
// regardless of how many heuristics ran.

function combineResults(
    urlResult: HeuristicResult,
    contentResult: HeuristicResult,
    linkResult: HeuristicResult
): HeuristicResult {
    const urlThreat     = 10 - urlResult.score;
    let   contentThreat = 10 - contentResult.score;
    let   linkThreat    = 10 - linkResult.score;

    // URL veto: when the URL module is completely clean (threat 0), weak
    // content/link signals are more likely to be false positives from
    // aggregated content than genuine indicators of the page itself.
    // Discard any content or link threat below 6 in that case.
    // Strong signals (≥ 6, meaning the module would independently flag "scam")
    // still carry through even on a clean URL.
    if (urlThreat === 0) {
        if (contentThreat < 6) contentThreat = 0;
        if (linkThreat    < 6) linkThreat    = 0;
    }

    const combinedThreat = Math.min(10, urlThreat + contentThreat + linkThreat);
    const score = 10 - combinedThreat;

    // Merge findings from all three modules in order.
    const findings = [...urlResult.findings, ...contentResult.findings, ...linkResult.findings];

    // Single source of truth for thresholds — toVerdict lives in contentHeuristics.ts.
    const { verdict, explanation } = toVerdict(score);

    return { score, verdict, explanation, findings, source: "combined" };
}

// –– Logging helper ––
// Prints a formatted summary of extracted page data to the browser console.
// Open DevTools on any page (F12 → Console) and look for [Beacon] entries.

function logExtractedData(label: string, data: ExtractedPageData): void {
    console.group(`[Beacon] Page data (${label})`);
    console.log("URL:", data.url);
    console.log("Title:", data.title);
    console.log("Meta description:", data.metaDescription);
    console.log("Text length:", data.textContent.length, "chars");
    console.log("Text preview:", data.textContent.substring(0, 200) + "…");
    console.log("Links found:", data.links.length);
    console.table(data.links.slice(0, 10));
    console.groupEnd();
}

// –– Pipeline (runs once on page load) ––

const initialData = extractPageData();
logExtractedData("page load", initialData);

// Run all three heuristics and combine into one result.
const urlResult = analyzeUrl(initialData.url);

// Skip content and link analysis on trusted aggregator domains when the URL
// is already clean — their pages contain aggregated/ad content that produces
// false positives without adding meaningful detection signal.
const skipContentAnalysis = isTrustedAggregator(initialData.url) && urlResult.score === 10;

const SAFE_MODULE: HeuristicResult = {
    score: 10, verdict: "safe",
    explanation: "Trusted aggregator — content analysis skipped.",
    findings: [], source: "content",
};

const contentResult = skipContentAnalysis ? SAFE_MODULE : analyzeContent(initialData);
const linkResult    = skipContentAnalysis
    ? { ...SAFE_MODULE, source: "url" as const }
    : analyzeLinks(initialData.links, initialData.url);

const combined = combineResults(urlResult, contentResult, linkResult);

console.log("[Beacon] Combined heuristic result:", combined);

// Hand the result to the background service worker for storage.
// The popup will request it later via { action: "getResult" }.
chrome.runtime.sendMessage({
    action:   "storeResult",
    result:   combined,
    pageData: initialData,
});

// –– Popup message listener (debugging) ––
// Kept so the popup can also request fresh page data directly if needed.
// "return true" tells Chrome to keep the message channel open so that
// sendResponse can be called after this listener returns.

chrome.runtime.onMessage.addListener(
    (
        message: { action: string },
        _sender: chrome.runtime.MessageSender,
        sendResponse: (response: ExtractedPageData) => void
    ) => {
        if (message.action === "scanPage") {
            const freshData = extractPageData();
            logExtractedData("popup scan", freshData);
            sendResponse(freshData);
        }
        return true;
    }
);
