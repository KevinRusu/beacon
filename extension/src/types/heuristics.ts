// SHARED Types for Heuristics (used by all modules)
// Anyone on the team building a heuristic function (URL checks, content
// checks, etc.) should import these types and use them as the input and
// output shapes for their function. This guarantees that all heuristic
// modules speak the same language and can be combined cleanly.

// Verdict

export type Verdict = "safe" | "uncertain" | "scam";

// HeuristicSource - describes which module produced the result.
// "content"  = text/phrase/link analysis of the page body
// "url"      = analysis of the page URL itself
// "combined" = a merged result from both url + content sources

export type HeuristicSource = "content" | "url" | "combined";

// HeuristicResult - the shape of output from any heuristic function

export interface HeuristicResult {
    score: number;
    verdict: Verdict;
    explanation: string;
    findings: string[];
    source: HeuristicSource;
}

// Link - extracted from page, links have visible text and href
// needed to detect mismatched link detection

export interface Link {
    text: string;
    href: string;
}

// ExtractedData - the shape of input that heuristic function receives

export interface ExtractedPageData {
    url: string;
    title: string;
    metaDescription: string;
    textContent: string;
    links: Link[];
}