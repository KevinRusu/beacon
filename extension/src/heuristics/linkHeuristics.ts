/**
 * linkHeuristics.ts
 *
 * Analyses the links found on the current page and returns a HeuristicResult.
 *
 * Two detection passes:
 *   (A) Mismatched link detection — visible text claims domain X, href goes to Y
 *   (B) Per-link URL heuristics  — 8 checks on each link's href
 *
 * Scoring (0–10, capped):
 *   0–3  → safe
 *   4–6  → uncertain
 *   7+   → scam
 */

import type { HeuristicResult, Link, Verdict } from "../types/heuristics";
import { toVerdict } from "./contentHeuristics";

// ─── Brand data ───────────────────────────────────────────────────────────────

const BRAND_FAVICONS: Record<string, string[]> = {
    amazon:    ["https://www.amazon.com/favicon.ico", "https://m.media-amazon.com/images/favicon"],
    apple:     ["https://www.apple.com/favicon.ico", "https://www.apple.com/assets/"],
    google:    ["https://www.google.com/favicon.ico"],
    facebook:  ["https://www.facebook.com/favicon.ico"],
    paypal:    ["https://www.paypal.com/favicon.ico"],
    github:    ["https://github.com/favicon.ico"],
    microsoft: ["https://www.microsoft.com/favicon.ico"],
    linkedin:  ["https://www.linkedin.com/favicon.ico"],
};

const COMMON_TYPOSQUATTING_PATTERNS: Record<string, string[]> = {
    google:    ["googl", "gogle", "goog1e", "g00gle", "g0ogle"],
    amazon:    ["amazo", "amaz0n", "amaZon", "am4zon"],
    facebook:  ["facebok", "faceb00k", "f4cebook", "faceboo"],
    paypal:    ["p4yp4l", "paypa1", "p@ypal"],
    apple:     ["4pple", "@pple", "appie"],
    microsoft: ["microsof", "micr0soft", "m1cr0s0ft"],
    twitter:   ["twiter", "tw1tter", "twitter1"],
    instagram: ["instag4m", "insta9ram", "inst4gram"],
    github:    ["g1thub", "gihub"],
    linkedin:  ["link3d1n", "1inkedin"],
};

const HOMOGLYPH_MAP: Record<string, string> = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "7": "t", "8": "b", "9": "g",
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function parseHostname(url: string): string {
    try {
        return new URL(url).hostname.toLowerCase();
    } catch {
        return "";
    }
}

function extractBaseDomain(hostname: string): string {
    const parts = hostname.split(".");
    return parts.length >= 2 ? parts.slice(-2).join(".") : hostname;
}

function extractDomain(url: string): string {
    try {
        const urlWithProtocol = url.startsWith("http") ? url : `http://${url}`;
        return new URL(urlWithProtocol).hostname || "";
    } catch {
        const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^/?#]+)/);
        return match ? match[1] : "";
    }
}

/**
 * Tries to parse a domain claim from link visible text.
 * Returns null when the text doesn't look like a URL or domain reference.
 */
function extractClaimedDomain(linkText: string): string | null {
    const text = linkText.trim().toLowerCase();
    const commonTlds = [".com", ".net", ".org", ".io", ".co", ".uk", ".de", ".jp", ".fr"];
    const hasTld = commonTlds.some(tld => text.endsWith(tld) || text.includes(tld + "/"));
    if (!hasTld) return null;

    try {
        return new URL(text).hostname.toLowerCase();
    } catch {
        try {
            return new URL("http://" + text).hostname.toLowerCase();
        } catch {
            return null;
        }
    }
}

// ─── Per-link URL checks ──────────────────────────────────────────────────────

function checkExcessiveLength(url: string): { flagged: boolean; reason: string } {
    const domain = extractDomain(url);
    if (domain.length > 45) {
        return { flagged: true, reason: `Domain name is ${domain.length} characters (exceeds 45 char limit)` };
    }
    return { flagged: false, reason: "" };
}

function checkInsufficientLength(url: string): { flagged: boolean; reason: string } {
    const domain = extractDomain(url);
    const domainWithoutTLD = domain.split(".").slice(0, -1).join(".");
    if (domainWithoutTLD.length < 6 && domainWithoutTLD.length > 0) {
        return { flagged: true, reason: `Domain name is only ${domainWithoutTLD.length} characters (under 6 char minimum)` };
    }
    return { flagged: false, reason: "" };
}

function checkIPAddressLink(url: string): { flagged: boolean; reason: string } {
    const ipv4Regex = /^(?:https?:\/\/)?(\d{1,3}\.){3}\d{1,3}/;
    const ipv6Regex = /^(?:https?:\/\/)?\[?([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]?/;
    if (ipv4Regex.test(url)) {
        return { flagged: true, reason: "URL uses IP address instead of domain name (IPv4)" };
    }
    if (ipv6Regex.test(url)) {
        return { flagged: true, reason: "URL uses IP address instead of domain name (IPv6)" };
    }
    return { flagged: false, reason: "" };
}

function checkTyposquattingAndHomoglyphs(url: string): { flagged: boolean; reasons: string[] } {
    const domain = extractDomain(url).toLowerCase();
    const reasons: string[] = [];

    for (const [legitimate, misspellings] of Object.entries(COMMON_TYPOSQUATTING_PATTERNS)) {
        for (const misspelling of misspellings) {
            if (domain.includes(misspelling)) {
                reasons.push(`Possible typosquatting: "${misspelling}" resembles legitimate brand "${legitimate}"`);
            }
        }
    }

    for (const [number, letter] of Object.entries(HOMOGLYPH_MAP)) {
        if (domain.includes(number)) {
            const withoutNumber = domain.replace(new RegExp(number, "g"), letter);
            for (const brand of Object.keys(COMMON_TYPOSQUATTING_PATTERNS)) {
                if (withoutNumber.includes(brand)) {
                    reasons.push(`Homoglyph detected: "${number}" used instead of "${letter}" (resembles "${brand}")`);
                }
            }
        }
    }

    if (/[0-9]{2,}/.test(domain)) {
        const numberSequences = domain.match(/[0-9]{2,}/g);
        if (numberSequences) {
            reasons.push(`Multiple consecutive numbers detected: ${numberSequences.join(", ")}`);
        }
    }

    return { flagged: reasons.length > 0, reasons };
}

function checkZeroDayDomain(url: string): { flagged: boolean; reason: string } {
    const domain = extractDomain(url);
    const hyphenCount = (domain.match(/-/g) || []).length;
    const parts = domain.split(".");
    const domainName = parts.slice(0, -1).join(".");

    if (hyphenCount > 2) {
        return { flagged: true, reason: `Excessive hyphens in domain (${hyphenCount}), typical of zero-day/newly registered domains` };
    }

    const hasOnlyConsonants = /^[bcdfghjklmnpqrstvwxyz-]+$/.test(domainName);
    if (domainName.length > 5 && hasOnlyConsonants) {
        return { flagged: true, reason: "Domain name pattern suggests zero-day/randomly generated domain (mostly consonants)" };
    }

    const tld = parts[parts.length - 1].toLowerCase();
    const rareTLDs = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "download", "review"];
    if (rareTLDs.includes(tld)) {
        return { flagged: true, reason: `Rare/suspicious TLD (.${tld}), commonly used for phishing domains` };
    }

    return { flagged: false, reason: "" };
}

function checkHTTPSUsage(url: string): { flagged: boolean; reason: string } {
    const urlLower = url.toLowerCase();
    if (!urlLower.startsWith("https://")) {
        if (urlLower.startsWith("http://")) {
            return { flagged: true, reason: "URL uses HTTP instead of HTTPS (no encryption)" };
        }
        return { flagged: true, reason: "URL lacks HTTPS protocol (no secure connection)" };
    }
    return { flagged: false, reason: "" };
}

function checkAtSymbolInURL(url: string): { flagged: boolean; reason: string } {
    if (url.includes("@")) {
        const parts = url.split("@");
        return {
            flagged: true,
            reason: `URL contains @ symbol (credential injection risk). Text before @: "${parts[0]}", actual domain: "${parts[1]}"`,
        };
    }
    return { flagged: false, reason: "" };
}

function checkFaviconMismatch(url: string, expectedFaviconBrand?: string): { flagged: boolean; reason: string } {
    const domain = extractDomain(url).toLowerCase();
    for (const [brand] of Object.entries(BRAND_FAVICONS)) {
        const isBrandDomain = domain.includes(brand);
        if (!isBrandDomain && expectedFaviconBrand) {
            if (expectedFaviconBrand.toLowerCase().includes(brand)) {
                return { flagged: true, reason: `Favicon mismatch: Link text suggests "${brand}" but domain is "${domain}"` };
            }
        }
    }
    return { flagged: false, reason: "" };
}

// ─── Single-link analysis ─────────────────────────────────────────────────────

/**
 * Runs 8 URL-based checks on a single link href.
 * score is the raw flag count (0–8); verdict is derived from it.
 */
export function analyzeLink(link: Link): HeuristicResult {
    const findings: string[] = [];
    let suspicionScore = 0;

    const checks = [
        checkExcessiveLength(link.href),
        checkInsufficientLength(link.href),
        checkIPAddressLink(link.href),
        checkHTTPSUsage(link.href),
        checkAtSymbolInURL(link.href),
        checkZeroDayDomain(link.href),
        checkFaviconMismatch(link.href, link.text),
    ];

    for (const check of checks) {
        if (check.flagged) {
            findings.push(`⚠️ ${check.reason}`);
            suspicionScore++;
        }
    }

    // Typosquatting check can produce multiple reasons but counts as one flag
    const typosquatCheck = checkTyposquattingAndHomoglyphs(link.href);
    if (typosquatCheck.flagged) {
        for (const reason of typosquatCheck.reasons) {
            findings.push(`⚠️ ${reason}`);
        }
        suspicionScore++;
    }

    // Safety score: 10 = no flags, 0 = all 8 flags fired.
    const score = 10 - Math.round((suspicionScore / 8) * 10);
    let verdict: Verdict;
    if (suspicionScore === 0) {
        verdict = "safe";
    } else if (suspicionScore <= 4) {
        verdict = "uncertain";
    } else {
        verdict = "scam";
    }

    return {
        score,
        verdict,
        explanation: `Link analysis: ${findings.length} suspicious characteristics detected.`,
        findings,
        source: "url",
    };
}

// ─── Page-level link analysis ─────────────────────────────────────────────────

/**
 * Analyses all links on the page against two passes:
 *   (A) Mismatched link detection (visible domain claim ≠ href destination)
 *   (B) Per-link URL heuristics (requires 3+ flags per link to avoid false positives
 *       from weak signals like HTTP-only links)
 *
 * currentUrl is needed to filter out same-site navigation from mismatch detection.
 */
export function analyzeLinks(links: Link[], currentUrl: string): HeuristicResult {
    if (links.length === 0) {
        return {
            score: 10,
            verdict: "safe",
            explanation: "No links found on page.",
            findings: [],
            source: "url",
        };
    }

    const findings: string[] = [];
    let score = 0;

    // (A) Mismatched link detection
    // Detects links where visible text claims domain X but href goes to domain Y.
    // e.g. <a href="http://evil.xyz">www.paypal.com</a>
    const currentBase = extractBaseDomain(parseHostname(currentUrl));
    let mismatchCount = 0;

    for (const link of links) {
        const claimed = extractClaimedDomain(link.text);
        if (!claimed) continue;

        const hrefHostname = parseHostname(link.href);
        if (!hrefHostname) continue;

        // Same-site navigation is not a mismatch
        if (extractBaseDomain(hrefHostname) === currentBase) continue;

        if (extractBaseDomain(claimed) !== extractBaseDomain(hrefHostname)) {
            mismatchCount++;
            findings.push(
                `Mismatched link: visible text claims '${claimed}' but href goes to '${hrefHostname}'`
            );
        }
    }
    // Each mismatched link adds 4 points, capped at 8
    score += Math.min(mismatchCount * 4, 8);

    // (B) Per-link URL heuristics
    // Require 3+ threat flags per link — keeps false positives low. Since analyzeLink
    // now returns a safety score, "3+ flags" maps to safety score ≤ 6.
    const linkResults = links.map(analyzeLink);
    const seriouslyFlagged = linkResults.filter(r => r.score <= 6);

    // Each seriously flagged link adds 1 point, capped at 3
    score += Math.min(seriouslyFlagged.length, 3);

    // Report per-link findings only for links with 2+ flags (safety score ≤ 7).
    for (const [i, result] of linkResults.entries()) {
        if (result.score <= 7) {
            const label = links[i].text || links[i].href;
            findings.push(`Link (${label}): ${result.findings.join("; ")}`);
        }
    }

    // Invert to a safety score: 10 = no threats, 0 = maximum threat.
    const safetyScore = 10 - Math.min(score, 10);
    const { verdict } = toVerdict(safetyScore);

    return {
        score: safetyScore,
        verdict,
        explanation: `Analysed ${links.length} links — ${mismatchCount} mismatched, ${seriouslyFlagged.length} suspicious.`,
        findings,
        source: "url",
    };
}
