/**
 * contentHeuristics.ts
 *
 * Rule-based phishing detection engine for Beacon.
 * All new rules are derived from EDA on the PhiUSIIL dataset (~235K URLs,
 * 57% legitimate / 43% phishing). See HEURISTICS.md for the full rationale.
 *
 * Architecture — two tiers of rules, plus legacy phrase and link checks:
 *
 *   Tier 1  Standalone rules with near-zero false positive rates. Each rule
 *           individually justifies a high-risk verdict. These map to binary
 *           features that showed 100% phishing rates in the EDA.
 *
 *   Tier 2  Compound rules that require multiple weak signals to fire together.
 *           Individual signals here have acceptable false positive rates, but
 *           pairing them raises precision significantly (Brian Ha's insight:
 *           "a URL being long alone is a red herring — combine it with another
 *           weak feature like special characters and it becomes meaningful").
 *
 *   Supplementary  Scam phrase detection and mismatched link analysis retained
 *           from the original implementation. These are content-based signals
 *           that complement the structural EDA-backed rules above.
 *
 * Scoring (0–10, capped):
 *   0–3  → Safe
 *   4–6  → Uncertain
 *   7+   → Likely Scam
 */

import type { HeuristicResult, ExtractedPageData } from "../types/heuristics";

// ─── EDA-derived thresholds ──────────────────────────────────────────────────

/**
 * 99th percentile of the phishing URL length distribution in PhiUSIIL.
 * Every URL above this threshold was phishing in the dataset (100% precision).
 * Distribution: legitimate median=26, max=57; phishing median=34, 75th%=48.
 */
const URL_LENGTH_HARD = 144;

/**
 * Softer length threshold (above the phishing 75th percentile).
 * Used only in compound rules — too many false positives alone because some
 * legitimate URLs (e.g. long product pages) exceed this value.
 */
const URL_LENGTH_SOFT = 75;

/**
 * Minimum count of %XX percent-encoded sequences in a URL to contribute
 * to the compound length + complexity rule.
 */
const PERCENT_ENCODED_MIN = 3;

/**
 * Minimum hyphen count in the hostname to signal subdomain-stacking attacks
 * (e.g. secure-paypal-login-verify.attacker.com → 3 hyphens).
 * Legitimate hostnames rarely exceed 2 hyphens.
 */
const HOST_HYPHENS_MIN = 3;

/**
 * Body text length (chars) below which a page is "structurally sparse".
 * Proxy for largestlinelength and lineofcode — the two dominant EDA features
 * (separation score 1.464, ~3× stronger than URL features). Phishing pages
 * are thin templates; legitimate pages are content-rich.
 */
const SPARSE_TEXT_MAX = 200;

// ─── Internal types ──────────────────────────────────────────────────────────

interface RuleResult {
    triggered: boolean;
    /** Human-readable description added to findings when this rule fires. */
    finding: string;
}

interface Rule {
    id: string;
    tier: 1 | 2;
    /** Points added to the score when this rule triggers. */
    weight: number;
    /** One-line rationale linking the rule back to the EDA finding. */
    description: string;
    check: (data: ExtractedPageData) => RuleResult;
}

// ─── URL helpers ─────────────────────────────────────────────────────────────

/** Returns the lowercase hostname from a URL string, or "" on parse failure. */
function parseHostname(url: string): string {
    try {
        return new URL(url).hostname.toLowerCase();
    } catch {
        return "";
    }
}

/** Returns the base domain (last two labels) from a full hostname. */
function extractBaseDomain(hostname: string): string {
    const parts = hostname.split(".");
    return parts.length >= 2 ? parts.slice(-2).join(".") : hostname;
}

// ─── Tier 1 rules ────────────────────────────────────────────────────────────
// Standalone — each fires independently and carries enough weight on its own.

const TIER_1_RULES: Rule[] = [
    {
        id: "isdomainip",
        tier: 1,
        weight: 10,
        description:
            "URL uses a raw IP address instead of a domain name. " +
            "EDA: isdomainip had a 100% phishing rate — no legitimate site in the " +
            "dataset used an IP-based URL.",
        check(data) {
            const hostname = parseHostname(data.url);
            // Bare IPv4 — legitimate domains never look like this
            const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
            return {
                triggered: isIp,
                finding: `URL uses a raw IP address (${hostname}) instead of a domain name`,
            };
        },
    },

    {
        id: "hasobfuscation",
        tier: 1,
        weight: 8,
        description:
            "URL contains credential-injection '@' or percent-encoded characters in " +
            "the hostname. EDA: hasobfuscation had a 100% phishing rate. " +
            "e.g. http://paypal.com@evil.com — browser resolves evil.com but URL " +
            "looks like paypal.com to a casual reader.",
        check(data) {
            try {
                const parsed = new URL(data.url);

                // Credentials before the host: http://paypal.com@evil.com
                if (parsed.username !== "" || parsed.password !== "") {
                    return {
                        triggered: true,
                        finding: `URL contains '@' credential-injection — actual host is '${parsed.hostname}'`,
                    };
                }

                // Percent-encoded characters inside the hostname itself
                if (/%[0-9a-fA-F]{2}/.test(parsed.hostname)) {
                    return {
                        triggered: true,
                        finding: `URL hostname contains percent-encoded characters (obfuscation): ${parsed.hostname}`,
                    };
                }
            } catch {
                // Unparseable URLs are handled by urlLengthHard or left for other rules
            }
            return { triggered: false, finding: "" };
        },
    },

    {
        id: "urlLengthHard",
        tier: 1,
        weight: 7,
        description:
            `URL exceeds ${URL_LENGTH_HARD} characters (99th percentile of the phishing ` +
            "distribution). EDA Finding 3.9: all URLs above this threshold were phishing " +
            "(100% precision). Attackers pad URLs with random subdomains, obfuscation " +
            "strings, and path segments to disguise the destination.",
        check(data) {
            return {
                triggered: data.url.length > URL_LENGTH_HARD,
                finding: `URL is ${data.url.length} chars, exceeding the ${URL_LENGTH_HARD}-char phishing threshold`,
            };
        },
    },
];

// ─── Tier 2 rules (compound) ─────────────────────────────────────────────────
// Each requires two independent weak signals simultaneously.
// Neither signal alone is precise enough; together they raise confidence.

const TIER_2_RULES: Rule[] = [
    {
        id: "urlLengthWithComplexity",
        tier: 2,
        weight: 4,
        description:
            `URL exceeds ${URL_LENGTH_SOFT} chars AND shows hostname complexity ` +
            `(≥${PERCENT_ENCODED_MIN} percent-encoded sequences OR ≥${HOST_HYPHENS_MIN} hyphens in hostname). ` +
            "EDA: URL length is a secondary signal; noofotherspecialcharsinurl and " +
            "noofsubdomain are individually weak. Paired, they capture attack patterns " +
            "like 'https://secure-paypal-login-verify.evil.com/...'.",
        check(data) {
            // Gate on soft length first — skip the rest for short URLs
            if (data.url.length <= URL_LENGTH_SOFT) {
                return { triggered: false, finding: "" };
            }
            const hostname = parseHostname(data.url);
            // Scope percent-encoding check to hostname + path only, not the query string.
            // Encoded query parameters (?q=hello%20world) are normal on legitimate sites
            // and would cause false positives if counted here.
            const urlWithoutQuery = data.url.split("?")[0];
            const percentEncoded = (urlWithoutQuery.match(/%[0-9a-fA-F]{2}/g) ?? []).length;
            const hostHyphens = (hostname.match(/-/g) ?? []).length;

            const complexityTriggered =
                percentEncoded >= PERCENT_ENCODED_MIN || hostHyphens >= HOST_HYPHENS_MIN;

            return {
                triggered: complexityTriggered,
                finding:
                    `Long URL (${data.url.length} chars) with suspicious structure — ` +
                    `${percentEncoded} %-encoded sequences, ${hostHyphens} hyphens in hostname`,
            };
        },
    },

    {
        id: "sparsityNoMeta",
        tier: 2,
        weight: 3,
        description:
            "Page has very little body text AND no meta description. " +
            "Proxy for largestlinelength + lineofcode (EDA Finding 3.8, separation " +
            "score 1.464 — the two strongest discriminating features). Phishing pages " +
            "are thin templates: low line count, sparse HTML, no trust signals. " +
            "hasdescription correlates with legitimacy at r=0.69 in the EDA.",
        check(data) {
            const textLength = data.textContent.trim().length;
            const isSparse = textLength < SPARSE_TEXT_MAX;
            const noMeta = data.metaDescription.trim().length === 0;
            return {
                triggered: isSparse && noMeta,
                finding:
                    `Sparse page: ${textLength} chars of text and no meta description ` +
                    `(phishing pages are thin templates; legitimate pages are content-rich)`,
            };
        },
    },
];

// ─── Supplementary: scam phrase detection ────────────────────────────────────
// Retained from original implementation. Content-based signal that complements
// the structural EDA rules above. Phrases in title/meta score higher because
// attackers deliberately craft these fields to deceive users.

const SCAM_PHRASES: readonly string[] = [
    "you have won",
    "you've won",
    "congratulations, you won",
    "claim your prize",
    "click here to claim",
    "urgent action required",
    "act now",
    "limited time offer",
    "exclusive deal",
    "send a wire transfer",
    "you are the lucky winner",
    "congratulations you are our winner",
];

/** Returns all SCAM_PHRASES found in the given text (case-insensitive). */
function findScamPhrases(text: string): string[] {
    const lower = text.toLowerCase();
    return SCAM_PHRASES.filter(phrase => lower.includes(phrase));
}

// ─── Supplementary: mismatched link detection ────────────────────────────────
// Retained from original implementation. Detects links where visible text
// claims domain X but the href actually goes to domain Y.
// e.g. <a href="http://evil.xyz">www.paypal.com</a>
//
// Separate from the Rule interface because it produces one finding per link
// rather than a single boolean result.

/**
 * Tries to parse a domain claim out of link visible text.
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

// ─── Score → Verdict ─────────────────────────────────────────────────────────

function toVerdict(score: number): {
    verdict: HeuristicResult["verdict"];
    explanation: string;
} {
    if (score >= 7) {
        return {
            verdict: "Likely Scam",
            explanation:
                "Strong phishing indicators detected. Avoid entering credentials or interacting with this page.",
        };
    }
    if (score >= 4) {
        return {
            verdict: "Uncertain",
            explanation:
                "Multiple signals detected. Exercise caution and verify the site independently.",
        };
    }
    return {
        verdict: "Safe",
        explanation: "No significant phishing indicators detected.",
    };
}

// ─── Main export ─────────────────────────────────────────────────────────────

/**
 * Analyzes extracted page data and returns a phishing risk score (0–10).
 *
 * Execution order:
 *   1. Tier 1 rules (standalone, high-precision EDA signals)
 *   2. Tier 2 rules (compound EDA signals)
 *   3. Scam phrase detection (supplementary content signal)
 *   4. Mismatched link detection (supplementary structural signal)
 */
export function analyzeContent(pageData: ExtractedPageData): HeuristicResult {
    const findings: string[] = [];
    let score = 0;

    // 1 & 2 — Tier 1 then Tier 2 rule checks
    for (const rule of [...TIER_1_RULES, ...TIER_2_RULES]) {
        const result = rule.check(pageData);
        if (result.triggered) {
            score += rule.weight;
            findings.push(`[Tier ${rule.tier}] ${result.finding}`);
        }
    }

    // 3 — Scam phrase detection
    // Title and meta matches weighted at 3 (prominent, attacker-crafted fields).
    // Body text matches weighted at 2 (lower prominence, easier to include accidentally).
    const titleMatches = findScamPhrases(pageData.title);
    const metaMatches = findScamPhrases(pageData.metaDescription);
    const bodyMatches = findScamPhrases(pageData.textContent);

    for (const phrase of titleMatches) {
        score += 3;
        findings.push(`Scam phrase in title: "${phrase}"`);
    }
    for (const phrase of metaMatches) {
        score += 3;
        findings.push(`Scam phrase in meta description: "${phrase}"`);
    }
    for (const phrase of bodyMatches) {
        score += 2;
        findings.push(`Scam phrase in page text: "${phrase}"`);
    }

    // 4 — Mismatched link detection
    const currentBase = extractBaseDomain(parseHostname(pageData.url));
    let mismatchCount = 0;

    for (const link of pageData.links) {
        const claimed = extractClaimedDomain(link.text);
        if (!claimed) continue;

        const hrefHostname = parseHostname(link.href);
        if (!hrefHostname) continue;

        // Skip same-site navigation
        if (extractBaseDomain(hrefHostname) === currentBase) continue;

        if (extractBaseDomain(claimed) !== extractBaseDomain(hrefHostname)) {
            mismatchCount++;
            findings.push(
                `Mismatched link: visible text claims '${claimed}' but href goes to '${hrefHostname}'`
            );
        }
    }
    // Each mismatched link adds 4 points, capped at 8 total contribution
    score += Math.min(mismatchCount * 4, 8);

    score = Math.min(score, 10);

    const { verdict, explanation } = toVerdict(score);
    return { score, verdict, explanation, findings, source: "content" };
}
