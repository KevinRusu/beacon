/**
 * urlHeuristics.ts
 *
 * Analyses the URL of the current page (the string itself — not the page
 * content or any link destinations) and returns a HeuristicResult.
 *
 * All rules are derived from EDA on the PhiUSIIL dataset (~235K URLs,
 * 57% legitimate / 43% phishing). See HEURISTICS.md for full rationale.
 *
 * Scoring (0–10, capped):
 *   0–3  → safe
 *   4–6  → uncertain
 *   7+   → scam
 */

import type { HeuristicResult } from "../types/heuristics";
import { toVerdict } from "./contentHeuristics";

// ─── EDA-derived thresholds ──────────────────────────────────────────────────

/**
 * Path+hostname length above which a URL is flagged as suspiciously long.
 * Applied to the URL *without* the query string — legitimate sites (Google,
 * Amazon) have long query strings but short paths; phishing URLs pack
 * complexity into the hostname and path segments.
 */
const URL_LENGTH_HARD = 144;

/** Softer threshold (phishing 75th percentile) — used only in compound rules. */
const URL_LENGTH_SOFT = 75;

/** Min percent-encoded sequences in hostname+path to flag obfuscation. */
const PERCENT_ENCODED_MIN = 3;

/** Min hyphens in hostname to flag subdomain-stacking attacks. */
const HOST_HYPHENS_MIN = 3;

// ─── Brand data ───────────────────────────────────────────────────────────────
// Maps brand names to their known legitimate base domains.
// Used to detect subdomain spoofing: "paypal.verify.malicious.xyz" has
// "paypal" in the hostname but the registered domain is not paypal.com.

const BRAND_LEGITIMATE_DOMAINS: Record<string, string[]> = {
    paypal:        ["paypal.com"],
    amazon:        ["amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.fr", "amazon.es", "amazon.in", "amazon.com.au"],
    apple:         ["apple.com", "icloud.com"],
    microsoft:     ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "azure.com"],
    google:        ["google.com", "gmail.com", "googlemail.com", "googleapis.com", "gstatic.com"],
    facebook:      ["facebook.com", "fb.com", "meta.com"],
    instagram:     ["instagram.com"],
    netflix:       ["netflix.com"],
    twitter:       ["twitter.com", "x.com"],
    github:        ["github.com", "githubusercontent.com", "githubassets.com"],
    linkedin:      ["linkedin.com"],
    chase:         ["chase.com"],
    bankofamerica: ["bankofamerica.com"],
    wellsfargo:    ["wellsfargo.com"],
    citibank:      ["citi.com", "citibank.com"],
    ebay:          ["ebay.com"],
    dropbox:       ["dropbox.com"],
    zoom:          ["zoom.us"],
    coinbase:      ["coinbase.com"],
    binance:       ["binance.com"],
    usps:          ["usps.com"],
    fedex:         ["fedex.com"],
    ups:           ["ups.com"],
};

// ─── High-risk TLDs ──────────────────────────────────────────────────────────
// These TLDs have near-exclusive abuse rates in public threat intelligence feeds.
// Freenom TLDs (.tk, .ml, .ga, .cf, .gq) are offered free of charge, which
// drives almost all real-world usage toward spam, phishing, and malware.
// Newer generic TLDs (.icu, .cfd, .cyou) show similarly extreme abuse rates.

const HIGH_RISK_TLDS: string[] = [
    "tk", "ml", "ga", "cf", "gq",  // Freenom — free registration, near-exclusively abused
    "icu",                           // New gTLD — consistently top-ranked in phishing feeds
    "cfd",                           // New gTLD — heavily used for trading/CFD fraud
    "cyou",                          // New gTLD — high phishing rate in threat intel data
];

// ─── Free hosting platform detection ─────────────────────────────────────────
// Phishing campaigns increasingly deploy credential-harvesting pages on
// legitimate cloud platforms (Vercel, Netlify, GitHub Pages) to bypass
// URL-reputation blocklists. The platform TLD looks clean, but the subdomain
// chosen by the attacker carries the impersonation signal.

const FREE_HOSTING_PLATFORMS: string[] = [
    "vercel.app",
    "netlify.app",
    "github.io",
    "pages.dev",       // Cloudflare Pages
    "web.app",         // Firebase Hosting
    "firebaseapp.com", // Firebase Hosting
    "glitch.me",
    "surge.sh",
    "render.com",
    "onrender.com",
    "fly.dev",
    "railway.app",
    "replit.dev",
    "repl.co",
];

// Keywords that have no legitimate business in a free-hosting subdomain unless
// the page is impersonating a financial institution or payment service.
const FINANCIAL_SUBDOMAIN_KEYWORDS: string[] = [
    "bank", "banking",
    "wallet",
    "loan", "lending",
    "wire",
    "debit", "deposit",
    "mortgage",
    // Financial brands not already covered by BRAND_LEGITIMATE_DOMAINS
    "greendot", "netspend", "chime", "cashapp", "venmo", "zelle",
    "robinhood", "webull", "sofi", "nerdwallet",
];

// ─── Internal types ──────────────────────────────────────────────────────────

interface RuleResult {
    triggered: boolean;
    finding: string;
}

interface Rule {
    id: string;
    tier: 1 | 2;
    weight: number;
    check: (url: string) => RuleResult;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function parseHostname(url: string): string {
    try {
        return new URL(url).hostname.toLowerCase();
    } catch {
        return "";
    }
}

/** Returns the URL stripped of its query string and fragment. */
function pathOnly(url: string): string {
    return url.split("?")[0].split("#")[0];
}

// ─── Tier 1 rules — standalone ───────────────────────────────────────────────
// Each fires independently. Maps to a binary feature with high precision
// in the EDA — very few (if any) legitimate sites match these patterns.

const TIER_1_RULES: Rule[] = [
    {
        id: "isdomainip",
        tier: 1,
        weight: 10,
        check(url) {
            const hostname = parseHostname(url);
            // Bare IPv4 — no legitimate public-facing site uses one
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
        check(url) {
            try {
                const parsed = new URL(url);

                // Credential injection: http://paypal.com@evil.com — browser resolves evil.com
                if (parsed.username !== "" || parsed.password !== "") {
                    return {
                        triggered: true,
                        finding: `URL contains '@' credential-injection — actual host is '${parsed.hostname}'`,
                    };
                }

                // Percent-encoded characters in the hostname itself (invalid per RFC 3986)
                if (/%[0-9a-fA-F]{2}/.test(parsed.hostname)) {
                    return {
                        triggered: true,
                        finding: `URL hostname contains percent-encoded characters (obfuscation): ${parsed.hostname}`,
                    };
                }
            } catch {
                // Unparseable URLs fall through to other rules
            }
            return { triggered: false, finding: "" };
        },
    },

    {
        id: "urlLengthHard",
        tier: 1,
        weight: 7,
        check(url) {
            // Exclude query string — legitimate sites (Google, Amazon) have long query
            // strings but short paths. Phishing pads the hostname and path segments.
            const path = pathOnly(url);
            if (path.length <= URL_LENGTH_HARD) return { triggered: false, finding: "" };

            // A long path on a clean domain is normal for SaaS platforms — job boards
            // (Workday, Greenhouse), CMS deep links, and e-commerce all produce paths
            // well over 144 chars. Require the hostname to also look suspicious before
            // treating path length as a standalone phishing signal.
            const hostname = parseHostname(url);
            const tld = hostname.split(".").pop()?.toLowerCase() ?? "";
            const hostHyphens = (hostname.match(/-/g) ?? []).length;
            const domainAlsoSuspicious =
                HIGH_RISK_TLDS.includes(tld) ||  // .icu .tk .ml etc.
                hostHyphens >= 2;                 // heavily hyphenated hostname

            if (!domainAlsoSuspicious) return { triggered: false, finding: "" };

            return {
                triggered: true,
                finding:
                    `URL path is ${path.length} chars (query string excluded), ` +
                    `exceeding the ${URL_LENGTH_HARD}-char phishing threshold`,
            };
        },
    },

    {
        id: "brandSubdomainSpoofing",
        tier: 1,
        weight: 5,
        check(url) {
            const hostname = parseHostname(url);
            if (!hostname) return { triggered: false, finding: "" };

            for (const [brand, legitimateDomains] of Object.entries(BRAND_LEGITIMATE_DOMAINS)) {
                // Brand must appear as a standalone segment (surrounded by dots, hyphens,
                // or string boundaries) — prevents "googlemaps.com" from matching "google".
                const segmentPattern = new RegExp(`(?:^|[.-])${brand}(?:[.-]|$)`, "i");
                if (!segmentPattern.test(hostname)) continue;

                // If the hostname IS one of the brand's legitimate domains (or a subdomain
                // of one), this is expected navigation — not spoofing.
                const isLegit = legitimateDomains.some(
                    d => hostname === d || hostname.endsWith(`.${d}`)
                );
                if (isLegit) continue;

                // Brand name appears in a non-brand domain — subdomain spoofing.
                return {
                    triggered: true,
                    finding:
                        `Brand spoofing: "${brand}" appears in hostname "${hostname}" ` +
                        `but this is not a known ${brand} domain`,
                };
            }

            return { triggered: false, finding: "" };
        },
    },

    {
        id: "freeHostingFinancialSubdomain",
        tier: 1,
        weight: 5,
        check(url) {
            const hostname = parseHostname(url);
            if (!hostname) return { triggered: false, finding: "" };

            const platform = FREE_HOSTING_PLATFORMS.find(
                p => hostname === p || hostname.endsWith(`.${p}`)
            );
            if (!platform) return { triggered: false, finding: "" };

            // Isolate the subdomain portion the attacker controls.
            const subdomain = hostname.slice(0, hostname.length - platform.length - 1).toLowerCase();
            if (!subdomain) return { triggered: false, finding: "" };

            const keyword = FINANCIAL_SUBDOMAIN_KEYWORDS.find(k => subdomain.includes(k));
            if (!keyword) return { triggered: false, finding: "" };

            return {
                triggered: true,
                finding:
                    `Free hosting platform (${platform}) with financial keyword "${keyword}" ` +
                    `in subdomain "${subdomain}" — common pattern for financial credential phishing`,
            };
        },
    },

    {
        id: "suspiciousTld",
        tier: 1,
        weight: 5,
        check(url) {
            const hostname = parseHostname(url);
            if (!hostname) return { triggered: false, finding: "" };
            const tld = hostname.split(".").pop()?.toLowerCase() ?? "";
            if (!HIGH_RISK_TLDS.includes(tld)) return { triggered: false, finding: "" };
            return {
                triggered: true,
                finding: `Domain uses high-risk TLD (.${tld}) with documented near-exclusive phishing/spam abuse`,
            };
        },
    },
];

// ─── Tier 2 rules — compound ─────────────────────────────────────────────────
// Require two independent weak signals simultaneously. Neither signal alone
// is precise enough; together they raise confidence significantly.
// (Brian Ha's insight: "a URL being long alone is a red herring — combine it
//  with another weak feature and it becomes meaningful".)

const TIER_2_RULES: Rule[] = [
    {
        id: "urlLengthWithComplexity",
        tier: 2,
        weight: 4,
        check(url) {
            // Use full URL length for the entry threshold — long query strings are fine
            // but they still signal "this is a complex URL worth examining further."
            // The structural checks (hyphens, path encoding) then filter out legitimate
            // Google/Amazon URLs whose complexity is only in the query string.
            if (url.length <= URL_LENGTH_SOFT) {
                return { triggered: false, finding: "" };
            }
            const hostname = parseHostname(url);
            // Exclude query string from percent-encoding count — encoded params
            // (?q=hello%20world) are normal on legitimate sites.
            const urlWithoutQuery = pathOnly(url);
            const percentEncoded = (urlWithoutQuery.match(/%[0-9a-fA-F]{2}/g) ?? []).length;
            const hostHyphens = (hostname.match(/-/g) ?? []).length;

            const complexityTriggered =
                percentEncoded >= PERCENT_ENCODED_MIN || hostHyphens >= HOST_HYPHENS_MIN;

            return {
                triggered: complexityTriggered,
                finding:
                    `Long URL (${url.length} chars) with suspicious structure — ` +
                    `${percentEncoded} %-encoded sequences in path, ${hostHyphens} hyphens in hostname`,
            };
        },
    },

    {
        id: "gibberishDomainLabel",
        tier: 2,
        weight: 3,
        check(url) {
            const hostname = parseHostname(url);
            if (!hostname) return { triggered: false, finding: "" };
            // Check the registered second-level label (e.g. "nvkcy" in "nvkcy.icu").
            const parts = hostname.split(".");
            const label = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
            // Exclude very short labels (≤ 3 chars) — those are typically acronyms
            // (cnn, nfl, bbc) and have zero false-positive risk anyway.
            if (label.length <= 3) return { triggered: false, finding: "" };
            // Count real vowels (a e i o u). "y" is treated as a consonant here.
            const vowels = (label.match(/[aeiou]/gi) ?? []).length;
            if (vowels > 0) return { triggered: false, finding: "" };
            return {
                triggered: true,
                finding:
                    `Domain label "${label}" has no vowels — consistent with a randomly generated phishing domain`,
            };
        },
    },
];

// ─── Main export ─────────────────────────────────────────────────────────────

export function analyzeUrl(url: string): HeuristicResult {
    const findings: string[] = [];
    let score = 0;

    for (const rule of [...TIER_1_RULES, ...TIER_2_RULES]) {
        const result = rule.check(url);
        if (result.triggered) {
            score += rule.weight;
            findings.push(`[Tier ${rule.tier}] ${result.finding}`);
        }
    }

    // Invert to a safety score: 10 = no threats detected, 0 = maximum threat.
    score = 10 - Math.min(score, 10);
    const { verdict, explanation } = toVerdict(score);
    return { score, verdict, explanation, findings, source: "url" };
}
