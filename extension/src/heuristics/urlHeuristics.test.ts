// Manual test suite for urlHeuristics.ts
// Covers Tier 1 (isdomainip, hasobfuscation, urlLengthHard, brandSubdomainSpoofing)
// and Tier 2 (urlLengthWithComplexity) rules.

import { analyzeUrl } from "./urlHeuristics";

function runTest(name: string, url: string): void {
    console.log("=================================================================");
    console.log(`TEST: ${name}`);
    console.log(`URL:  ${url}`);
    console.log("-----------------------------------------------------------------");
    const result = analyzeUrl(url);
    console.log(`Score:       ${result.score}`);
    console.log(`Verdict:     ${result.verdict}`);
    console.log(`Explanation: ${result.explanation}`);
    if (result.findings.length === 0) {
        console.log("Findings:    (none)");
    } else {
        console.log("Findings:");
        for (const finding of result.findings) {
            console.log(`  - ${finding}`);
        }
    }
    console.log("");
}

// ─── Baseline ────────────────────────────────────────────────────────────────

// Clean HTTPS domain — no rules should fire.
// Expected: score 10, "safe".
runTest("Safe — Clean HTTPS domain", "https://en.wikipedia.org/wiki/Moon");

// ─── Tier 1: isdomainip ───────────────────────────────────────────────────────

// URL uses a raw IPv4 address. EDA: 100% phishing rate.
// Expected: score 0, "scam".
runTest("Tier 1 — IP address URL", "http://192.168.1.105/login");

// ─── Tier 1: hasobfuscation ──────────────────────────────────────────────────

// Credential-injection: http://paypal.com@evil-phishing.xyz/login
// Browser resolves evil-phishing.xyz; URL visually resembles paypal.com.
// Expected: score 2, "scam" (hasobfuscation weight 8 → threat 8 → safety 2).
runTest("Tier 1 — @ credential injection", "http://paypal.com@evil-phishing.xyz/login");

// ─── Tier 1: urlLengthHard ───────────────────────────────────────────────────

// URL path exceeds 144 chars (query string excluded).
// This URL has a 145+ char path before the '?'.
// Expected: score 3 (threat 7 → safety 3), "scam".
runTest(
    "Tier 1 — URL path exceeds 144-char hard threshold",
    "https://secure-login-verify-account-update-identity-confirmation-portal.paypal-accounts.malicious-domain.xyz/confirm/identity/step2/processing/final"
);

// Legitimate SaaS deep-link — long path because of job title + ATS segments,
// but domain is clean (.com, zero hyphens). urlLengthHard should NOT fire
// because the domain carries no suspicion alongside the path length.
// Expected: score 10, "safe".
runTest(
    "Tier 1 — Long ATS/job-board URL with clean domain (no false positive)",
    "https://pwc.wd3.myworkdayjobs.com/en-US/US_Experienced_Careers/job/NY-New-York/AI-Engineer---Data-Scientist--AI-Senior-Associate_723603WD-2/apply/applyManually"
);

// Google search URL — long only because of query params, path is short.
// The urlLengthHard fix (path-only) means this should NOT trigger.
// Expected: score 10, "safe".
runTest(
    "Tier 1 — Google search URL with long query string (no false positive)",
    "https://www.google.com/search?q=phishing+detection+heuristics&source=hp&ei=abc123xyz&iflsig=AK50M_UAAAAA&oq=phishing+detection&gs_lcp=Cgdnd3Mtd2l6EAMyBQgAEIAE"
);

// Amazon product URL — long path but legitimate domain and structure.
// Expected: score 10, "safe".
runTest(
    "Tier 1 — Amazon product URL with long path (no false positive)",
    "https://www.amazon.com/Amazon-Basics-Screen-Cleaning-Microfiber/dp/B01MR3TKAG/ref=sr_1_3?crid=2X&keywords=screen+cleaner&qid=1234567890"
);

// ─── Tier 1: brandSubdomainSpoofing ──────────────────────────────────────────

// "paypal" appears as a subdomain on a non-PayPal domain.
// Expected: score 5 (threat 5 → safety 5), "uncertain".
runTest(
    "Tier 1 — Brand spoofing: paypal in subdomain of non-PayPal domain",
    "https://paypal.verify-accounts.malicious.xyz/login"
);

// "paypal" embedded in a hyphenated segment of a non-PayPal hostname.
// Expected: score 5, "uncertain".
runTest(
    "Tier 1 — Brand spoofing: secure-paypal-login.com",
    "https://secure-paypal-login.attacker.com/account/verify"
);

// Legitimate PayPal subdomain — should NOT trigger.
// Expected: score 10, "safe".
runTest(
    "Tier 1 — Brand spoofing negative: legitimate www.paypal.com",
    "https://www.paypal.com/signin"
);

// Legitimate Google subdomain (mail.google.com) — should NOT trigger.
// Expected: score 10, "safe".
runTest(
    "Tier 1 — Brand spoofing negative: legitimate mail.google.com",
    "https://mail.google.com/mail/u/0/#inbox"
);

// "googlemaps" — "google" is part of a compound word, not a standalone segment.
// Should NOT trigger (word-boundary matching prevents this false positive).
// Expected: score 10, "safe".
runTest(
    "Tier 1 — Brand spoofing negative: googlemaps (compound word, no flag)",
    "https://googlemaps.example.com/embed"
);

// Brand spoofing + credential injection — both fire, score compounds.
// Expected: score 0, "scam" (threat 8 + 5 = 13, capped at 10 → safety 0).
runTest(
    "Tier 1 — Brand spoofing + @ injection (compound)",
    "http://paypal.com@secure-paypal-update.malicious.xyz/login"
);

// ─── Tier 2: urlLengthWithComplexity ─────────────────────────────────────────

// URL with 3+ hyphens in hostname AND brand name in non-brand domain.
// Both brandSubdomainSpoofing (threat 5) and urlLengthWithComplexity (threat 4) fire.
// Expected: score 1 (threat 9 → safety 1), "scam".
runTest(
    "Tier 2 — Long URL with hyphen-stacked hostname + brand spoofing",
    "https://secure-paypal-login-verify.attacker-phishing.com/account/verify?session=abc123"
);

// URL over 75 chars with percent-encoded sequences in the PATH (3+ %XX).
// Query string encoding is excluded to avoid false positives on legitimate search URLs.
// Expected: score 6, "uncertain".
runTest(
    "Tier 2 — Long URL with percent-encoded path obfuscation",
    "https://example.com/%72%65%64%69%72%65%63%74/%74%6f/evil-destination/landing-page-login"
);

// Legitimate long search URL — query string encoding should NOT trigger.
// Expected: score 10, "safe".
runTest(
    "Tier 2 — Legitimate search URL with encoded query params (no flag)",
    "https://www.google.com/search?q=hello%20world%20foo%20bar%20baz&source=hp&ei=abc123"
);

// ─── Edge cases ───────────────────────────────────────────────────────────────

// Empty string — should not throw.
// Expected: score 10, "safe".
runTest("Edge case — Empty URL", "");

// IP URL — score should cap at 10 even if other rules also fire.
// Expected: score 0, "scam".
runTest(
    "Edge case — IP URL score cap",
    "http://192.0.2.1/very-long-path-that-exceeds-the-soft-threshold-and-adds-more-characters-here"
);
