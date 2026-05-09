// Manual test suite for contentHeuristics.ts
// Run by compiling with the extension source. Not executed by the extension runtime.
//
// Coverage:
//   Tier 1 rules   — isdomainip, hasobfuscation, urlLengthHard
//   Tier 2 rules   — urlLengthWithComplexity, sparsityNoMeta
//   Supplementary  — scam phrase detection, mismatched link detection
//   Edge cases     — empty page, same-site links, generic link text

import { analyzeContent } from "./contentHeuristics";
import type { ExtractedPageData } from "../types/heuristics";

function runTest(name: string, pageData: ExtractedPageData): void {
    console.log("=================================================================");
    console.log(`TEST: ${name}`);
    console.log("-----------------------------------------------------------------");
    const result = analyzeContent(pageData);
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

// Safe, content-rich legitimate page.
// No rules should fire. Expected: score 0, "Safe".
runTest("Safe page — Wikipedia article", {
    url: "https://en.wikipedia.org/wiki/Moon",
    title: "Moon - Wikipedia",
    metaDescription: "The Moon is Earth's only natural satellite.",
    textContent:
        "The Moon is Earth's only natural satellite. It is the fifth largest " +
        "satellite in the Solar System and the largest relative to its parent planet.",
    links: [],
});

// ─── Tier 1: isdomainip ───────────────────────────────────────────────────────

// URL uses a raw IP address instead of a domain name.
// EDA: 100% phishing rate. Expected: score 10, "Likely Scam".
runTest("Tier 1 — IP address URL", {
    url: "http://192.168.1.105/login",
    title: "Login",
    metaDescription: "",
    textContent: "Enter your credentials below.",
    links: [],
});

// ─── Tier 1: hasobfuscation ──────────────────────────────────────────────────

// Credential-injection pattern: http://paypal.com@evil-phishing.xyz/login
// Browser resolves evil-phishing.xyz; text looks like paypal.com.
// EDA: 100% phishing rate. Expected: score 8, "Likely Scam".
runTest("Tier 1 — @ credential injection in URL", {
    url: "http://paypal.com@evil-phishing.xyz/login",
    title: "PayPal — Login",
    metaDescription: "Secure login to your PayPal account.",
    textContent: "Please enter your PayPal email and password to continue.",
    links: [],
});

// ─── Tier 1: urlLengthHard ───────────────────────────────────────────────────

// URL exceeds 144 chars (99th percentile of phishing distribution).
// EDA Finding 3.9: 100% phishing above this threshold.
// Expected: score 7, "Likely Scam".
runTest("Tier 1 — URL exceeds 144-char hard threshold", {
    url: "https://secure-login.paypal-accounts-verify.com/confirm/identity/step2?token=aB3xK9mNqR7vL2pW5yZ1cF4hJ8dU6tE0sG&session=mNqR7vL2pWxK9mN",
    title: "Verify Your Account",
    metaDescription: "Complete your account verification.",
    textContent: "Please verify your account details to continue.",
    links: [],
});

// ─── Tier 2: urlLengthWithComplexity ─────────────────────────────────────────

// URL over 75 chars with 3+ hyphens in hostname (subdomain stacking).
// Neither signal alone is reliable; together they indicate an attack URL.
// Expected: score 4, "Uncertain".
runTest("Tier 2 — Long URL with hyphen-stacked hostname", {
    url: "https://secure-paypal-login-verify.attacker-phishing.com/account/verify?session=abc123",
    title: "Account Verification",
    metaDescription: "Please verify your account.",
    textContent:
        "We noticed unusual activity on your account. " +
        "Please verify your identity to restore full access. " +
        "This process takes only a few minutes and helps keep your account secure.",
    links: [],
});

// URL over 75 chars with percent-encoded sequences in the PATH (≥3 %XX patterns).
// Encoding scoped to path/hostname — query string encoding is excluded to avoid
// false positives on legitimate search or redirect URLs.
// Expected: score 4, "Uncertain".
runTest("Tier 2 — Long URL with percent-encoded path obfuscation", {
    url: "https://example.com/%72%65%64%69%72%65%63%74/%74%6f/evil-destination/landing-page-login",
    title: "Redirecting...",
    metaDescription: "",
    textContent: "Please wait while you are redirected.",
    links: [],
});

// ─── Tier 2: sparsityNoMeta ──────────────────────────────────────────────────

// Very little body text AND no meta description.
// Proxy for low largestlinelength + lineofcode (dominant EDA features).
// Expected: score 3, "Safe" (single Tier 2 rule — needs another signal to reach Uncertain).
runTest("Tier 2 — Sparse page with no meta description", {
    url: "https://suspicious-login-page.com/",
    title: "Login",
    metaDescription: "",
    textContent: "Enter your details.",
    links: [],
});

// Sparse + no meta + one scam phrase — compound signals stack to Uncertain.
// Expected: score 5+, "Uncertain".
runTest("Tier 2 — Sparse page + scam phrase in title", {
    url: "https://totally-not-a-scam.com/",
    title: "Urgent action required",
    metaDescription: "",
    textContent: "Click the link below to secure your account.",
    links: [],
});

// ─── Supplementary: scam phrase detection ────────────────────────────────────

// Multiple scam phrases across title, meta, and body.
// Expected: high score, "Likely Scam".
runTest("Supplementary — Multiple scam phrases across fields", {
    url: "http://free-prize-winner.xyz/claim",
    title: "Congratulations you are our winner!",
    metaDescription: "You have won a brand new iPhone! Claim your prize today!",
    textContent:
        "Click here to claim your free gift! Act now, this is a limited time offer. " +
        "You have won a $1000 gift card!",
    links: [],
});

// One phrase in the title — tests the 3-point title weighting.
// Expected: score 3, "Safe" (just below Uncertain threshold).
runTest("Supplementary — Single scam phrase in title only", {
    url: "https://example.com",
    title: "You have won a prize",
    metaDescription: "A normal description of a normal page.",
    textContent: "This is the body of a normal page with nothing suspicious.",
    links: [],
});

// ─── Supplementary: mismatched link detection ─────────────────────────────────

// Link text claims apple.com but href goes to a phishing domain.
// Expected: score 4, "Uncertain".
runTest("Supplementary — Mismatched link claiming apple.com", {
    url: "https://newsletter.example.com",
    title: "Newsletter",
    metaDescription: "Our weekly updates.",
    textContent: "Thank you for reading. Please visit our sponsors.",
    links: [
        { text: "https://www.apple.com", href: "https://evil-phishing.xyz/login" },
    ],
});

// Same-site link — should NOT be flagged as a mismatch.
// Expected: score 0, "Safe".
runTest("Supplementary — Same-site subdomain link (no flag)", {
    url: "https://blog.example.com/posts/1",
    title: "My Blog Post",
    metaDescription: "A blog post about programming.",
    textContent: "Welcome to my blog. I write about software and cats.",
    links: [
        { text: "www.example.com", href: "https://shop.example.com/products" },
    ],
});

// Generic link text with no domain claim — should NOT trigger mismatch check.
// Expected: score 0, "Safe".
runTest("Supplementary — Generic link text (no domain claim, no flag)", {
    url: "https://news.example.com/article",
    title: "Breaking News",
    metaDescription: "Today's top headlines.",
    textContent: "In today's news, we cover several important events.",
    links: [
        { text: "Click here to read more", href: "https://different-site.com/story" },
        { text: "About us", href: "https://different-site.com/about" },
    ],
});

// ─── Edge cases ───────────────────────────────────────────────────────────────

// All fields empty — function should not throw.
// Expected: score 0, "Safe".
runTest("Edge case — Completely empty page", {
    url: "",
    title: "",
    metaDescription: "",
    textContent: "",
    links: [],
});

// Combination: IP URL + scam phrase — score should cap at 10.
// Expected: score 10, "Likely Scam".
runTest("Edge case — IP URL combined with scam phrases (score cap)", {
    url: "http://192.0.2.1/win",
    title: "You have won",
    metaDescription: "Claim your prize now.",
    textContent: "Act now. Send a wire transfer to claim your reward.",
    links: [],
});
