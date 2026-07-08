// Manual test suite for contentHeuristics.ts
// Covers CONTENT-only rules: sparsity + meta description, scam phrase detection.
// URL rules are tested in urlHeuristics.test.ts.
// Link rules are tested in linkHeuristics.test.ts.

import { analyzeContent } from "./contentHeuristics";
import type { ExtractedPageData } from "../types/heuristics";

// Default values for the DOM-extraction fields added in the second iteration.
// Existing tests only cover text/phrase rules, so these are always empty here.
const EMPTY_DOM: Pick<ExtractedPageData, "forms" | "buttonText" | "badgeAltTexts" | "overlayText"> = {
    forms: [],
    buttonText: "",
    badgeAltTexts: [],
    overlayText: "",
};

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

// Content-rich legitimate page. No rules should fire.
// Expected: score 10, "safe".
runTest("Safe page — Wikipedia article", {
    ...EMPTY_DOM,
    url: "https://en.wikipedia.org/wiki/Moon",
    title: "Moon - Wikipedia",
    metaDescription: "The Moon is Earth's only natural satellite.",
    textContent:
        "The Moon is Earth's only natural satellite. It is the fifth largest " +
        "satellite in the Solar System and the largest relative to its parent planet.",
    links: [],
});

// ─── sparsityNoMeta ──────────────────────────────────────────────────────────

// Very little body text AND no meta description.
// Expected: score 7, "safe" (single content rule — needs another signal to reach uncertain).
runTest("sparsityNoMeta — Sparse page with no meta", {
    ...EMPTY_DOM,
    url: "https://suspicious-login-page.com/",
    title: "Login",
    metaDescription: "",
    textContent: "Enter your details.",
    links: [],
});

// Sparse + no meta + one scam phrase in title — compound content signals stack.
// Expected: score 4 or lower, "uncertain".
runTest("sparsityNoMeta + scam phrase in title", {
    ...EMPTY_DOM,
    url: "https://totally-not-a-scam.com/",
    title: "Urgent action required",
    metaDescription: "",
    textContent: "Click the link below to secure your account.",
    links: [],
});

// Page with meta description but sparse text — should NOT fire sparsityNoMeta
// (both conditions required). Expected: score 10, "safe".
runTest("sparsityNoMeta — Sparse text but has meta (no flag)", {
    ...EMPTY_DOM,
    url: "https://example.com/landing",
    title: "Welcome",
    metaDescription: "A short but descriptive page summary.",
    textContent: "Enter your details.",
    links: [],
});

// ─── Scam phrase detection ────────────────────────────────────────────────────

// Multiple scam phrases across title, meta, and body.
// Expected: score 0, "scam".
runTest("Scam phrases — Multiple phrases across all fields", {
    ...EMPTY_DOM,
    url: "https://free-prize-winner.xyz/claim",
    title: "Congratulations you are our winner!",
    metaDescription: "You have won a brand new iPhone! Claim your prize today!",
    textContent:
        "Click here to claim your free gift! Act now, this is a limited time offer. " +
        "You have won a $1000 gift card!",
    links: [],
});

// One phrase in title only — tests the 3-point title weighting.
// Expected: score 7, "safe".
runTest("Scam phrases — Single phrase in title only", {
    ...EMPTY_DOM,
    url: "https://example.com",
    title: "You have won a prize",
    metaDescription: "A normal description of a normal page.",
    textContent: "This is the body of a normal page with nothing suspicious.",
    links: [],
});

// One phrase in body only — tests the 2-point body weighting.
// Expected: score 8, "safe".
runTest("Scam phrases — Single phrase in body only", {
    ...EMPTY_DOM,
    url: "https://example.com/news",
    title: "Today's Top Stories",
    metaDescription: "The latest news and updates.",
    textContent: "Act now to take advantage of this article before it expires.",
    links: [],
});

// ─── New DOM-level rules ──────────────────────────────────────────────────────

// Cross-domain credential form — form POSTs password to attacker's domain.
// Expected: score 4, "uncertain" (credentialFormCrossDomain weight 6).
runTest("credentialFormCrossDomain — password form posts to evil.xyz", {
    ...EMPTY_DOM,
    url: "https://secure-paypal-update.com/login",
    title: "PayPal — Sign In",
    metaDescription: "",
    textContent: "Enter your PayPal credentials to continue.",
    links: [],
    forms: [{ action: "https://evil.xyz/collect", hasPasswordField: true }],
});

// Same-domain form — should NOT flag.
// Expected: score 10, "safe".
runTest("credentialFormCrossDomain — negative: form posts to same domain", {
    ...EMPTY_DOM,
    url: "https://mybank.com/login",
    title: "Login",
    metaDescription: "Secure login to your account.",
    textContent: "Enter your credentials.",
    links: [],
    forms: [{ action: "https://mybank.com/api/auth", hasPasswordField: true }],
});

// Suspicious CTA button text — button says "Claim Now" on a suspicious page.
// Expected: score 7, "safe" alone (weight 3), but stacks when URL is flagged.
runTest("suspiciousButtonText — 'claim now' on suspicious page", {
    ...EMPTY_DOM,
    url: "https://prize-claim.tk/",
    title: "You've been selected",
    metaDescription: "",
    textContent: "Press the button below to collect your reward.",
    links: [],
    buttonText: "Claim Now | Get My Prize",
});

// Countdown timer with urgency language.
// Expected: score 8, "safe" alone (weight 2), but stacks when URL is flagged.
runTest("countdownUrgency — timer with 'expires' in body text", {
    ...EMPTY_DOM,
    url: "https://offer.icu/deal",
    title: "Special Offer",
    metaDescription: "",
    textContent: "This offer expires in 05:00. Hurry — limited spots remaining!",
    links: [],
});

// ─── Edge cases ───────────────────────────────────────────────────────────────

// All fields empty — function should not throw.
// Expected: score 10, "safe".
runTest("Edge case — Completely empty page", {
    ...EMPTY_DOM,
    url: "",
    title: "",
    metaDescription: "",
    textContent: "",
    links: [],
});
