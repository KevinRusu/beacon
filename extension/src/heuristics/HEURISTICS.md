# Beacon Heuristics Engine

Rule-based phishing detection for the Beacon browser extension.
All rules are derived from EDA on the **PhiUSIIL dataset** (~235,795 URLs; 57% legitimate, 43% phishing).

---

## Architecture

The engine runs four detection passes in order and sums their scores into a final risk score (0–10).

```
ExtractedPageData
        │
        ├─ Tier 1 rules       (standalone, near-zero false positives)
        ├─ Tier 2 rules       (compound — require 2 weak signals together)
        ├─ Scam phrase scan   (supplementary content signal)
        └─ Mismatched links   (supplementary structural signal)
                │
                ▼
        score 0–10  →  Verdict
```

### Score → Verdict

| Score | Verdict      |
|-------|--------------|
| 0–3   | Safe         |
| 4–6   | Uncertain    |
| 7–10  | Likely Scam  |

---

## Tier 1 Rules — Standalone

These rules fire independently. Each one alone provides enough evidence for a high-risk verdict.
They map to binary features with **100% phishing rates** in the EDA.

### `isdomainip` — Weight: 10

**What it checks:** Whether the URL's hostname is a raw IPv4 address (e.g. `http://192.168.1.1/login`).

**EDA basis:** The `isdomainip` feature had a **100% phishing rate** in PhiUSIIL. No legitimate site in the dataset used an IP-based URL. Attackers use IPs to avoid domain registration trails.

**False positive risk:** Near-zero. No legitimate public-facing site uses a bare IP.

---

### `hasobfuscation` — Weight: 8

**What it checks:** Two sub-patterns, either triggers the rule:
1. **Credential injection** — `@` before the hostname (e.g. `http://paypal.com@evil.com`). The browser resolves `evil.com` as the destination, but the URL visually resembles `paypal.com`.
2. **Encoded hostname** — percent-encoded characters (`%XX`) inside the hostname itself (e.g. `%70%61%79%70%61%6c.com`).

**EDA basis:** The `hasobfuscation` feature had a **100% phishing rate**. Any URL-level character obfuscation was exclusively associated with phishing in the dataset.

**False positive risk:** Near-zero. Percent-encoding in hostnames is invalid per RFC 3986; `@` in authority is a legacy credential syntax never used by legitimate sites.

---

### `urlLengthHard` — Weight: 7

**What it checks:** Whether the full URL exceeds **144 characters**.

**EDA basis:** EDA Finding 3.9 — `urllength` at the 99th percentile was **144 chars**. Every URL above this threshold was phishing in the dataset (**100% precision**). Attackers pad URLs with random subdomains, obfuscation strings, and path segments to disguise the destination.

Distribution context:
| Class       | Median | 75th% | 99th% |
|-------------|--------|-------|-------|
| Legitimate  | 26     | 29    | —     |
| Phishing    | 34     | 48    | 144   |

**False positive risk:** Low. At 144 chars, almost all false positives are extremely unusual legitimate URLs. Validate against production data before tightening.

---

## Tier 2 Rules — Compound

These rules require **two independent weak signals** to fire simultaneously. 

### `urlLengthWithComplexity` — Weight: 4

**What it checks:** URL exceeds **75 chars** AND at least one of:

- `≥ 3` percent-encoded sequences (`%XX`) in the URL hostname/path (query string excluded — encoded query params are normal on legitimate sites), OR
- `≥ 3` hyphens in the hostname (subdomain-stacking attack)

**EDA basis:** URL length is a secondary signal (family separation score 0.535 vs HTML's 1.464). `noofotherspecialcharsinurl` and `noofsubdomain` are individually weak. Paired with length they capture attack patterns like:
```
https://secure-paypal-login-verify.attacker-site.com/account/confirm?token=...
         ↑ 3 hyphens, long URL
```

**False positive risk:** Moderate for length alone; low for the compound. Hyphens in hostnames are uncommon beyond 2 in legitimate domains.

---

### `sparsityNoMeta` — Weight: 3

**What it checks:** Page body text is **< 200 chars** AND meta description is empty.

**EDA basis:** EDA Finding 3.8 — `largestlinelength` and `lineofcode` are the **two strongest discriminating features** (combined separation score 1.464, ~3× stronger than all URL features combined). Phishing pages are thin templates with minimal HTML; legitimate pages are content-rich.

Since the extension does not have direct access to raw HTML line counts, this rule uses extracted text length as a proxy. `hasdescription` (meta description presence) correlates with legitimacy at **r = 0.69** in the EDA.

**False positive risk:** Moderate alone (some minimal legitimate pages exist). The compound requirement (both conditions) significantly reduces false positives.

---

## Supplementary Signals

These were in the previous implementations and are retained as complementary signals alongside the EDA-backed rules.

### Scam Phrase Detection

Scans the page title, meta description, and body text for known scam phrases.

**Weights:**
- Title match: **+3** per phrase (high-prominence field, intentionally crafted)
- Meta match: **+3** per phrase
- Body match: **+2** per phrase

**Phrase list:** See `SCAM_PHRASES` in `contentHeuristics.ts`.

---

### Mismatched Link Detection

Detects links where the visible anchor text claims domain X but the `href` resolves to domain Y.

**Example:** `<a href="https://evil-phish.xyz/login">www.paypal.com</a>`

**Weight:** **+4** per mismatched link, capped at **+8** total.

Same-site navigation and generic link text (no domain claim) are excluded to avoid false positives.

---

## Feature Family Separation Scores (EDA)

| Feature Family   | Separation Score | Notes                                      |
|------------------|------------------|--------------------------------------------|
| HTML features    | **1.464**        | Dominant signal; 3× stronger than URL      |
| URL features     | 0.535            | Secondary but meaningful                   |
| Other (links)    | 0.137            | Weak standalone                            |
| Security (HTTPS) | **0.086**        | Nearly useless — phishing sites use HTTPS too |

**Key takeaway:** HTTPS presence is not a meaningful signal and is intentionally excluded from the engine.

---

## Adding a New Rule

1. Decide on tier (standalone precision → Tier 1; requires pairing → Tier 2).
2. Add an entry to `TIER_1_RULES` or `TIER_2_RULES` in `contentHeuristics.ts`.
3. Set `weight` proportional to the EDA separation score or phishing rate of the underlying feature.
4. Add a corresponding test case in `contentHeuristics.test.ts`.
5. Update this document with the EDA basis and false positive risk.

---

## Key EDA References

- **Finding 3.3** — Phishing URLs are systematically longer than legitimate ones.
- **Finding 3.7** — Only `isdomainip` and `hasobfuscation` are near-perfect binary phishing indicators (100% rate).
- **Finding 3.8** — After outlier removal, phishing pages cluster in the low `largestlinelength` + low `lineofcode` zone.
- **Finding 3.9** — URLs above the 99th percentile on key features are 100% phishing; supports a tiered rule → later ML/LLM-based approach.

Full EDA: `extension/src/heuristics/beacon_heuristics_EDA.ipynb`
