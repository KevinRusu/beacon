# Eval Dataset — Data Selection Criteria

This document explains why each URL category was chosen, what signals we expect
each entry to exercise, and how to expand the dataset with more real-world data.

---

## Selection Goals

The dataset is designed to test four things:

1. **Detection rate** — Does the engine catch known phishing patterns?
2. **False positive rate** — Does it incorrectly flag legitimate sites?
3. **Compound rule precision** — Do Tier 2 rules fire appropriately, not excessively?
4. **Edge case handling** — Do legitimate long URLs, encoded query strings, and banking
   sites survive without being flagged?

---

## URL Categories

### Legitimate — Core

Well-known, high-traffic sites with clean URLs. These should produce score 10
(safe) across all three modules. If any of these are flagged, it indicates a
false positive problem in the engine.

Chosen criteria:
- HTTPS
- Registered domain (no IP)
- Short, clean hostname (no hyphens, no encoding)
- High Tranco/Alexa rank

Sites included: Google, Wikipedia, GitHub, Apple, Microsoft, Amazon, PayPal (legit),
Chase, Bank of America, IRS, Canada.ca, BBC, NYT, Reddit, Stack Overflow, LinkedIn,
YouTube, Netflix, Harvard, MIT, Zoom, Dropbox, Mozilla, USPS, Twitter.

---

### Legitimate — Edge Cases

Sites or URLs that could plausibly trigger false positives. Included to ensure
the engine doesn't over-flag. If these are incorrectly flagged, document the
specific rule that fired and consider adjusting the threshold or compound requirement.

| URL | Risk | Expected outcome |
|-----|------|-----------------|
| Long Amazon product URL | `urlLengthWithComplexity` (encoded query params) | **Safe** — query string encoding is excluded by design |
| Long Amazon search URL | Same as above | **Safe** |
| Long Google search URL | Same as above | **Safe** |
| Google accounts sign-in | Long path + `signin` keyword | **Safe** |
| MDN developer docs | Long URL path | **Safe** |
| Wells Fargo with path | Contains `mortgage` + path | **Safe** |
| Gmail | Subdomain of google.com | **Safe** |

The Amazon and Google long URL cases are critical. They contain many `%XX`
sequences in the query string. Our `urlLengthWithComplexity` rule intentionally
excludes query strings from the percent-encoding count — these cases verify
that exclusion is working.

---

### Phishing — IP-Based (`isdomainip`, Tier 1, weight 10)

**EDA basis:** `isdomainip` had a 100% phishing rate in PhiUSIIL. No legitimate
public-facing site in the dataset used a bare IPv4 as its hostname.

IP ranges used in the test data:
- `192.0.2.x` — RFC 5737 documentation range (safe for examples, won't route)
- `203.0.113.x` — RFC 5737 documentation range
- `198.51.100.x` — RFC 5737 documentation range
- `192.168.x.x` — RFC 1918 private range (never a public site)
- `10.0.0.x` — RFC 1918 private range

All IP-based phishing examples should produce score 0 (scam), verdict "scam".

---

### Phishing — Credential Injection (`hasobfuscation`, Tier 1, weight 8)

**EDA basis:** `hasobfuscation` had a 100% phishing rate. The `@` syntax is a
legacy URL credential format (`user:pass@host`). When used with a brand domain
before the `@`, it visually deceives users while the browser resolves the domain
*after* the `@` as the actual destination.

Example: `http://paypal.com@192.0.2.1/login`
- Visible to user: looks like paypal.com
- Actual destination: 192.0.2.1

Three examples covering: PayPal, Apple, Microsoft. All should score near 0.

---

### Phishing — URL Length > 144 chars (`urlLengthHard`, Tier 1, weight 7)

**EDA basis:** EDA Finding 3.9 — 99th percentile of phishing URL length = 144 chars.
Every URL above this threshold was phishing in the PhiUSIIL dataset (100% precision).

Phishing pages pad URLs with:
- Random token parameters (`?token=aB3xK9...`)
- Multiple redirect hops (`&redirect=...&session=...`)
- Long subdomains

Two examples with distinct patterns. Both should score 0 (scam).

---

### Phishing — Hyphen Stacking + Length (`urlLengthWithComplexity`, Tier 2, weight 4)

**Brian Ha's compound signal insight:** "A URL being long alone is a red herring —
combine it with another weak feature like special characters and it becomes
meaningful."

Pattern: `secure-paypal-login-verify.account-update.xyz` — attackers stack hyphens
in subdomains to make URLs look official while evading simple string matching.

Rule triggers when: URL > 75 chars AND hostname has ≥ 3 hyphens.

Four examples covering: PayPal, Amazon, Microsoft, Apple impersonation.
Expected verdict: **uncertain** (Tier 2 alone scores 4 = lower boundary of uncertain).

---

### Phishing — Percent-Encoded Path (`urlLengthWithComplexity`, Tier 2, weight 4)

Rule triggers when: URL > 75 chars AND ≥ 3 `%XX` sequences in hostname/path
(query string excluded).

Used to hide the actual path destination:
`/%70%61%79%70%61%6c` decodes to `/paypal`

Two examples with 6+ encoded sequences in the path.
Expected verdict: **uncertain** (Tier 2 compound rule).

---

### Phishing — Suspicious TLDs (linkHeuristics `checkZeroDayDomain`)

Rare/free TLDs historically abused for phishing:
- `.tk` (Tokelau) — historically offered free domains
- `.ml` (Mali) — free registrations widely abused
- `.cf` (Central African Republic) — free, heavily phishing-associated
- `.gq`, `.ga`, `.xyz`, `.top` also in scope

These fire the `checkZeroDayDomain` check in `linkHeuristics.ts` when a link
on a page points to one of these TLDs. The page-level verdict depends on whether
other signals also fire.

---

### Phishing — Typosquatting / Homoglyphs (linkHeuristics)

| Pattern | Substitution |
|---------|-------------|
| `paypa1.com` | `1` → `l` |
| `micros0ft.com` | `0` → `o` |
| `g00gle.com` | `00` → `oo` |
| `faceb00k.com` | `00` → `oo` |

These fire `checkTyposquattingAndHomoglyphs` in `linkHeuristics.ts`. They are
detected when a link on a page points to one of these domains, not necessarily
when the page URL itself uses them.

---

## How to Add More URLs

### From PhishTank (recommended for phishing)

1. Download the verified phishing feed: https://data.phishtank.com/data/online-valid.csv.gz
2. Filter to `verified = true` and `online = true`
3. Sample 30–50 diverse entries (mix of categories: banking, social, crypto, etc.)
4. Add to `urls.csv` with `source = phishtank` and `label = phishing`
5. Run the notebook immediately — PhishTank URLs go offline within days

```bash
# Download and sample PhishTank data
curl -L "https://data.phishtank.com/data/online-valid.csv.gz" | gunzip | \
  python3 -c "import sys,csv,random; rows=list(csv.DictReader(sys.stdin)); \
  sample=random.sample([r for r in rows if r['verified']=='yes'], 30); \
  [print(r['url']+',phishing,phishtank-live') for r in sample]"
```

### From OpenPhish

https://openphish.com/feed.txt — plain-text feed of active phishing URLs.
Refresh daily before running the notebook.

### From Tranco (for legitimate)

https://tranco-list.eu — ranked list of popular domains. Sample from rank 100–10000
to get well-known but not-top-1 sites (these have more content variance).

---

## Evaluation Limitations

| Limitation | Impact | Mitigation |
|------------|--------|-----------|
| Phishing pages go offline quickly | Phase 2 (content eval) can't fetch them | Run notebook within 24h of downloading PhishTank data; use Phase 1 for static URL analysis |
| Dataset is small (~60 curated + PhishTank sample) | Metrics have high variance | Report confidence intervals; note sample size |
| URL-pattern phishing examples are illustrative | Not guaranteed to be real live phishing pages | Label source as `manual`; use only for URL heuristics testing |
| No multilingual scam phrases | Content heuristics will miss non-English scams | Add phrases in future iterations |
| Content heuristics depend on page layout | Phishing pages may use unusual HTML structures | Note fetch failures in Phase 2 output |
