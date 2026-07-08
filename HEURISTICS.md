# Beacon — Heuristics System

```mermaid
flowchart TD
    PAGE(["User visits page"])

    PAGE --> EXTRACT

    subgraph EXTRACT ["content.ts — extractPageData()"]
        direction LR
        EX1["url · title · metaDescription · textContent"]
        EX2["links · forms · buttonText · badgeAltTexts · overlayText"]
    end

    EXTRACT --> AGG

    AGG{"Trusted aggregator?\ngoogle · bing · yahoo · wikipedia\nreddit · youtube · twitter · x"}

    AGG -- "Yes  AND  urlScore = 10" --> BYPASS
    AGG -- No --> RUN

    BYPASS(["contentResult = score 10\nlinkResult   = score 10"])

    RUN --> URL_MOD & CONTENT_MOD & LINK_MOD

    subgraph URL_MOD ["urlHeuristics.ts — analyzeUrl()"]
        direction TB
        T1["── Tier 1 : standalone ──"]
        T1 --> U1["isdomainip\nraw IP address instead of domain · wt 10"]
        T1 --> U2["hasobfuscation\n@ credential injection or encoded hostname · wt 8"]
        T1 --> U3["urlLengthHard\npath-only length > 144 chars · wt 7"]
        T1 --> U4["brandSubdomainSpoofing\npaypal/amazon/google/… in non-brand hostname · wt 5"]
        T1 --> U5["freeHostingFinancialSubdomain\nbank/wallet/greendot/… in vercel/netlify/github.io/… · wt 5"]
        T1 --> U6["suspiciousTld\n.icu .tk .ml .ga .cf .gq .cfd .cyou · wt 5"]
        T2["── Tier 2 : compound (needs 2 weak signals) ──"]
        T2 --> U7["urlLengthWithComplexity\nURL > 75 chars  AND  hyphens ≥ 3  OR  path encoding ≥ 3 · wt 4"]
        T2 --> U8["gibberishDomainLabel\n4+ char label with zero vowels · wt 3"]
    end

    subgraph CONTENT_MOD ["contentHeuristics.ts — analyzeContent()"]
        direction TB
        C1["sparsityNoMeta\nbody < 200 chars  AND  no meta description · wt 3"]
        C2["scamPhrases in title\n'you have won' · 'act now' · 'your account has been suspended' · … · wt 3 each"]
        C3["scamPhrases in meta description · wt 3 each"]
        C4["scamPhrases in body text · wt 2 each"]
        C5["scamPhrases in overlay/modal · wt 3 each"]
        C6["suspiciousButtonText\n'Claim Now' · 'Access My Funds' · 'Unlock My Account' · … · wt 3 each"]
        C7["credentialFormCrossDomain\npassword form POSTs to a different domain · wt 6"]
        C8["fakeSecurityBadge\nNorton / McAfee / DigiCert img alt texts · wt 2"]
        C9["countdownUrgency\nclock pattern  +  expires/remaining/hurry · wt 2"]
    end

    subgraph LINK_MOD ["linkHeuristics.ts — analyzeLinks()"]
        direction TB
        L1["Pass A — mismatched link text\nvisible text claims domain X, href goes to Y · +4 per match, cap 8"]
        L2["Pass B — per-link URL checks\nIP · no HTTPS · @ symbol · excessive hyphens · rare TLD\ntyposquatting/homoglyphs · domain length\n+1 per seriously-flagged link, cap 3"]
    end

    BYPASS --> COMBINE
    URL_MOD --> COMBINE
    CONTENT_MOD --> COMBINE
    LINK_MOD --> COMBINE

    subgraph COMBINE ["content.ts — combineResults()"]
        direction TB
        CV1["Convert each module score to threat:  threat = 10 − score"]
        CV2["URL veto:\nif urlThreat = 0  →  discard content/link threats that are < 6\n(prevents false positives from aggregated ad copy on clean URLs)"]
        CV3["combinedThreat = min(urlThreat + contentThreat + linkThreat, 10)"]
        CV4["finalScore = 10 − combinedThreat"]
        CV5["≥ 7 → safe     4–6 → uncertain     < 4 → scam"]
        CV1 --> CV2 --> CV3 --> CV4 --> CV5
    end

    COMBINE --> RESULT(["HeuristicResult\nscore · verdict · findings · source"])

    RESULT --> BG[("background.js\nstoreResult")]
    BG --> POPUP

    RESULT --> GATE{"score < 7?\n(uncertain or scam)"}
    GATE -- "Yes" --> LLM
    GATE -- "No (safe)" --> POPUP

    subgraph LLM ["Tier 2 — LLM Analysis"]
        direction TB
        L_API["FastAPI backend"]
        L_MODEL["Gemini 2.5 Flash Lite"]
        L_INV["risk_score 0–10  →  invert  →  10 − risk_score"]
        L_API --> L_MODEL --> L_INV
    end

    LLM --> POPUP

    POPUP(["Popup\nGauge score · Verdict badge · Findings list"])
```

---

## Score scale

| Score | Verdict | Meaning |
|---|---|---|
| 7 – 10 | **Safe** | No significant indicators |
| 4 – 6 | **Uncertain** | Multiple signals — verify independently |
| 0 – 3 | **Scam** | Strong phishing indicators — avoid |

## URL rule weights reference

| Rule | Tier | Weight | Fires when |
|---|---|---|---|
| `isdomainip` | 1 | 10 | Hostname is a raw IPv4 address |
| `hasobfuscation` | 1 | 8 | `@` credential injection or encoded hostname |
| `urlLengthHard` | 1 | 7 | Path (no query string) > 144 chars |
| `brandSubdomainSpoofing` | 1 | 5 | Known brand in non-brand hostname |
| `freeHostingFinancialSubdomain` | 1 | 5 | Financial keyword in Vercel/Netlify/etc. subdomain |
| `suspiciousTld` | 1 | 5 | `.icu` `.tk` `.ml` `.ga` `.cf` `.gq` `.cfd` `.cyou` |
| `urlLengthWithComplexity` | 2 | 4 | URL > 75 chars AND (hyphens ≥ 3 OR path encoding ≥ 3) |
| `gibberishDomainLabel` | 2 | 3 | 4+ char label with zero vowels |

## Content rule weights reference

| Rule | Weight | Fires when |
|---|---|---|
| `sparsityNoMeta` | 3 | Body < 200 chars AND no meta description |
| Scam phrase — title/meta | 3 each | Phrase from list appears in title or meta |
| Scam phrase — body/overlay | 2–3 each | Phrase appears in body text or open modal |
| `suspiciousButtonText` | 3 each | CTA button contains urgency/harvest phrase |
| `credentialFormCrossDomain` | 6 | Password form POSTs to different domain |
| `fakeSecurityBadge` | 2 | Norton/McAfee/DigiCert/etc. in img alt |
| `countdownUrgency` | 2 | Clock pattern + urgency word in body |
