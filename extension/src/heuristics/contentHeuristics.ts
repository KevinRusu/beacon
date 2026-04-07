//Content heuristics module

//analyzes content of page (text, links, title, etc)
//returns HeuristicResult showing how likely page is a scam

import type { HeuristicResult, ExtractedPageData } from "../types/heuristics";

//Scam phrase list

const SCAM_PHRASES:  readonly string[] = [
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

//Helper (scan piece of text for scam phrase)
//takes chunk of text and returns list of scam phrases found in it
//returns empty list if no phrases found

function findScamPhrases(text: string): string[] {
    const lowerText: string = text.toLowerCase();
    const matches: string[] = [];

    for (const phrase of SCAM_PHRASES) {
        if (lowerText.includes(phrase)) {
            matches.push(phrase);
        }
    }
    return matches;
}

// main analysis function
//takes extracted page data abd returns a HeuristicResult

export function analyzeContent(pageData: ExtractedPageData): HeuristicResult {
    const findings: string[] = [];
    //(1) scam phrases
    const titleMatches: string[] = findScamPhrases(pageData.title);
    const metaMatches: string[] = findScamPhrases(pageData.metaDescription);
    const textMatches: string[] = findScamPhrases(pageData.textContent);

    //add finding for each match, noting where it was found
    for (const phrase of titleMatches) {
        findings.push(`Scam phrase in title: '${phrase}'`);
    }
    for (const phrase of metaMatches) {
        findings.push(`Scam phrase in meta description: '${phrase}'`);
    }
    for (const phrase of textMatches) {
        findings.push(`Scam phrase in page text: '${phrase}'`);
    }

//Scoring
//combine all matches into single score
//the more matches found, the higher the score
//phrases in title or meta count more than in body

    let score: number = 0;
    score += titleMatches.length * 3;
    score += metaMatches.length * 3;
    score += textMatches.length * 2;

//cap score at 10
    if (score > 10) {
        score = 10; 
    }

//verdict + explanation
//convert numeric score into verdict and explanation
    let verdict: HeuristicResult["verdict"];
    let explanation: string;

    if (score === 0) {
        verdict = "Safe";
        explanation = "No scam phrases detected in content.";
    } else if (score <= 3) {
        verdict = "Safe";
        explanation = "Minor indicators of potential scam content.";
    } else if (score <= 6) {
        verdict = "Uncertain";
        explanation = "The page contains some phrases commonly associated with scams. Exercise caution.";
    } else {
        verdict = "Likely Scam";
        explanation = "Strong indicators of scam content detected. Avoid interacting with this page.";
    }

    return {
        score: score,
        verdict: verdict,
        explanation: explanation,
        findings: findings,
        source: "content"
    };
}