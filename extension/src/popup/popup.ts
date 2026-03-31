//(1) typescript interfaces for structured data
interface PageData {
  url: string;
  textContent: string;
}

interface WebsiteInfo {
  domainAge: string;
  country: string;
  registrar: string;
  popularity: string;
}

interface AnalysisResult {
  score: number;
  verdict: string;
  explanation: string;
  websiteInfo: WebsiteInfo;
}

//(2) grab references to HTML elements

const scanButton = document.getElementById("scan-button") as HTMLButtonElement;
const resultsDiv = document.getElementById("results") as HTMLDivElement;
const scoreCircle = document.getElementById("score-circle") as HTMLDivElement;
const scoreNumber = document.getElementById("score-number") as HTMLSpanElement;
const verdictText = document.getElementById("verdict-text") as HTMLParagraphElement;
const verdictUrl = document.getElementById("verdict-url") as HTMLParagraphElement;
const explanationText = document.getElementById("explanation-text") as HTMLParagraphElement;
const errorDiv = document.getElementById("error") as HTMLDivElement;
const errorMessage = document.getElementById("error-message") as HTMLParagraphElement;

//Website info elements
const infoAge = document.getElementById("info-age") as HTMLSpanElement;
const infoCountry = document.getElementById("info-country") as HTMLSpanElement;
const infoRegistrar = document.getElementById("info-registrar") as HTMLSpanElement;
const infoPopularity = document.getElementById("info-popularity") as HTMLSpanElement;

//(2.5) helper to extract domain from URL

function getDomain(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    return url;
  }
}

//(3) Mock Analysis function
//only temporary until we connect to backend API

function mockAnalyze(pageData: PageData): AnalysisResult {
  const url: string = pageData.url.toLowerCase();
  const domain: string = getDomain(pageData.url);

  // Known safe domains with their mock info
  const safeDomainsInfo: { [key: string]: WebsiteInfo } = {
    "google.com": {
      domainAge: "Created 27 years ago",
      country: "United States",
      registrar: "MarkMonitor Inc.",
      popularity: "Very High (Top 5 globally)"
    },
    "gmail.com": {
      domainAge: "Created 20 years ago",
      country: "United States",
      registrar: "MarkMonitor Inc.",
      popularity: "Very High (Top 10 globally)"
    },
    "youtube.com": {
      domainAge: "Created 21 years ago",
      country: "United States",
      registrar: "MarkMonitor Inc.",
      popularity: "Very High (Top 3 globally)"
    },
    "github.com": {
      domainAge: "Created 18 years ago",
      country: "United States",
      registrar: "MarkMonitor Inc.",
      popularity: "High (Top 100 globally)"
    },
    "wikipedia.org": {
      domainAge: "Created 25 years ago",
      country: "United States",
      registrar: "Gandi SAS",
      popularity: "Very High (Top 10 globally)"
    },
    "amazon.com": {
      domainAge: "Created 30 years ago",
      country: "United States",
      registrar: "MarkMonitor Inc.",
      popularity: "Very High (Top 15 globally)"
    },
    "apple.com": {
      domainAge: "Created 38 years ago",
      country: "United States",
      registrar: "CSC Corporate Domains",
      popularity: "Very High (Top 20 globally)"
    },
    "microsoft.com": {
      domainAge: "Created 33 years ago",
      country: "United States",
      registrar: "MarkMonitor Inc.",
      popularity: "Very High (Top 30 globally)"
    }
  };

  // Check if the domain matches any safe domain.
  // Object.keys() gives us an array of all the keys in our object
  // (the domain names). We use .find() to look for one that
  // appears in the URL. .find() returns the first match or
  // undefined if nothing matches.
  const matchedSafe: string | undefined = Object.keys(safeDomainsInfo).find(
    (safeDomain: string) =>
      domain === safeDomain || domain.endsWith("." + safeDomain)
  );

  if (matchedSafe) {
    return {
      score: 1,
      verdict: "Safe",
      explanation: "This is a well-known, trusted website. No signs of phishing or scam content detected.",
      websiteInfo: safeDomainsInfo[matchedSafe]
    };
  }

  // Check for suspicious URL patterns
  const suspiciousPatterns: string[] = [
    "free-money",
    "winner",
    "prize",
    "urgent",
    "verify-account",
    "login-secure",
    "bit.ly",
    "tinyurl"
  ];

  const isSuspicious: boolean = suspiciousPatterns.some(
    (pattern: string) => url.includes(pattern)
  );

  if (isSuspicious) {
    return {
      score: 8,
      verdict: "Likely Scam",
      explanation: "This URL contains patterns commonly used in phishing and scam websites. Do not enter any personal information.",
      websiteInfo: {
        domainAge: "Created less than 1 year ago",
        country: "Unknown",
        registrar: "NameCheap Inc.",
        popularity: "Very Low (Not ranked)"
      }
    };
  }

  //rest = medium score
  return {
    score: 4,
    verdict: "Suspicious",
    explanation: "This website could not be verified as safe. Be cautious and avoid entering personal or financial information.",
    websiteInfo: {
      domainAge: "Created 2 years ago",
      country: "Unknown",
      registrar: "GoDaddy",
      popularity: "Low"
    }
  };
}

//(4) Determine verdict level from score
// Returns "safe", "suspicious", or "scam" based on the score
//Using this to pick the right CSS color classes.
//0-3 = safe, 4-6 = suspicious, 7-10 = scam

function getVerdictLevel(score: number): string {
    if (score <= 3) {
        return "safe";
    } else if (score <= 6) {
        return "suspicious";
    } else {
        return "scam";
    }
}

//(5) Show Error msg

function showError(message: string): void {
    resultsDiv.classList.add("hidden");
    errorDiv.classList.remove("hidden");
    errorMessage.textContent = message;
}

//(6) Display Scan results
//takes an AnalysisResult and a URL, then updates all the
//HTML elements to show the score, verdict, and explanation with  correct colors.

function showResults(result: AnalysisResult, url: string): void {
    errorDiv.classList.add("hidden");
    resultsDiv.classList.remove("hidden");

    scoreNumber.textContent = result.score.toString(); // Update score number inside circle
    verdictText.textContent = result.verdict; // Update verdict text and URL
    const shortUrl: string = url.length > 50 //shortens URL 
    ? url.substring(0, 50) + "..."
    : url;
    verdictUrl.textContent = shortUrl;

    explanationText.textContent = result.explanation; // Update explanation text

    //update website info section
    infoAge.textContent = result.websiteInfo.domainAge;
    infoCountry.textContent = result.websiteInfo.country;
    infoRegistrar.textContent = result.websiteInfo.registrar;
    infoPopularity.textContent = result.websiteInfo.popularity;

    const level: string = getVerdictLevel(result.score);
    
    scoreCircle.classList.remove("score-safe", "score-suspicious", "score-scam"); // Remove old classes
    scoreCircle.classList.add("score-" + level);

    verdictText.classList.remove("verdict-safe", "verdict-suspicious", "verdict-scam"); // Remove old classes
    verdictText.classList.add("verdict-" + level);
}

//(7) Handle Button Click

scanButton.addEventListener("click", () => {
    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";

    chrome.tabs.query(
        { active: true, currentWindow: true },
        (tabs: chrome.tabs.Tab[]) => {
            
            const tab = tabs[0];
            if (!tab || tab.id === undefined) {
                showError("Could not find the current tab. Please try again.");
                scanButton.disabled = false;
                scanButton.textContent = "Check this page";
                return;
            }

            const tabId: number = tab.id;

            chrome.tabs.sendMessage(
                tab.id,
                { action: "scanPage" },
                (response: PageData) => {
                    
                    if (chrome.runtime.lastError) {
                        showError(
                            "Could not scan this page. Try refreshing first."
                        );
                    } else if (response) {
                        const result: AnalysisResult = mockAnalyze(response);
                        showResults(result, response.url);
                    } else {
                        showError("No response from the page.");
                    }
                    
                    scanButton.disabled = false;
                    scanButton.textContent = "Check this page";
                }
            );
        }
    );
});