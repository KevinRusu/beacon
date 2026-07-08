import { useState, useEffect } from "react";
import {
  RadioTower,
  Sparkles,
  AlertTriangle,
  CheckCircle,
  Info,
  ShieldAlert,
  Power,
  BrainCircuit,
  Activity,
  AlertCircle,
} from "lucide-react";
import type { HeuristicResult, ExtractedPageData } from "../types/heuristics";
import type { AnalyzeResponse } from "../types/api";

const RESTRICTED_PROTOCOLS = new Set([
  "chrome:",
  "chrome-extension:",
  "edge:",
  "about:",
  "view-source:",
  "file:",
]);

function isRestrictedUrl(url: string): boolean {
  try {
    return RESTRICTED_PROTOCOLS.has(new URL(url).protocol);
  } catch {
    return false;
  }
}

function getDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

export default function App() {
  const [result, setResult] = useState<HeuristicResult | null>(null);
  const [pageData, setPageData] = useState<ExtractedPageData | null>(null);
  const [pageUrl, setPageUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [extensionEnabled, setExtensionEnabled] = useState(true);
  const [aiEnabled, setAiEnabled] = useState(true);
  const [llmResult, setLlmResult] = useState<AnalyzeResponse | null>(null);
  const [llmError, setLlmError] = useState<string | null>(null);

  useEffect(() => {
    // Load persisted enabled state from background before fetching result
    chrome.storage.local.get("aiEnabled", (stored) => {
      if (stored.aiEnabled !== undefined) setAiEnabled(stored.aiEnabled as boolean);
    });

    chrome.runtime.sendMessage({ action: "getEnabled" }, (resp: { enabled: boolean }) => {
      if (!chrome.runtime.lastError && resp?.enabled !== undefined) {
        setExtensionEnabled(resp.enabled);
      }

      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs[0];
        if (!tab?.id) {
          setError("Could not identify the current tab.");
          setIsLoading(false);
          return;
        }
        if (isRestrictedUrl(tab.url ?? "")) {
          setError("Beacon cannot analyse this page type.");
          setIsLoading(false);
          return;
        }
        chrome.runtime.sendMessage(
          { action: "getResult", tabId: tab.id },
          (response: { result?: HeuristicResult; pageData?: ExtractedPageData; error?: string }) => {
            if (chrome.runtime.lastError || response?.error || !response?.result) {
              setError("Page not yet analysed. Refresh the page and try again.");
            } else {
              setResult(response.result);
              setPageData(response.pageData ?? null);
              setPageUrl(response.pageData?.url ?? tab.url ?? "");
            }
            setIsLoading(false);
          }
        );
      });
    });
  }, []);

  const handleExtensionToggle = (enabled: boolean) => {
    setExtensionEnabled(enabled);
    chrome.runtime.sendMessage({ action: "setEnabled", enabled });
  };

  const handleAiToggle = (enabled: boolean) => {
    setAiEnabled(enabled);
    chrome.storage.local.set({ aiEnabled: enabled });
  };

  const handleCheckPage = async () => {
    if (!result || !pageData) return;
    setIsAnalyzing(true);
    setLlmError(null);
    try {
      const resp = await fetch(`${__API_BASE_URL__}/v1/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Beacon-Key": __BEACON_API_KEY__,
        },
        body: JSON.stringify({
          url: pageData.url,
          text: pageData.textContent.slice(0, 1500),
          heuristic_score: result.score,
          context: "page_body",
          title: pageData.title,
          meta_description: pageData.metaDescription,
          heuristic_verdict: result.verdict,
          heuristic_findings: result.findings,
        }),
      });
      if (!resp.ok) throw new Error(`${resp.status}`);
      const data: AnalyzeResponse = await resp.json();
      setLlmResult(data);
    } catch {
      setLlmError("AI check unavailable");
    } finally {
      setIsAnalyzing(false);
    }
  };

  // LLM returns a risk score (0=safe, 10=dangerous); invert to match heuristic safety scale (10=safe, 0=dangerous).
  const score = llmResult ? 10 - llmResult.risk_score : (result?.score ?? 0);
  const activeVerdict = llmResult?.label ?? result?.verdict;
  const isSafe = !result || activeVerdict === "safe";
  const isWarning = activeVerdict === "uncertain";
  const isDanger = activeVerdict === "scam";

  let statusColor = "text-green-600";
  let ringColor = "text-green-500";
  let statusText = "Safe";
  let StatusIcon = CheckCircle;
  let summaryBg = "bg-green-50 text-green-800 border-green-200";

  if (isWarning) {
    statusColor = "text-amber-500";
    ringColor = "text-amber-500";
    statusText = "Warning";
    StatusIcon = AlertTriangle;
    summaryBg = "bg-amber-50 text-amber-800 border-amber-200";
  } else if (isDanger) {
    statusColor = "text-red-600";
    ringColor = "text-red-500";
    statusText = "Dangerous";
    StatusIcon = ShieldAlert;
    summaryBg = "bg-red-50 text-red-800 border-red-200";
  }

  const summaryText =
    llmResult?.reason ??
    result?.explanation ??
    (isSafe ? "No significant phishing indicators detected. This page appears safe to browse." : "");

  // SVG circular gauge
  const radius = 32;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 10) * circumference;

  if (isLoading) {
    return (
      <div className="w-[400px] h-[200px] bg-[#f5f5f7] flex items-center justify-center font-sans">
        <div className="flex flex-col items-center gap-3 text-gray-500">
          <Activity className="w-7 h-7 animate-pulse text-blue-500" />
          <p className="text-sm font-medium">Checking page…</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="w-[400px] bg-[#f5f5f7] flex flex-col font-sans">
        {/* Header */}
        <div className="flex flex-col items-center pt-8 pb-5 px-6">
          <div className="flex items-center gap-2 mb-1 text-blue-900">
            <RadioTower className="w-8 h-8 text-blue-600" />
            <h1 className="text-3xl font-bold tracking-tight">Beacon</h1>
          </div>
          <p className="text-[15px] text-gray-500 font-medium">Scam Detection Tool</p>
        </div>
        <div className="px-5 pb-8">
          <div className="p-4 rounded-xl border border-red-200 bg-red-50 shadow-sm">
            <div className="flex items-start gap-3">
              <AlertCircle className="w-5 h-5 mt-0.5 flex-shrink-0 text-red-500" />
              <p className="text-[15px] leading-snug font-medium text-red-800">{error}</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="w-[400px] h-[600px] bg-[#f5f5f7] flex flex-col font-sans overflow-hidden text-gray-900">
      <div className="flex-1 overflow-y-auto">

        {/* Header */}
        <div className="flex flex-col items-center pt-8 pb-5 px-6">
          <div className="flex items-center gap-2 mb-1 text-blue-900">
            <RadioTower className="w-8 h-8 text-blue-600" />
            <h1 className="text-3xl font-bold tracking-tight">Beacon</h1>
          </div>
          <p className="text-[15px] text-gray-500 font-medium">Scam Detection Tool</p>
        </div>

        <div className="px-5 space-y-5 pb-8">

          {/* Action Button */}
          <div>
            <button
              onClick={handleCheckPage}
              disabled={isSafe || isAnalyzing || !extensionEnabled || !aiEnabled || !!llmResult}
              className={`w-full py-3.5 px-4 rounded-xl font-semibold text-[16px] shadow-sm flex justify-center items-center gap-2 transition-all ${
                isSafe || !extensionEnabled || !aiEnabled
                  ? "bg-gray-200 text-gray-400 cursor-not-allowed"
                  : "bg-blue-600 hover:bg-blue-700 text-white hover:shadow-md active:scale-[0.98]"
              }`}
            >
              {isAnalyzing ? (
                <>
                  <Activity className="w-5 h-5 animate-pulse" />
                  Analyzing page…
                </>
              ) : isSafe ? (
                <>
                  <CheckCircle className="w-5 h-5" />
                  Page is Safe — Check Not Needed
                </>
              ) : (
                <>
                  <Sparkles className="w-5 h-5" />
                  Check this page
                </>
              )}
            </button>
            {!isSafe && (
              <p className="text-center text-xs text-gray-500 mt-2 font-medium">
                Uses Advanced AI to scan for hidden threats
              </p>
            )}
          </div>

          {/* Score Card */}
          <div
            className={`bg-white rounded-2xl p-5 shadow-sm border border-gray-100 transition-opacity ${
              !extensionEnabled ? "opacity-50" : ""
            }`}
          >
            <div className="flex items-center gap-5">
              {/* Circular Gauge */}
              <div className="relative w-[84px] h-[84px] flex-shrink-0">
                <svg className="w-full h-full transform -rotate-90">
                  <circle
                    className="text-gray-100"
                    strokeWidth="8"
                    stroke="currentColor"
                    fill="transparent"
                    r={radius}
                    cx="42"
                    cy="42"
                  />
                  <circle
                    className={`${ringColor} transition-all duration-1000 ease-out`}
                    strokeWidth="8"
                    strokeDasharray={circumference}
                    strokeDashoffset={strokeDashoffset}
                    strokeLinecap="round"
                    stroke="currentColor"
                    fill="transparent"
                    r={radius}
                    cx="42"
                    cy="42"
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-2xl font-bold text-gray-800 leading-none">{score}</span>
                  <span className="text-[11px] font-bold text-gray-400">/ 10</span>
                </div>
              </div>

              {/* Verdict */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <StatusIcon className={`w-5 h-5 ${statusColor}`} />
                  <h2 className={`text-xl font-bold ${statusColor}`}>{statusText}</h2>
                  {llmResult && <BrainCircuit className="w-4 h-4 text-purple-400" />}
                </div>
                <p className="text-gray-500 text-[15px] truncate font-medium">
                  {getDomain(pageUrl) || "—"}
                </p>
              </div>
            </div>
          </div>


          {/* Summary */}
          <div
            className={`p-4 rounded-xl border ${summaryBg} shadow-sm transition-opacity ${
              !extensionEnabled ? "opacity-50" : ""
            }`}
          >
            <div className="flex items-start gap-3">
              <Info className="w-5 h-5 mt-0.5 flex-shrink-0 opacity-80" />
              <p className="text-[15px] leading-snug font-medium">{summaryText}</p>
            </div>
          </div>

          {/* AI disclaimer + error */}
          {(llmResult || llmError) && (
            <p className="text-center text-xs text-gray-400 px-2">
              {llmError
                ? "AI check unavailable. Results shown are from heuristic scan only."
                : "AI results may not always be accurate. When in doubt, avoid the site."}
            </p>
          )}

          {/* Settings */}
          <div>
            <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-2 px-1">
              Settings
            </h3>
            <div className="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden divide-y divide-gray-100">

              {/* Enable Beacon */}
              <div className="p-4 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div
                    className={`p-2 rounded-lg ${
                      extensionEnabled ? "bg-blue-50 text-blue-600" : "bg-gray-100 text-gray-500"
                    }`}
                  >
                    <Power className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="font-semibold text-[15px] text-gray-900">Enable Beacon</div>
                    <div className="text-[13px] text-gray-500">Protect your browsing</div>
                  </div>
                </div>
                <Toggle enabled={extensionEnabled} onChange={handleExtensionToggle} />
              </div>

              {/* Advanced AI Check */}
              <div className="p-4 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div
                    className={`p-2 rounded-lg ${
                      aiEnabled && extensionEnabled
                        ? "bg-purple-50 text-purple-600"
                        : "bg-gray-100 text-gray-500"
                    }`}
                  >
                    <BrainCircuit className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="font-semibold text-[15px] text-gray-900">Advanced AI Check</div>
                    <div className="text-[13px] text-gray-500">Allow calling language model</div>
                  </div>
                </div>
                <Toggle
                  enabled={aiEnabled}
                  onChange={handleAiToggle}
                  disabled={!extensionEnabled}
                />
              </div>

            </div>
          </div>

        </div>
      </div>
    </div>
  );
}

function Toggle({
  enabled,
  onChange,
  disabled = false,
}: {
  enabled: boolean;
  onChange: (val: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={() => !disabled && onChange(!enabled)}
      disabled={disabled}
      className={`relative inline-flex h-7 w-12 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
        disabled ? "opacity-50 cursor-not-allowed" : ""
      } ${enabled ? "bg-green-500" : "bg-gray-300"}`}
      role="switch"
      aria-checked={enabled}
    >
      <span
        aria-hidden="true"
        className={`pointer-events-none inline-block h-6 w-6 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
          enabled ? "translate-x-5" : "translate-x-0"
        }`}
      />
    </button>
  );
}
