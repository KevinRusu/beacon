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
  Moon,
} from "lucide-react";
import type { HeuristicResult, ExtractedPageData } from "../types/heuristics";
import type { AnalyzeResponse } from "../types/api";
import { applyTheme, readTheme, saveTheme, type Theme } from "./theme";

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
  const [tabId, setTabId] = useState<number | null>(null);
  const [pageUrl, setPageUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [extensionEnabled, setExtensionEnabled] = useState(true);
  const [aiEnabled, setAiEnabled] = useState(true);
  const [llmResult, setLlmResult] = useState<AnalyzeResponse | null>(null);
  const [llmError, setLlmError] = useState<string | null>(null);
  // popup.tsx already applied this to <html> before render; this just mirrors
  // it into React so the switch shows the right position.
  const [theme, setTheme] = useState<Theme>(readTheme);

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
        setTabId(tab.id);
        chrome.runtime.sendMessage(
          { action: "getResult", tabId: tab.id },
          (response: {
            result?: HeuristicResult;
            pageData?: ExtractedPageData;
            aiResult?: AnalyzeResponse;
            error?: string;
          }) => {
            if (chrome.runtime.lastError || response?.error || !response?.result) {
              setError("Page not yet analysed. Refresh the page and try again.");
            } else {
              setResult(response.result);
              setPageData(response.pageData ?? null);
              setPageUrl(response.pageData?.url ?? tab.url ?? "");
              // A Tier 2 check completed earlier for this tab survives
              // popup close/reopen — the background worker cached it.
              if (response.aiResult) setLlmResult(response.aiResult);
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

  const handleThemeToggle = (dark: boolean) => {
    const next: Theme = dark ? "dark" : "light";
    setTheme(next);
    applyTheme(next);
    saveTheme(next);
  };

  // The network call lives in the background service worker (the only place
  // that fetches) — it builds the payload, calls the API, and caches the
  // response so it survives popup close/reopen.
  const handleCheckPage = () => {
    if (!result || tabId === null) return;
    setIsAnalyzing(true);
    setLlmError(null);
    chrome.runtime.sendMessage(
      { action: "checkWithAI", tabId },
      (response: { aiResult?: AnalyzeResponse; error?: string }) => {
        if (chrome.runtime.lastError || response?.error || !response?.aiResult) {
          setLlmError("AI check unavailable");
        } else {
          setLlmResult(response.aiResult);
        }
        setIsAnalyzing(false);
      }
    );
  };

  // Both tiers use the same SAFETY scale (10 = safe, 0 = scam) — no inversion.
  const score = llmResult ? llmResult.safety_score : (result?.score ?? 0);
  const activeVerdict = llmResult?.label ?? result?.verdict;
  const isSafe = !result || activeVerdict === "safe";
  const isWarning = activeVerdict === "uncertain";
  const isDanger = activeVerdict === "scam";

  // Dark variants lighten the hue rather than reuse it: green-600 on a dark
  // card is too low-contrast to read as a status colour.
  let statusColor = "text-green-600 dark:text-green-400";
  let ringColor = "text-green-500 dark:text-green-400";
  let statusText = "Safe";
  let StatusIcon = CheckCircle;
  let summaryBg =
    "bg-green-50 text-green-800 border-green-200 dark:bg-green-950 dark:text-green-200 dark:border-green-900";

  if (isWarning) {
    statusColor = "text-amber-500 dark:text-amber-400";
    ringColor = "text-amber-500 dark:text-amber-400";
    statusText = "Warning";
    StatusIcon = AlertTriangle;
    summaryBg =
      "bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950 dark:text-amber-200 dark:border-amber-900";
  } else if (isDanger) {
    statusColor = "text-red-600 dark:text-red-400";
    ringColor = "text-red-500 dark:text-red-400";
    statusText = "Dangerous";
    StatusIcon = ShieldAlert;
    summaryBg =
      "bg-red-50 text-red-800 border-red-200 dark:bg-red-950 dark:text-red-200 dark:border-red-900";
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
      <div className="w-[400px] h-[200px] bg-[#f5f5f7] dark:bg-gray-900 flex items-center justify-center font-sans">
        <div className="flex flex-col items-center gap-3 text-gray-500 dark:text-gray-400">
          <Activity className="w-7 h-7 animate-pulse text-blue-500 dark:text-blue-400" />
          <p className="text-sm font-medium">Checking page…</p>
        </div>
      </div>
    );
  }

  if (!extensionEnabled || error) {
    return (
      <div className="w-[400px] bg-[#f5f5f7] dark:bg-gray-900 flex flex-col font-sans">
        {/* Header */}
        <div className="flex flex-col items-center pt-8 pb-5 px-6">
          <div className="flex items-center gap-2 mb-1 text-blue-900 dark:text-blue-300">
            <RadioTower className="w-8 h-8 text-blue-600 dark:text-blue-400" />
            <h1 className="text-3xl font-bold tracking-tight">Beacon</h1>
          </div>
          <p className="text-[15px] text-gray-500 dark:text-gray-400 font-medium">
            Scam Detection Tool
          </p>
        </div>
        <div className="px-5 pb-8 space-y-5">
          {!extensionEnabled ? (
            <div className="p-4 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shadow-sm">
              <div className="flex items-start gap-3">
                <Power className="w-5 h-5 mt-0.5 flex-shrink-0 text-gray-400 dark:text-gray-500" />
                <p className="text-[15px] leading-snug font-medium text-gray-600 dark:text-gray-300">
                  Beacon is paused. Switch <span className="font-semibold">Enable Beacon</span> back
                  on to resume checking pages.
                </p>
              </div>
            </div>
          ) : (
            <div className="p-4 rounded-xl border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950 shadow-sm">
              <div className="flex items-start gap-3">
                <AlertCircle className="w-5 h-5 mt-0.5 flex-shrink-0 text-red-500 dark:text-red-400" />
                <p className="text-[15px] leading-snug font-medium text-red-800 dark:text-red-200">
                  {error}
                </p>
              </div>
            </div>
          )}
          <SettingsPanel
            extensionEnabled={extensionEnabled}
            aiEnabled={aiEnabled}
            darkMode={theme === "dark"}
            onExtensionToggle={handleExtensionToggle}
            onAiToggle={handleAiToggle}
            onThemeToggle={handleThemeToggle}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="w-[400px] h-[600px] bg-[#f5f5f7] dark:bg-gray-900 flex flex-col font-sans overflow-hidden text-gray-900 dark:text-gray-100">
      <div className="flex-1 overflow-y-auto">

        {/* Header */}
        <div className="flex flex-col items-center pt-8 pb-5 px-6">
          <div className="flex items-center gap-2 mb-1 text-blue-900 dark:text-blue-300">
            <RadioTower className="w-8 h-8 text-blue-600 dark:text-blue-400" />
            <h1 className="text-3xl font-bold tracking-tight">Beacon</h1>
          </div>
          <p className="text-[15px] text-gray-500 dark:text-gray-400 font-medium">
            Scam Detection Tool
          </p>
        </div>

        <div className="px-5 space-y-5 pb-8">

          {/* Action Button */}
          <div>
            <button
              onClick={handleCheckPage}
              disabled={isSafe || isAnalyzing || !extensionEnabled || !aiEnabled || !!llmResult}
              className={`w-full py-3.5 px-4 rounded-xl font-semibold text-[16px] shadow-sm flex justify-center items-center gap-2 transition-all ${
                isSafe || !extensionEnabled || !aiEnabled
                  ? "bg-gray-200 text-gray-400 dark:bg-gray-800 dark:text-gray-500 cursor-not-allowed"
                  : // blue-600 in both themes on purpose: blue-500 would drop
                    // the white label to 3.7:1, below the light theme's 5.2:1.
                    "bg-blue-600 hover:bg-blue-700 text-white hover:shadow-md active:scale-[0.98]"
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
              <p className="text-center text-xs text-gray-500 dark:text-gray-400 mt-2 font-medium">
                Uses Advanced AI to scan for hidden threats
              </p>
            )}
          </div>

          {/* Score Card */}
          <div
            className={`bg-white dark:bg-gray-800 rounded-2xl p-5 shadow-sm border border-gray-100 dark:border-gray-700 transition-opacity ${
              !extensionEnabled ? "opacity-50" : ""
            }`}
          >
            <div className="flex items-center gap-5">
              {/* Circular Gauge */}
              <div className="relative w-[84px] h-[84px] flex-shrink-0">
                <svg className="w-full h-full transform -rotate-90">
                  <circle
                    className="text-gray-100 dark:text-gray-700"
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
                  <span className="text-2xl font-bold text-gray-800 dark:text-gray-100 leading-none">
                    {score}
                  </span>
                  <span className="text-[11px] font-bold text-gray-400 dark:text-gray-500">
                    / 10
                  </span>
                </div>
              </div>

              {/* Verdict */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <StatusIcon className={`w-5 h-5 ${statusColor}`} />
                  <h2 className={`text-xl font-bold ${statusColor}`}>{statusText}</h2>
                  {llmResult && (
                    <BrainCircuit className="w-4 h-4 text-purple-400 dark:text-purple-300" />
                  )}
                </div>
                <p className="text-gray-500 dark:text-gray-400 text-[15px] truncate font-medium">
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

          {/* AI disclaimer + error. gray-400 reads in both themes (7.0:1 on the
              dark page), so it needs no dark variant. */}
          {(llmResult || llmError) && (
            <p className="text-center text-xs text-gray-400 px-2">
              {llmError
                ? "AI check unavailable. Results shown are from heuristic scan only."
                : "AI results may not always be accurate. When in doubt, avoid the site."}
            </p>
          )}

          <SettingsPanel
            extensionEnabled={extensionEnabled}
            aiEnabled={aiEnabled}
            darkMode={theme === "dark"}
            onExtensionToggle={handleExtensionToggle}
            onAiToggle={handleAiToggle}
            onThemeToggle={handleThemeToggle}
          />

        </div>
      </div>
    </div>
  );
}

// Rendered by every popup state, so the Enable Beacon toggle is always reachable.
function SettingsPanel({
  extensionEnabled,
  aiEnabled,
  darkMode,
  onExtensionToggle,
  onAiToggle,
  onThemeToggle,
}: {
  extensionEnabled: boolean;
  aiEnabled: boolean;
  darkMode: boolean;
  onExtensionToggle: (val: boolean) => void;
  onAiToggle: (val: boolean) => void;
  onThemeToggle: (val: boolean) => void;
}) {
  return (
    <div>
      <h3 className="text-sm font-bold text-gray-400 uppercase tracking-wider mb-2 px-1">
        Settings
      </h3>
      <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-gray-100 dark:border-gray-700 overflow-hidden divide-y divide-gray-100 dark:divide-gray-700">

        {/* Enable Beacon */}
        <div className="p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className={`p-2 rounded-lg ${
                extensionEnabled
                  ? "bg-blue-50 text-blue-600 dark:bg-blue-950 dark:text-blue-400"
                  : "bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-400"
              }`}
            >
              <Power className="w-5 h-5" />
            </div>
            <div>
              <div className="font-semibold text-[15px] text-gray-900 dark:text-gray-100">
                Enable Beacon
              </div>
              <div className="text-[13px] text-gray-500 dark:text-gray-400">
                Protect your browsing
              </div>
            </div>
          </div>
          <Toggle enabled={extensionEnabled} onChange={onExtensionToggle} />
        </div>

        {/* Advanced AI Check */}
        <div className="p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className={`p-2 rounded-lg ${
                aiEnabled && extensionEnabled
                  ? "bg-purple-50 text-purple-600 dark:bg-purple-950 dark:text-purple-400"
                  : "bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-400"
              }`}
            >
              <BrainCircuit className="w-5 h-5" />
            </div>
            <div>
              <div className="font-semibold text-[15px] text-gray-900 dark:text-gray-100">
                Advanced AI Check
              </div>
              <div className="text-[13px] text-gray-500 dark:text-gray-400">
                Allow calling language model
              </div>
            </div>
          </div>
          <Toggle enabled={aiEnabled} onChange={onAiToggle} disabled={!extensionEnabled} />
        </div>

        {/* Dark Mode — a display preference, so unlike the AI check it stays
            usable while Beacon is paused. */}
        <div className="p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className={`p-2 rounded-lg ${
                darkMode
                  ? "bg-indigo-50 text-indigo-600 dark:bg-indigo-950 dark:text-indigo-400"
                  : "bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-400"
              }`}
            >
              <Moon className="w-5 h-5" />
            </div>
            <div>
              <div className="font-semibold text-[15px] text-gray-900 dark:text-gray-100">
                Dark Mode
              </div>
              <div className="text-[13px] text-gray-500 dark:text-gray-400">
                Easier on the eyes at night
              </div>
            </div>
          </div>
          <Toggle enabled={darkMode} onChange={onThemeToggle} />
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
      } ${enabled ? "bg-green-500" : "bg-gray-300 dark:bg-gray-600"}`}
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
