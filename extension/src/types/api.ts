import type { Verdict } from "./heuristics";

export interface AnalyzeResponse {
  safety_score: number;  // 0–10 SAFETY scale (10 = safe) — same scale as HeuristicResult.score, never inverted
  label: Verdict;        // "safe" | "uncertain" | "scam"
  action: "allow" | "warn" | "block";
  reason: string;
}