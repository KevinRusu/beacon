from schemas import AnalyzeRequest, AnalyzeResponse


class MockProvider:
    # Echoes the heuristic safety score back and derives the label from it,
    # using the same thresholds as the extension's toVerdict():
    # >=7 safe, 4-6 uncertain, <=3 scam.
    async def analyze(self, request: AnalyzeRequest) -> AnalyzeResponse:
        score = request.heuristic_score
        if score >= 7:
            return AnalyzeResponse(
                safety_score=score,
                label="safe",
                action="allow",
                reason="No significant risk indicators detected.",
            )
        if score >= 4:
            return AnalyzeResponse(
                safety_score=score,
                label="uncertain",
                action="warn",
                reason="Some suspicious indicators detected; proceed with caution.",
            )
        return AnalyzeResponse(
            safety_score=score,
            label="scam",
            action="block",
            reason="Heuristic signals indicate high likelihood of phishing or fraud.",
        )