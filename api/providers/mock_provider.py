from schemas import AnalyzeRequest, AnalyzeResponse


class MockProvider:
    async def analyze(self, request: AnalyzeRequest) -> AnalyzeResponse:
        score = request.heuristic_score
        if score >= 7:
            return AnalyzeResponse(
                risk_score=score,
                label="scam",
                action="block",
                reason="Heuristic signals indicate high likelihood of phishing or fraud.",
            )
        if score >= 4:
            return AnalyzeResponse(
                risk_score=score,
                label="uncertain",
                action="warn",
                reason="Some suspicious indicators detected; proceed with caution.",
            )
        return AnalyzeResponse(
            risk_score=score,
            label="safe",
            action="allow",
            reason="No significant risk indicators detected.",
        )