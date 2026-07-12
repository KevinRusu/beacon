# Contract tests for the /v1/analyze wire contract.
#
# The one invariant that must never regress: every score is a SAFETY score
# (10 = safe, 0 = scam) with toVerdict thresholds (>=7 safe, 4-6 uncertain,
# <=3 scam). The original C1 bug shipped a scam page as "10/10 Safe" because
# one side of the wire read the scale inverted — these tests pin both sides.

import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

BASE_BODY = {
    "url": "https://example.com/login",
    "text": "Enter your password to continue.",
    "context": "page_body",
}


def analyze(score: int, headers: dict | None = None, **overrides):
    body = {**BASE_BODY, "heuristic_score": score, **overrides}
    return client.post("/v1/analyze", json=body, headers=headers or {})


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# –– Safety-scale mapping (the C1 regression tests) ––

@pytest.mark.parametrize(
    "score, label, action",
    [
        (0, "scam", "block"),
        (3, "scam", "block"),
        (4, "uncertain", "warn"),
        (5, "uncertain", "warn"),
        (6, "uncertain", "warn"),
        (7, "safe", "allow"),
        (10, "safe", "allow"),
    ],
)
def test_safety_scale_verdicts(score, label, action):
    resp = analyze(score)
    assert resp.status_code == 200
    data = resp.json()
    assert data["label"] == label
    assert data["action"] == action
    # Mock echoes the safety score unchanged — same scale, never inverted.
    assert data["safety_score"] == score


def test_scam_page_is_never_reported_safe():
    # The exact C1 failure: heuristic safety score 0 (scam) must come back
    # as a scam verdict, not "safe" with a perfect score.
    data = analyze(0).json()
    assert data["label"] == "scam"
    assert data["safety_score"] == 0


def test_response_uses_safety_score_field():
    data = analyze(5).json()
    assert "safety_score" in data
    assert "risk_score" not in data


# –– Input validation (request-size caps) ––

def test_score_out_of_range_rejected():
    assert analyze(11).status_code == 422
    assert analyze(-1).status_code == 422


def test_oversized_title_rejected():
    assert analyze(5, title="x" * 301).status_code == 422


def test_oversized_url_rejected():
    body = {**BASE_BODY, "heuristic_score": 5, "url": "https://e.com/" + "a" * 2100}
    assert client.post("/v1/analyze", json=body).status_code == 422


def test_too_many_findings_rejected():
    assert analyze(5, heuristic_findings=["f"] * 21).status_code == 422


def test_oversized_finding_rejected():
    assert analyze(5, heuristic_findings=["x" * 301]).status_code == 422


# –– Origin allowlist ––

GOOD_ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"


def test_origin_allowlist(monkeypatch):
    monkeypatch.setenv("ALLOWED_EXTENSION_ORIGINS", GOOD_ORIGIN)
    assert analyze(5, headers={"Origin": GOOD_ORIGIN}).status_code == 200
    assert analyze(5, headers={"Origin": "https://evil.example"}).status_code == 401
    assert analyze(5).status_code == 401  # no Origin header at all


def test_no_allowlist_accepts_everything(monkeypatch):
    monkeypatch.delenv("ALLOWED_EXTENSION_ORIGINS", raising=False)
    assert analyze(5).status_code == 200
    assert analyze(5, headers={"Origin": "https://anywhere.example"}).status_code == 200