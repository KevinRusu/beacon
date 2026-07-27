# Provider configuration guards.
#
# Constructing the real (Vertex) provider without the required config must fail
# fast with ProviderConfigError — not a network/auth error later — so a
# misconfigured deploy is caught at startup by _validate_config(). No network is
# touched: the guard raises before any Vertex client is built.

import pytest

from providers.gemini_provider import GeminiProvider
from exceptions import ProviderConfigError


def test_missing_project_raises_config_error(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    with pytest.raises(ProviderConfigError):
        GeminiProvider()
