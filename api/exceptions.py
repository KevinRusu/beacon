class ProviderConfigError(RuntimeError):
    """Raised when a provider is missing required configuration (e.g. API key)."""