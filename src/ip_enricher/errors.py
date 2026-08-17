class EnricherError(Exception):
    """Base error for expected application failures."""


class ConfigurationError(EnricherError):
    """Configuration is invalid or incomplete."""


class ProviderError(EnricherError):
    """A provider request failed."""


class AuthenticationError(ProviderError):
    """Provider authentication failed."""


class RateLimitError(ProviderError):
    """Provider rate limit was reached."""


class QueryBudgetExceeded(ProviderError):
    """The configured per-run query-credit budget was exhausted."""


class IncompleteResultsError(ProviderError):
    """A discovery rule required a complete result set."""


class StorageError(EnricherError):
    """Investigation artifacts could not be persisted."""
