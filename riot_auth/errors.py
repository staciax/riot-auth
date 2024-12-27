from typing import Any

from aiohttp import ClientResponse

__all__ = (
    'RiotAuthError',
    'RiotAuthenticationError',
    'RiotMultifactorError',
    'RiotRatelimitError',
    'RiotUnknownErrorTypeError',
    'RiotUnknownResponseTypeError',
)


class RiotAuthError(Exception):
    """Base class for RiotAuth errors."""


class RiotAuthHTTPError(RiotAuthError):
    """Base class for RiotAuth HTTP errors."""

    def __init__(self, response: ClientResponse, message: str | dict[str, Any] | None) -> None:
        self.response: ClientResponse = response
        self.status: int = response.status
        self.text: str
        if isinstance(message, dict):
            self.text = message.get('error', '')
        else:
            self.text = message or ''

        fmt = '{0.status}'
        if len(self.text):
            fmt += ': {1}'

        super().__init__(fmt.format(self.response, self.text))


class RiotAuthenticationError(RiotAuthHTTPError):
    """Failed to authenticate."""


class RiotRatelimitError(RiotAuthHTTPError):
    """Ratelimit error."""

    # def __init__(
    #     self,
    #     response: ClientResponse,
    #     message: str | dict[str, Any] | None,
    # ) -> None:
    #     super().__init__(response, message)
    #     self.retry_after: int = int(response.headers.get('retry-after', 0))


class RiotMultifactorError(RiotAuthHTTPError):
    """Multi-factor failed."""


class RiotUnknownResponseTypeError(RiotAuthHTTPError):
    """Unknown response type."""


class RiotUnknownErrorTypeError(RiotAuthHTTPError):
    """Unknown response error type."""
