from .auth import RiotAuth
from .errors import (
    RiotAuthenticationError,
    RiotAuthError,
    RiotMultifactorError,
    RiotRatelimitError,
    RiotUnknownErrorTypeError,
    RiotUnknownResponseTypeError,
)

__all__ = (
    'RiotAuth',
    'RiotAuthError',
    'RiotAuthenticationError',
    'RiotMultifactorError',
    'RiotRatelimitError',
    'RiotUnknownErrorTypeError',
    'RiotUnknownResponseTypeError',
)

__version__ = '0.1.0'
