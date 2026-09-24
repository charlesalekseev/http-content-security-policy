"""HTTP Content Security Policy parser.

Expose the public API for parsing Content-Security-Policy header values.
"""

from .core import Policy, parse

__all__ = ["Policy", "parse"]
