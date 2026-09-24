"""Core parsing logic for Content-Security-Policy headers.

The parser accepts a header value and returns a Policy object that maps
directive names to lists of source expressions. Source expressions are
returned exactly as they appear, without validation, because validating
source grammar would require maintaining a large and frequently changing
set of rules. Keeping the parser structural only makes it predictable.
"""

from __future__ import annotations

from typing import Dict, List


class Policy:
    """Structured representation of a Content-Security-Policy.

    Attributes:
        directives: A mapping of lowercase directive names to their source
            lists. Directives with an empty source list (for example,
            ``sandbox``) are stored with an empty list, preserving the
            distinction between a directive that is absent and one that is
            present with no sources.
    """

    def __init__(self, directives: Dict[str, List[str]]):
        self.directives = directives

    def __getitem__(self, name: str) -> List[str]:
        """Return the source list for a directive.

        Raises KeyError if the directive is not present, matching normal
        mapping behaviour. Callers that prefer a default should use
        ``policy.directives.get(name, [])``.
        """
        return self.directives[name.lower()]

    def get(self, name: str, default: List[str] | None = None) -> List[str]:
        """Return the source list for a directive, or a default."""
        if default is None:
            default = []
        return self.directives.get(name.lower(), default)

    def __contains__(self, name: str) -> bool:
        return name.lower() in self.directives

    def __repr__(self) -> str:
        return f"Policy({self.directives!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Policy):
            return NotImplemented
        return self.directives == other.directives


def parse(header: str) -> Policy:
    """Parse a Content-Security-Policy header value.

    The grammar is intentionally simple and matches the RFC's core structure:
    a header consists of one or more directives separated by semicolons. Each
    directive has a name followed by zero or more source expressions. Source
    expressions are separated by whitespace and returned in the order they
    appear.

    Directive names are case-insensitive and are normalised to lowercase.
    Source expressions are returned exactly as written; the caller is
    responsible for any further validation or interpretation.

    Args:
        header: The raw header value. May be empty, in which case an empty
            Policy is returned.

    Returns:
        A Policy object containing the parsed directives.
    """
    if not isinstance(header, str):
        raise TypeError("header must be a string")

    directives: Dict[str, List[str]] = {}

    # Split on semicolons; each segment is one directive. The final
    # segment may be empty when the header ends with a semicolon, which
    # is valid and should be ignored.
    for segment in header.split(";"):
        # Collapse all whitespace runs to single spaces for consistent
        # tokenisation. Leading and trailing whitespace around a segment
        # is also removed.
        parts = segment.strip().split()
        if not parts:
            continue

        name = parts[0].lower()
        sources = parts[1:]

        # If the same directive appears twice, later occurrences replace
        # earlier ones. This is the simplest deterministic rule and is
        # commonly observed in browsers.
        directives[name] = sources

    return Policy(directives)
