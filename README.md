# http-content-security-policy

Parse a Content-Security-Policy header into a structured mapping of directives and source lists.

```python
from http_content_security_policy import parse

header = "default-src 'self'; img-src 'self' data:; sandbox"
policy = parse(header)

print(policy.directives)
# {'default-src': ["'self'"], 'img-src': ["'self'", 'data:'], 'sandbox': []}

print(policy["img-src"])
# ["'self'", 'data:']
```

## Why this exists

CSP headers are simple enough that hand-rolled splitting often works until a source list contains unusual whitespace, duplicate directives, or an empty directive like `sandbox`. This library provides one deterministic parsing rule: split on semicolons, then split each segment on whitespace, returning the directive name and its source list. No source grammar validation is attempted, because that ruleset changes often and would make the parser heavier than most callers need.

## Edge cases

Directive names are lowercased. Source expressions are returned exactly as they appear. Duplicate directives replace earlier ones. A directive with no sources, such as `sandbox`, is stored with an empty list, not omitted.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

