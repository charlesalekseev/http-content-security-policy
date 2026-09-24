"""Tests for the Content-Security-Policy parser."""

import unittest

from http_content_security_policy import Policy, parse


class ParseTests(unittest.TestCase):
    def test_empty_header_returns_empty_policy(self):
        policy = parse("")
        self.assertEqual(policy, Policy({}))

    def test_single_directive_with_sources(self):
        policy = parse("default-src 'self' cdn.example.net")
        self.assertEqual(
            policy.directives,
            {"default-src": ["'self'", "cdn.example.net"]},
        )

    def test_multiple_directives(self):
        header = "default-src 'self'; img-src 'self' data:; script-src 'unsafe-inline'"
        policy = parse(header)
        self.assertEqual(
            policy.directives,
            {
                "default-src": ["'self'"],
                "img-src": ["'self'", "data:"],
                "script-src": ["'unsafe-inline'"],
            },
        )

    def test_directive_without_sources_has_empty_list(self):
        policy = parse("sandbox")
        self.assertEqual(policy.directives, {"sandbox": []})

    def test_directive_names_are_lowercased(self):
        policy = parse("Default-Src 'self'")
        self.assertEqual(policy.directives, {"default-src": ["'self'"]})

    def test_duplicate_directives_last_wins(self):
        policy = parse("default-src 'self'; default-src 'none'")
        self.assertEqual(policy.directives, {"default-src": ["'none'"]})

    def test_extra_semicolons_are_ignored(self):
        policy = parse(";; default-src 'self' ;;")
        self.assertEqual(policy.directives, {"default-src": ["'self'"]})

    def test_whitespace_runs_are_collapsed(self):
        policy = parse("default-src    'self'\t\ncdn.example.net")
        self.assertEqual(
            policy.directives,
            {"default-src": ["'self'", "cdn.example.net"]},
        )

    def test_policy_getitem_lowercases_key(self):
        policy = parse("default-src 'self'")
        self.assertEqual(policy["DEFAULT-SRC"], ["'self'"])

    def test_policy_get_returns_default_when_missing(self):
        policy = parse("default-src 'self'")
        self.assertEqual(policy.get("img-src"), [])

    def test_policy_contains_checks_lowercase(self):
        policy = parse("default-src 'self'")
        self.assertIn("DEFAULT-SRC", policy)
        self.assertNotIn("img-src", policy)

    def test_non_string_header_raises_type_error(self):
        with self.assertRaises(TypeError):
            parse(None)  # type: ignore[arg-type]

    def test_source_expressions_are_preserved(self):
        header = "script-src 'unsafe-eval' 'sha256-abc123' https://cdn.example.net"
        policy = parse(header)
        self.assertEqual(
            policy.directives["script-src"],
            ["'unsafe-eval'", "'sha256-abc123'", "https://cdn.example.net"],
        )


if __name__ == "__main__":
    unittest.main()
