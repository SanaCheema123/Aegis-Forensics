import unittest
from unittest.mock import patch

import modules.semantic_matcher as semantic_matcher
from modules.semantic_matcher import SemanticMatcher


class SemanticMatcherTests(unittest.TestCase):
    def test_fallback_is_labeled_as_heuristic_and_has_results(self):
        with patch.object(semantic_matcher, "_SENTENCE_TRANSFORMERS_AVAILABLE", False):
            with patch.object(semantic_matcher, "SentenceTransformer", None):
                matcher = SemanticMatcher()

        matches = matcher.correlate_events(
            ["Failed logins from an unknown host", "Routine startup"],
            "failed logins",
        )

        self.assertEqual(matcher.last_mode, "lexical_heuristic")
        self.assertIn("not installed", matcher.last_error)
        self.assertEqual(matches[0]["event"], "Failed logins from an unknown host")


if __name__ == "__main__":
    unittest.main()
