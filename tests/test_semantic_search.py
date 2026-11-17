"""Evidence identity, text selection, caching, and original-row regressions."""
import ast
from pathlib import Path
import unittest
from unittest.mock import MagicMock, Mock, patch

import pandas as pd

import modules.semantic_matcher as matcher_module
from modules.semantic_matcher import SemanticMatcher
from modules.semantic_search import event_text_columns, prepare_evidence_search, search_evidence


ROOT = Path(__file__).resolve().parents[1]
APP_TREE = ast.parse((ROOT / "dashboard/app.py").read_text(encoding="utf-8"))
SEARCH_TAB = next(node for node in APP_TREE.body if isinstance(node, ast.With)
                  and ast.unparse(node.items[0].context_expr) == "tab3")


class SemanticSearchTests(unittest.TestCase):
    def setUp(self):
        self.available = patch.object(matcher_module, "_SENTENCE_TRANSFORMERS_AVAILABLE", False)
        self.available.start()
        self.addCleanup(self.available.stop)

    def prepare(self, frame, **changes):
        options = dict(sha256="a" * 64, case_id="CASE-A", query="failed login",
                       filename="events.csv", max_records=10_000)
        options.update(changes)
        return prepare_evidence_search(frame, **options)

    def run_tab(self, state, frame, *, sha256="a" * 64, case_id="CASE-A",
                query="failed login", click=False, max_records=10_000):
        st = MagicMock()
        st.session_state = state
        st.text_input.return_value = query
        st.button.return_value = click
        namespace = dict(st=st, df=frame, tab3=MagicMock(), sha256_hash=sha256,
                         case_id=case_id, safe_name="events.csv", raw_df=None,
                         SEMANTIC_SEARCH_MAX_RECORDS=max_records,
                         prepare_evidence_search=prepare_evidence_search,
                         search_evidence=search_evidence, pd=pd,
                         _render_technical_table=Mock())
        exec(compile(ast.Module(body=[SEARCH_TAB], type_ignores=[]), "dashboard/app.py", "exec"), namespace)
        return st, namespace

    def test_event_columns_override_timestamp_and_identifier_column_order(self):
        frame = pd.DataFrame({
            "timestamp": ["2026-11-12"], "user": ["alice"], "proto": ["tcp"],
            "Description": pd.Series(["authentication rejected"], dtype="string"),
            "Event Details": ["remote workstation"], "Message": ["failed login"],
        })
        self.assertEqual(event_text_columns(frame), ["Message", "Description", "Event Details"])
        prepared = self.prepare(frame)
        text = prepared["records"][0]["event"]
        for value in ("failed login", "authentication rejected", "remote workstation"):
            self.assertIn(value, text)
        for value in ("alice", "2026-11-12", "tcp"):
            self.assertNotIn(value, text)

    def test_raw_log_column_is_supported(self):
        frame = pd.DataFrame({"id": [1], "raw_log": ["failed login"]})
        self.assertEqual(self.prepare(frame)["columns"], ["raw_log"])

    def test_missing_or_empty_text_does_not_search_identifiers_or_initialize_model(self):
        for frame in (
            pd.DataFrame({"user": ["alice"], "id": [5]}),
            pd.DataFrame({"message": [None, "  ", 123]}),
            pd.DataFrame(),
        ):
            with self.subTest(columns=list(frame.columns)), patch(
                "modules.semantic_search.SemanticMatcher"
            ) as matcher:
                prepared = self.prepare(frame)
                self.assertEqual(search_evidence(prepared)["matches"], [])
                matcher.assert_not_called()
                state = {"investigation_search_result": {"query": "failed login", "matches": ["stale"]}}
                st, _ = self.run_tab(state, frame, click=True)
                self.assertNotIn("investigation_search_result", state)
                st.warning.assert_called_once()

    def test_repeated_query_reuses_results_but_new_evidence_cannot_display_old_matches(self):
        frame = pd.DataFrame({"message": ["failed login from workstation A"]})
        state = {}
        with patch("modules.semantic_search.SemanticMatcher", wraps=SemanticMatcher) as factory:
            self.run_tab(state, frame, click=True)
            first = state["investigation_search_result"]
            self.run_tab(state, frame, click=True)
            self.assertIs(state["investigation_search_result"], first)
            self.assertEqual(factory.call_count, 1)
            other = pd.DataFrame({"message": ["routine service on workstation B"]})
            st, namespace = self.run_tab(state, other, sha256="b" * 64)
            self.assertNotIn("investigation_search_result", state)
            namespace["_render_technical_table"].assert_not_called()
            self.run_tab(state, other, sha256="b" * 64, query="routine", click=True)
            second = state["investigation_search_result"]
            self.assertNotEqual(second["key"], first["key"])
            self.assertEqual(second["matches"][0]["sha256"], "b" * 64)
            self.assertNotIn("workstation A", second["matches"][0]["event"])

    def test_case_query_and_limit_changes_clear_dashboard_results(self):
        frame = pd.DataFrame({"message": ["failed login", "routine service"]})
        for change in (dict(case_id="CASE-B"), dict(query="routine"), dict(max_records=1)):
            with self.subTest(change=change):
                state = {}
                self.run_tab(state, frame, click=True)
                self.run_tab(state, frame, **change)
                self.assertNotIn("investigation_search_result", state)

    def test_key_covers_model_columns_content_filename_and_search_settings(self):
        frame = pd.DataFrame({"message": ["failed login"]})
        baseline = self.prepare(frame)
        self.assertEqual(self.prepare(frame)["key"], baseline["key"])
        for changes in (dict(model_name="different-model"), dict(filename="other.csv"),
                        dict(sha256="b" * 64), dict(case_id="CASE-B"),
                        dict(query="other query"), dict(max_records=1)):
            self.assertNotEqual(self.prepare(frame, **changes)["key"], baseline["key"])
        for changed in (frame.rename(columns={"message": "description"}),
                        pd.DataFrame({"message": ["different content"]})):
            self.assertNotEqual(self.prepare(changed)["key"], baseline["key"])

    def test_blank_rows_and_duplicate_text_keep_original_record_references(self):
        frame = pd.DataFrame({"message": [None, "failed login", "failed login"]},
                             index=[10, 30, 30])
        source = pd.DataFrame({"line_no": [2, 3, 4]})
        prepared = self.prepare(frame, source_rows=source)
        result = search_evidence(prepared)
        self.assertEqual([match["record_position"] for match in result["matches"]], [1, 2])
        self.assertEqual([match["record_number"] for match in result["matches"]], [2, 3])
        self.assertTrue(all("source_line" not in match for match in result["matches"]))
        for match in result["matches"]:
            self.assertEqual(match["source_index"], 30)
            self.assertEqual(match["case_id"], "CASE-A")
            self.assertEqual(match["file"], "events.csv")
            self.assertEqual(match["sha256"], "a" * 64)

    def test_blank_query_does_not_initialize_model(self):
        prepared = self.prepare(pd.DataFrame({"message": ["failed login"]}), query="  ")
        with patch("modules.semantic_search.SemanticMatcher") as matcher:
            self.assertEqual(search_evidence(prepared)["mode"], "no_input")
            matcher.assert_not_called()

    def test_network_categories_search_without_numeric_prose_or_false_matches(self):
        frame = pd.DataFrame({"proto": ["tcp", None, "tcp"],
            "service": ["http", None, "http"], "state": ["FIN", None, "FIN"],
            "attack_cat": ["Generic", None, "Generic"], "dur": [1, 2, 3], "label": [1, 0, 1]})
        prepared = self.prepare(frame, query="Generic")
        self.assertEqual(prepared["columns"], ["proto", "service", "state", "attack_cat"])
        matches = search_evidence(prepared)["matches"]
        self.assertEqual([m["record_number"] for m in matches], [1, 3])
        self.assertNotIn("dur:", matches[0]["event"])
        self.assertEqual(search_evidence(self.prepare(frame, query="unauthorized access"))["matches"], [])

    def test_network_multiline_source_locations_are_preserved_after_filtering(self):
        import tempfile
        from modules.csv_evidence import read_evidence_csv, CSV_METADATA
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network.csv"
            path.write_text('proto,attack_cat\ntcp,"Generic\ncategory"\nudp,Normal\ntcp,Generic\n', encoding="utf-8")
            frame = read_evidence_csv(path)
            selected = frame.iloc[[0, 2]]
            prepared = self.prepare(selected, sha256=frame.attrs[CSV_METADATA]["sha256"], query="Generic")
            matches = search_evidence(prepared)["matches"]
            self.assertEqual(sorted((m["record_number"], m["source_line"], m["source_line_end"]) for m in matches),
                             [(1, 2, 3), (3, 5, 5)])

    def test_demo_csv_has_40_generic_lexical_matches(self):
        from modules.csv_evidence import read_evidence_csv, CSV_METADATA
        frame = read_evidence_csv(ROOT / "data/training/UNSW_NB15_demo_balanced.csv")
        result = search_evidence(self.prepare(frame, query="Generic", sha256=frame.attrs[CSV_METADATA]["sha256"]))
        self.assertEqual(len(result["matches"]), 40)

    def test_dashboard_search_error_is_visible_and_does_not_cache_failure(self):
        with patch.dict(self.run_tab.__globals__, search_evidence=Mock(side_effect=RuntimeError("search unavailable"))):
            state = {}
            st, _ = self.run_tab(state, pd.DataFrame({"message": ["failed login"]}), click=True)
            st.error.assert_called_once()
            self.assertIn("search unavailable", st.error.call_args.args[0])
            self.assertNotIn("investigation_search_result", state)

    def test_investigation_tabs_have_persistent_key_and_track_selection(self):
        tabs = next(node for node in ast.walk(APP_TREE) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute) and node.func.attr == "tabs")
        options = {kw.arg: ast.literal_eval(kw.value) for kw in tabs.keywords}
        self.assertEqual(options["key"], "investigation_workspace_tab")
        self.assertEqual(options["on_change"], "rerun")


class TransformerCacheTests(unittest.TestCase):
    def setUp(self):
        matcher_module._cached_model.cache_clear()
        self.addCleanup(matcher_module._cached_model.cache_clear)
        snapshot = patch.object(matcher_module, '_reviewed_transformer_snapshot',
            return_value=(Path('/reviewed/local/model'), {'model_id': 'reviewed-test-model', 'revision': 'test'}))
        snapshot.start()
        self.addCleanup(snapshot.stop)

    def test_model_is_initialized_once_per_model_name(self):
        with patch.object(matcher_module, "_SENTENCE_TRANSFORMERS_AVAILABLE", True), patch.object(
            matcher_module, "SentenceTransformer"
        ) as constructor:
            first = SemanticMatcher("model-a")
            second = SemanticMatcher("model-a")
            self.assertIs(first.model, second.model)
            constructor.assert_called_once_with(str(Path("/reviewed/local/model")), local_files_only=True, trust_remote_code=False, model_kwargs={"use_safetensors": True})
            SemanticMatcher("model-b")
            self.assertEqual(constructor.call_count, 2)

    def test_failed_initialization_is_not_cached(self):
        with patch.object(matcher_module, "_SENTENCE_TRANSFORMERS_AVAILABLE", True), patch.object(
            matcher_module, "SentenceTransformer", side_effect=[RuntimeError("unavailable"), Mock()]
        ) as constructor:
            first = SemanticMatcher("retry-model")
            self.assertIsNone(first.model)
            self.assertIn("unavailable", first.last_error)
            second = SemanticMatcher("retry-model")
            self.assertIsNotNone(second.model)
            self.assertEqual(constructor.call_count, 2)

    def test_transformer_ranking_retains_input_positions_for_duplicate_text(self):
        model = Mock()
        with patch.object(matcher_module, "_SENTENCE_TRANSFORMERS_AVAILABLE", True), patch.object(
            matcher_module, "SentenceTransformer", return_value=model
        ), patch.object(matcher_module, "util") as util:
            util.cos_sim.return_value = [[0.1, 0.9]]
            matches = SemanticMatcher("rank-model").correlate_events(["same", "same"], "query")
        self.assertEqual([match["record_position"] for match in matches], [1, 0])


if __name__ == "__main__":
    unittest.main()
