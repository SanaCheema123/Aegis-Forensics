import ast
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "dashboard" / "app.py"
UI_PATH = ROOT / "dashboard" / "forensic_ui.py"
APP_SOURCE = APP_PATH.read_text(encoding="utf-8")
APP_TREE = ast.parse(APP_SOURCE)
UI_SPEC = importlib.util.spec_from_file_location("aegis_navigation_ui", UI_PATH)
UI_MODULE = importlib.util.module_from_spec(UI_SPEC)
sys.modules[UI_SPEC.name] = UI_MODULE
UI_SPEC.loader.exec_module(UI_MODULE)


def function_node(name):
    return next(
        node for node in APP_TREE.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )


class DashboardNavigationTests(unittest.TestCase):
    def test_top_navigation_has_five_sections_and_all_existing_pages_are_mapped(self):
        self.assertEqual(
            UI_MODULE.NAV,
            [
                "Dashboard",
                "Security Scanner",
                "Live Protection",
                "Investigations",
                "Reports & History",
            ],
        )
        self.assertEqual(len(UI_MODULE.SECTION_PAGES), 6)
        self.assertEqual(
            {page for pages in UI_MODULE.SECTION_PAGES.values() for page in pages},
            {
                "Home",
                "File Scan",
                "Image Scan",
                "Folder Scan",
                "Laptop Scan",
                "URL Scan",
                "Network CSV",
                "YARA Rules",
                "Real-Time Protection",
                "Live Security Alerts",
                "Security Scan History",
                "AI Forensic Reports",
                "Windows Review",
                "Investigation",
                "Evidence",
                "YARA Rules",
                "About",
            },
        )
        self.assertFalse(any("â" in label or "ðŸ" in label for label in UI_MODULE.NAV))

    def test_navigation_uses_native_top_nav_controls_and_no_sidebar(self):
        radio_calls = [
            node for node in ast.walk(APP_TREE)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "st"
            and node.func.attr == "radio"
        ]
        self.assertEqual(len(radio_calls), 2)
        radio_labels = {
            ast.literal_eval(call.args[0])
            for call in radio_calls
            if call.args and isinstance(call.args[0], ast.Constant)
        }
        self.assertIn("Section pages", radio_labels)
        self.assertIn("Live Protection views", radio_labels)
        self.assertIn('st.selectbox(\n                "Navigate"', APP_SOURCE)
        self.assertIn('st.container(key="aegis_top_nav")', APP_SOURCE)
        self.assertIn('st.container(key="aegis_desktop_nav")', APP_SOURCE)
        self.assertIn("ui.MOBILE_NAV", APP_SOURCE)
        self.assertIn("on_click=navigate_to", APP_SOURCE)
        self.assertNotIn("Primary navigation", APP_SOURCE)
        self.assertNotIn("st.sidebar", APP_SOURCE)
        self.assertNotIn("key=\"site_nav\"", APP_SOURCE)
        self.assertEqual(UI_MODULE.MOBILE_NAV, [*UI_MODULE.NAV, "Settings"])

    def test_navigation_callbacks_map_all_legacy_destinations_to_sections(self):
        nodes = [
            function_node(name)
            for name in ("_section_page_key", "navigate_to", "_apply_pending_navigation")
        ]

        class FakeStreamlit:
            session_state = {}

        namespace = {"st": FakeStreamlit, "ui": UI_MODULE, "re": __import__("re")}
        exec(
            compile(ast.Module(body=nodes, type_ignores=[]), str(APP_PATH), "exec"),
            namespace,
        )
        navigate = namespace["navigate_to"]
        apply_pending = namespace["_apply_pending_navigation"]
        for destination, (section, page) in UI_MODULE.NAVIGATION_DESTINATIONS.items():
            FakeStreamlit.session_state["site_section_mobile"] = "Security Scanner"
            FakeStreamlit.session_state[namespace["_section_page_key"](section)] = "previous"
            navigate(destination)
            self.assertEqual(FakeStreamlit.session_state["active_section"], section)
            self.assertEqual(
                FakeStreamlit.session_state["site_section_mobile"],
                "Security Scanner",
            )
            self.assertEqual(
                FakeStreamlit.session_state[namespace["_section_page_key"](section)],
                "previous",
            )
            apply_pending()
            self.assertEqual(
                FakeStreamlit.session_state[namespace["_section_page_key"](section)],
                page,
            )

        with self.assertRaises(ValueError):
            navigate("Unknown destination")

    def test_navigation_defers_widget_state_changes_until_before_widget_creation(self):
        navigate_source = ast.get_source_segment(APP_SOURCE, function_node("navigate_to"))
        apply_source = ast.get_source_segment(APP_SOURCE, function_node("_apply_pending_navigation"))
        self.assertNotIn("st.session_state[_section_page_key(", navigate_source)
        self.assertIn("st.session_state.pop(\"_pending_navigation\"", apply_source)
        self.assertIn("st.session_state[_section_page_key(target_section)] = target_page", apply_source)
        self.assertIn("_apply_pending_navigation()\nsection =", APP_SOURCE)

    def test_dashboard_contains_health_alert_coverage_and_action_panels(self):
        home_source = ast.get_source_segment(APP_SOURCE, function_node("show_home"))
        for required in (
            "Saved alerts",
            "Files scanned",
            "Protection status",
            "Recent scans",
            "Quick scan actions",
            "Recent monitor alerts",
            "Monitoring activity",
            "Recent monitor alerts",
        ):
            self.assertIn(required, home_source)
        self.assertIn("_render_alert_collection", home_source)
        self.assertIn("load_background_alerts", home_source)
        self.assertIn("load_scan_history", home_source)

    def test_demo_tools_are_separate_and_collapsed(self):
        source = ast.get_source_segment(APP_SOURCE, function_node("_render_synthetic_event_demo"))
        self.assertIn('st.expander("Demo Tools · Synthetic events", expanded=False)', source)

    def test_theme_uses_requested_palette_and_mobile_navigation(self):
        css = UI_MODULE.DARK_THEME_CSS
        for color in ("#080D19", "#101827", "#151F31", "#27344A", "#8B5CF6", "#3B82F6", "#F1F5F9", "#94A3B8"):
            self.assertIn(color, css)
        self.assertIn("@media (max-width:800px)", css)
        self.assertIn(".st-key-aegis_mobile_nav { display:block; }", css)
        self.assertIn(".st-key-aegis_desktop_nav .stButton > button", css)
        self.assertIn('.st-key-aegis_top_nav [data-testid="stColumn"] { min-width:140px; }', css)
        self.assertIn('.st-key-aegis_nav_actions [data-testid="stColumn"]', css)
        self.assertNotIn(".st-key-aegis_desktop_nav div[role=\"radiogroup\"]", css)
        self.assertIn("[data-testid=\"stSidebar\"]", css)


if __name__ == "__main__":
    unittest.main()
