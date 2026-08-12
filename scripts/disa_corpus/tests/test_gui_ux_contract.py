import re
import unittest
from html.parser import HTMLParser
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
FRONTEND = REPO / "crates" / "gui" / "frontend" / "scanner"


class _ElementCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class GuiUxContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = (FRONTEND / "index.html").read_text(encoding="utf-8")
        cls.styles = (FRONTEND / "styles.css").read_text(encoding="utf-8")
        cls.app = (FRONTEND / "app.js").read_text(encoding="utf-8")
        cls.scan = (FRONTEND / "scan.js").read_text(encoding="utf-8")
        cls.deliveries = (FRONTEND / "deliveries.js").read_text(encoding="utf-8")
        cls.content = (FRONTEND / "content.js").read_text(encoding="utf-8")
        cls.connection = (FRONTEND / "connection.js").read_text(encoding="utf-8")
        cls.api = (FRONTEND / "api.js").read_text(encoding="utf-8")
        cls.scanner_api = (
            REPO / "crates" / "gui" / "src" / "scanner_api.rs"
        ).read_text(encoding="utf-8")
        cls.stig_manager_client = (
            REPO
            / "crates"
            / "integrations"
            / "src"
            / "stig_manager"
            / "client.rs"
        ).read_text(encoding="utf-8")
        cls.html = _ElementCollector()
        cls.html.feed(cls.index)

    def _elements(self, tag):
        return [attrs for element_tag, attrs in self.html.elements if element_tag == tag]

    def test_served_shell_is_the_scanner_first_frontend(self):
        main = (REPO / "crates" / "gui" / "src" / "main.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn('#[folder = "frontend/scanner/"]', main)
        self.assertIn('src="app.js"', self.index)
        self.assertNotIn('src="../app.js"', self.index)

    def test_shell_navigation_is_exact_and_keyboard_accessible(self):
        skip = next(
            attrs for attrs in self._elements("a")
            if attrs.get("class") == "skip-link"
        )
        self.assertEqual(skip.get("href"), "#main")
        main = next(attrs for attrs in self._elements("main") if attrs.get("id") == "main")
        self.assertEqual(main.get("tabindex"), "-1")
        nav = next(attrs for attrs in self._elements("nav"))
        self.assertEqual(nav.get("aria-label"), "Primary navigation")
        links = [
            attrs for attrs in self._elements("a")
            if "nav-link" in attrs.get("class", "").split()
        ]
        self.assertEqual(
            [link.get("data-route") for link in links],
            ["scan", "deliveries", "content", "connection"],
        )
        self.assertEqual(sum(link.get("aria-current") == "page" for link in links), 1)

    def test_first_open_explains_the_product_boundary_and_two_paths(self):
        for text in (
            "Where should this run go?",
            "STIG Manager remains the system of record",
            "Connect to STIG Manager",
            "Run disconnected",
            "Use existing assets and assignments only",
            "Changed reviews use a selected-run handoff",
            "No local portfolio is created",
        ):
            self.assertIn(text, self.scan)

    def test_manager_duplicate_workspaces_are_absent(self):
        combined = "\n".join(
            [self.index, self.app, self.scan, self.deliveries, self.content, self.connection]
        )
        for retired in (
            "Run New Assessment",
            "Import Existing Results",
            "Add Asset",
            "Assign STIG",
            "Answer Files",
            "Global Findings",
            "Portfolio Report",
        ):
            self.assertNotIn(retired, combined)
        for retired_path in ("/answer-files", "/checklists", "/export/all-zip", "/assets/bulk"):
            self.assertNotIn(retired_path, combined)

    def test_scanner_api_cannot_manage_remote_assets_assignments_or_changed_reviews(self):
        routes = self.scanner_api.split("pub fn routes()", 1)[1].split(
            "#[derive(Serialize)]", 1
        )[0]
        self.assertIn(
            '"/stig-manager/collections/{collection_id}/assets",\n            get(list_assets)',
            routes,
        )
        self.assertIn(
            '"/stig-manager/collections/{collection_id}/assets/{asset_id}/assignments",\n            get(list_assignments)',
            routes,
        )
        self.assertNotRegex(
            routes,
            r'"/stig-manager/[^"\n]*(?:assets|assignments|reviews)[^"\n]*"\s*,\s*(?:post|put|delete)',
        )
        self.assertIn("conditional_review_writes: false", self.stig_manager_client)
        self.assertIn("#[cfg(test)]\n    fn with_mock_conditional_review_writes", self.stig_manager_client)
        self.assertEqual(
            self.stig_manager_client.count("self.conditional_review_writes = true;"),
            1,
        )
        self.assertIn("if !self.conditional_review_writes", self.stig_manager_client)
        self.assertIn("StigManagerError::ConditionalWriteUnsupported", self.stig_manager_client)

    def test_connected_flow_requires_existing_exact_remote_identity(self):
        for text in (
            "Select a collection",
            "Select an asset",
            "exact assigned STIG revision",
            "Manage assignments in STIG Manager",
            "No assets are available. Create and assign the asset in STIG Manager",
        ):
            self.assertIn(text, self.scan)

    def test_incomplete_evidence_and_experimental_profiles_fail_closed(self):
        self.assertIn("pilot_acknowledged: Boolean", self.scan)
        self.assertIn("experimental pilot run", self.scan)
        self.assertIn("Nothing was queued for delivery", self.scan)
        self.assertIn("Incomplete or ambiguous evidence is never delivered", self.deliveries)
        self.assertIn("collectionComplete === false", self.deliveries)

    def test_changed_remote_reviews_are_handoff_only(self):
        self.assertIn("&& !previewWarning", self.deliveries)
        self.assertIn("Download selected-run handoff", self.deliveries)
        self.assertIn("Confirm remote no-op", self.deliveries)
        self.assertIn("Recheck remote state", self.deliveries)
        self.assertNotIn("Deliver to STIG Manager", self.deliveries)

    def test_full_benchmark_denominators_are_visible(self):
        for contract in (
            "fullBenchmarkRules",
            "reviewedRules",
            "Full benchmark",
            "Outside profile",
            "Not a compliance score",
        ):
            self.assertIn(contract, self.deliveries + self.content)

    def test_secrets_are_ephemeral_and_downloads_are_authenticated(self):
        combined = self.app + self.api + self.scan + self.connection
        self.assertNotRegex(
            combined,
            r"(?:localStorage|sessionStorage)\.setItem\([^\n]*(?:token|password|secret|credential)",
        )
        self.assertIn("clearSensitiveInputs(passwordInput, keyPassphraseInput)", self.scan)
        self.assertIn("headers.set('X-Auth-Token', authToken)", self.api)
        self.assertIn("downloadHandoff(event.currentTarget, run.handoffUrl)", self.scan)
        self.assertNotRegex(self.api, r"[?&](?:token|auth)=")

    def test_retention_and_provenance_are_visible_read_only(self):
        for contract in (
            "Evidence and provenance",
            "Replay evidence",
            "expires",
            "purged",
            "Result hashes remain verifiable",
        ):
            self.assertIn(contract, self.deliveries)
        self.assertNotIn("method: 'PATCH'", self.deliveries)

    def test_responsive_and_reduced_motion_contracts_remain(self):
        compact = re.sub(r"\s+", " ", self.styles)
        self.assertIn(".table-scroll", self.styles)
        self.assertIn("overflow-x: auto", self.styles)
        self.assertIn("@media (max-width: 800px)", self.styles)
        self.assertIn("@media (prefers-reduced-motion: reduce)", self.styles)
        self.assertRegex(
            compact,
            r"@media \(max-width: 580px\) \{.*?\.primary-nav \{[^}]*display: grid",
        )


if __name__ == "__main__":
    unittest.main()
