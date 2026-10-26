"""Product-list feedback honours the application's reverse-proxy mount path.

    python -m unittest tests.test_product_feedback_urls
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup
from pymisp import MISPEvent

import config
from webapp import audit, collection_cache, create_app, misp_store


UUID = "8261112b-619c-4ee0-9409-c898df74520c"
PRODUCTS = (
    ("threat_actor_profile", "/products/threat-actor-profile", "list_threat_actor_profiles",
     "_tap_ns"),
    ("flash_intel", "/products/flash-intel", "list_fias", "_fia_ns"),
    ("vea", "/products/vea", "list_veas", "_vea_ns"),
    ("detection_eng", "/products/detection-eng", "list_ders", "_der_ns"),
    ("daily_briefing", "/briefing", "list_briefings", "_briefing_ns"),
)


class ProductFeedbackURLs(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        for patch in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db")),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log")),
            mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch("webapp._setup_file_logging"),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(audit, "record"),
        ):
            self.enterContext(patch)
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()

    def test_feedback_buttons_use_mounted_urls_and_the_modal_uses_the_button_url(self):
        for endpoint, path, list_name, factory in PRODUCTS:
            for prefix in ("", "/zsazsa"):
                with self.subTest(product=endpoint, prefix=prefix):
                    event = MISPEvent()
                    event.uuid = UUID
                    event.id = "42"
                    event.date = "2026-10-26"
                    event.info = "Example product"
                    product = getattr(misp_store, factory)(event)
                    with mock.patch.object(misp_store, list_name, return_value=[product]):
                        response = self.client.get(
                            path + "/", headers={"X-Forwarded-Prefix": prefix})
                    self.assertEqual(response.status_code, 200)
                    page = BeautifulSoup(response.data, "html.parser")
                    button = page.select_one(".feedback-btn")
                    self.assertIsNotNone(button)
                    self.assertEqual(button.get("data-action"), f"{prefix}{path}/{UUID}/feedback")
                    scripts = "\n".join(s.get_text() for s in page.find_all("script"))
                    source = "btn" if endpoint == "daily_briefing" else "trigger"
                    self.assertIn(
                        f"document.getElementById('feedback-form').action = {source}.dataset.action;",
                        scripts,
                    )

    def test_threat_actor_feedback_submits_and_redirects_with_the_mount_prefix(self):
        event = MISPEvent()
        event.uuid = UUID
        event.id = "42"
        event.date = "2026-10-26"
        tap = misp_store._tap_ns(event)
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"
        with mock.patch.object(misp_store, "get_threat_actor_profile", return_value=tap), \
             mock.patch.object(misp_store, "add_product_feedback", return_value=True) as add:
            response = self.client.post(
                f"/products/threat-actor-profile/{UUID}/feedback",
                headers={"X-Forwarded-Prefix": "/zsazsa"},
                data={"csrf_token": "test-token", "author": "Analyst",
                      "rating": "Useful", "comment": "Useful context"},
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, f"/zsazsa/products/threat-actor-profile/{UUID}")
        add.assert_called_once_with(UUID, "Analyst", "Useful", "Useful context",
                                    published=tap.published)


if __name__ == "__main__":
    unittest.main()
