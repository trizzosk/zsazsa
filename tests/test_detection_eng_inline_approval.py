"""Inline detection request approval opens from the board and refreshes its state.

    python -m unittest tests.test_detection_eng_inline_approval
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bs4 import BeautifulSoup
from pymisp import MISPEvent

import config
from webapp import audit, collection_cache, create_app, job_store, misp_session, misp_store
from webapp.routes import detection_eng


UUID = "8261112b-619c-4ee0-9409-c898df74520c"
BASE = "/products/detection-eng"


class InlineApproval(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        for patch in (
            mock.patch.object(config, "DB_FILE", str(Path(tmp) / "test.db")),
            mock.patch.object(config, "LOG_FILE", str(Path(tmp) / "test.log")),
            mock.patch.object(config, "MISP_SESSION_COOKIE_NAME", "MISP-test", create=True),
            mock.patch.object(config, "MISP_SESSION_REDIRECT_TO_LOGIN", False),
            mock.patch("webapp._setup_file_logging"),
            mock.patch.object(collection_cache, "start_worker"),
            mock.patch.object(job_store, "_command", return_value=None),
            mock.patch.object(audit, "record"),
        ):
            self.enterContext(patch)
        event = MISPEvent()
        event.uuid = UUID
        event.date = "2026-10-26"
        self.der = misp_store._der_ns(event)
        self.der.der_id = "DER-00042"
        self.der.title = "Detect lateral movement"
        self.der.audience = "SOC"
        self.der.review_state = misp_store.DER_REVIEW_PENDING
        self.enterContext(mock.patch.object(misp_store, "list_ders", side_effect=lambda: [self.der]))
        self.enterContext(mock.patch.object(misp_store, "get_der", return_value=self.der))
        self.publish = self.enterContext(mock.patch.object(misp_store, "publish_der", return_value=True))
        self.deliver = self.enterContext(mock.patch.object(detection_eng, "_start_der_delivery"))
        self.can_publish = self.enterContext(
            mock.patch.object(misp_session, "current_user_can_publish", return_value=True))
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-token"

    def page(self):
        response = self.client.get(BASE + "/", headers={"X-Forwarded-Prefix": "/zsazsa"})
        self.assertEqual(response.status_code, 200)
        return BeautifulSoup(response.data, "html.parser")

    def approve(self, **data):
        return self.client.post(
            f"{BASE}/{UUID}/approve", headers={"X-Forwarded-Prefix": "/zsazsa"},
            data={"csrf_token": "test-token", "return_to": "review", **data},
        )

    def test_approve_first_opens_the_matching_preview_with_an_inline_form(self):
        page = self.page()
        button = page.select_one(".approval-open")
        self.assertIsNotNone(button)
        self.assertEqual(button.name, "button")
        self.assertEqual(button["aria-controls"], f"der-preview-{UUID}")
        row = page.find(id=button["aria-controls"])
        self.assertIsNone(page.select_one(".preview-toggle-btn"))
        form = row.select_one(".inline-approval-form")
        self.assertEqual(form["action"], f"/zsazsa{BASE}/{UUID}/approve")
        self.assertEqual(form.select_one('[name="return_to"]')["value"], "review")
        self.assertIsNone(form.select_one('button[type="submit"]').get("disabled"))
        self.assertEqual(form.parent, row.select_one("[data-recipients-url]").parent)

    def test_approval_refreshes_the_list_and_unlocks_the_kanban_card(self):
        def publish(_uuid):
            self.der.review_state = misp_store.DER_REVIEW_APPROVED
            return True

        self.publish.side_effect = publish
        response = self.approve()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/zsazsa" + BASE + "/")
        self.publish.assert_called_once_with(UUID)
        self.deliver.assert_called_once_with("DER-00042", UUID, "publish")
        page = self.page()
        self.assertEqual(page.select_one(".kanban-card")["draggable"], "true")
        self.assertIsNotNone(page.select_one(".kanban-card-icon .fa-check-circle"))
        self.assertIsNone(page.select_one(".approval-open"))
        self.assertIsNone(page.select_one(".inline-approval-form"))
        preview = page.select_one(".preview-toggle-btn")
        self.assertIsNotNone(preview)
        self.assertIn("fa-fw", preview.select_one("i")["class"])

    def test_drafts_can_also_be_reviewed_inline(self):
        self.der.review_state = misp_store.DER_REVIEW_DRAFT
        self.assertIsNotNone(self.page().select_one(".inline-approval-form"))
        self.assertEqual(self.approve().location, "/zsazsa" + BASE + "/")
        self.publish.assert_called_once_with(UUID)

    def test_resubmitting_approval_does_not_notify_again(self):
        self.der.review_state = misp_store.DER_REVIEW_APPROVED
        self.assertEqual(self.approve().location, "/zsazsa" + BASE + "/")
        self.publish.assert_not_called()
        self.deliver.assert_not_called()

    def test_older_unapproved_requests_outside_pending_still_open_inline(self):
        for status in misp_store.DER_STATUSES:
            with self.subTest(status=status):
                self.der.status = status
                page = self.page()
                self.assertIsNotNone(page.select_one(".approval-open"))
                self.assertIsNone(page.select_one(".preview-toggle-btn"))
                self.assertIsNotNone(page.select_one(".inline-approval-form"))

    def test_publish_rights_are_required_in_the_form_and_route(self):
        self.can_publish.return_value = False
        form = self.page().select_one(".inline-approval-form")
        self.assertIsNotNone(form)
        self.assertIsNotNone(form.select_one('button[type="submit"]').get("disabled"))
        self.assertEqual(self.approve().location, "/zsazsa" + BASE + "/")
        self.publish.assert_not_called()
        self.deliver.assert_not_called()

    def test_missing_audience_disables_approval_and_is_refused(self):
        for audience in ("", "   "):
            with self.subTest(audience=audience):
                self.der.audience = audience
                form = self.page().select_one(".inline-approval-form")
                self.assertIsNotNone(form.select_one('button[type="submit"]').get("disabled"))
                self.assertEqual(self.approve().location, "/zsazsa" + BASE + "/")
        self.publish.assert_not_called()
        self.deliver.assert_not_called()

    def test_failed_approval_returns_to_the_list_with_a_warning(self):
        self.publish.side_effect = RuntimeError("MISP unavailable")
        self.assertEqual(self.approve().location, "/zsazsa" + BASE + "/")
        self.deliver.assert_not_called()
        with self.client.session_transaction() as session:
            self.assertTrue(any("MISP unavailable" in text for _category, text in session["_flashes"]))

    def test_detail_approval_still_returns_to_detail_and_ignores_untrusted_return_urls(self):
        response = self.approve(return_to="https://example.org")
        self.assertEqual(response.location, f"/zsazsa{BASE}/{UUID}")

    def test_approval_still_requires_csrf(self):
        response = self.client.post(f"{BASE}/{UUID}/approve", data={"return_to": "review"})
        self.assertEqual(response.status_code, 403)
        self.publish.assert_not_called()


if __name__ == "__main__":
    unittest.main()
