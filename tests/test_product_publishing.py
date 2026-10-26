"""A product published in zsazsa has its MISP event published as well.

A threat actor profile was only marked published on its object, and its MISP
event stayed unpublished. Feedback on any published product adds a report to
its event, which MISP answers by unpublishing it, and nothing published it
again. A publish MISP refused was only logged, or not at all when MISP answered
with an error instead of raising, so the product looked published while its
event was not. Now the refusal comes back to the caller, which tells the
analyst, and the delivery still goes out.

MISP is a specced stand-in.

    python -m unittest tests.test_product_publishing
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from pymisp import PyMISP

from webapp import misp_store

UUID = "5f0c7a3e-1b2c-4d5e-8f90-a1b2c3d4e5f6"


def _misp(reply=None):
    misp = mock.create_autospec(PyMISP, instance=True)
    misp.publish.return_value = reply if reply is not None else {"saved": True, "success": True}
    return misp


class PublishEvent(unittest.TestCase):
    def test_published_without_misp_s_alert_mail(self):
        misp = _misp()
        self.assertTrue(misp_store.publish_event(misp, UUID, "FIA-00042"))
        misp.publish.assert_called_once_with(UUID, alert=False)

    def test_an_error_answer_is_a_refusal(self):
        """MISP answers a refusal rather than raising, and it went unnoticed."""
        with self.assertLogs(misp_store.logger, "WARNING") as logs:
            self.assertFalse(misp_store.publish_event(_misp({"errors": (403, "Not allowed")}), UUID, "FIA-00042"))
        self.assertIn("FIA-00042", logs.output[0])

    def test_a_server_that_cannot_be_reached_is_one_too(self):
        misp = _misp()
        misp.publish.side_effect = ConnectionError("MISP down")
        with self.assertLogs(misp_store.logger, "WARNING"):
            self.assertFalse(misp_store.publish_event(misp, UUID, "FIA-00042"))


class ThreatActorProfile(unittest.TestCase):
    def test_publishing_it_publishes_its_event(self):
        misp = _misp()
        tap = SimpleNamespace(**dict(dict.fromkeys(misp_store._TAP_FIELDS, ""), tap_id="TAP-00007"))
        with mock.patch.object(misp_store, "_misp", return_value=misp), \
             mock.patch.object(misp_store, "get_threat_actor_profile", return_value=tap), \
             mock.patch.object(misp_store, "update_threat_actor_profile") as update:
            self.assertTrue(misp_store.publish_threat_actor_profile(UUID))
        self.assertEqual(update.call_args.args[1]["status"], "Published")
        misp.publish.assert_called_once_with(UUID, alert=False)


class Feedback(unittest.TestCase):
    def feedback(self, published, reply=None):
        misp = _misp(reply)
        misp.add_event_report.return_value = {"EventReport": {}}
        with mock.patch.object(misp_store, "_misp", return_value=misp):
            result = misp_store.add_product_feedback(UUID, "analyst", "useful", "Spot on.", published=published)
        return result, misp

    def test_a_published_product_is_published_again(self):
        """MISP unpublishes an event when a report is added to it."""
        result, misp = self.feedback(published=True)
        self.assertTrue(result)
        misp.publish.assert_called_once_with(UUID, alert=False)

    def test_a_draft_stays_unpublished(self):
        result, misp = self.feedback(published=False)
        self.assertTrue(result)
        misp.publish.assert_not_called()

    def test_a_refusal_is_reported(self):
        with self.assertLogs(misp_store.logger, "WARNING"):
            result, _misp_used = self.feedback(published=True, reply={"errors": (403, "Not allowed")})
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
