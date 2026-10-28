"""The Collection coverage card on a PIR counts what its scope preview lists.

The card searched the PIR's focus points, and the preview every scope value.
ATT&CK techniques are scope values but not focus points, so an event that
matched only on a technique was in the preview and not on the card: the demo
PIR showed 23 events in one and 20 in the other. The cache is stubbed and the
pages' templates are not rendered.

    python -m unittest tests.test_pir_collection_coverage
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from flask import Flask
from pymisp import MISPEvent

from webapp import collection_cache, misp_store
from webapp.routes import requirements

UUID = "8006520f-a3a7-4f2d-b2e6-c94c79c7f2c4"


def _pir():
    event = MISPEvent()
    event.uuid = UUID
    event.date = "2026-10-01"
    event.add_object(misp_store._pir_obj({
        "pir_id": "PIR-00003", "question": "Who takes over accounts?", "status": "Active",
        "geographic_scope": ["Belgium"], "mitre_attack_techniques": ["Valid Accounts - T1078"]}))
    pir = misp_store._pir_ns(event)
    # The form makes a focus point of every scope value but a technique.
    pir.focus_points = [SimpleNamespace(category="Geography", value="Belgium")]
    return pir


def _cached(uuid, info, tags):
    return {"uuid": uuid, "id": "1", "source_id": "scraper", "info": info, "date": "2026-10-24",
            "org": "", "orgc": "", "tags": tags, "galaxy_names": [], "vulnerability_ids": []}


class CoverageAndPreview(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.register_blueprint(requirements.bp)
        self.client = app.test_client()
        events = [_cached("a" * 36, "Phishing wave in Belgium", []),
                  _cached("b" * 36, "Data leak", ['misp-galaxy:mitre-attack-pattern="Valid Accounts - T1078"'])]
        galaxies = {name: mock.Mock(return_value=[]) for name in (
            "galaxy_geography", "galaxy_sectors", "galaxy_threat_actors", "galaxy_mitre_attack_patterns")}
        for patcher in (mock.patch.object(misp_store, "get_pir", return_value=_pir()),
                        mock.patch.object(misp_store, "list_stakeholders", return_value=[]),
                        mock.patch.multiple(misp_store, **galaxies),
                        mock.patch.object(collection_cache, "cached_source_ids", return_value=["scraper"]),
                        mock.patch.object(collection_cache, "get_events", return_value=events)):
            patcher.start()
            self.addCleanup(patcher.stop)
        render = mock.patch.object(requirements, "render_template", return_value="")
        self.render = render.start()
        self.addCleanup(render.stop)

    def context(self, path):
        self.assertEqual(self.client.get(path).status_code, 200)
        return self.render.call_args.kwargs

    def test_an_event_matching_only_a_technique_counts_on_the_card_too(self):
        preview = self.context(f"/pirs/{UUID}/scope/preview")["matches"]
        coverage = self.context(f"/pirs/{UUID}")["coverage"]
        self.assertEqual(len(preview), 2)
        self.assertEqual(coverage["recent_matches"], len(preview))


if __name__ == "__main__":
    unittest.main()
