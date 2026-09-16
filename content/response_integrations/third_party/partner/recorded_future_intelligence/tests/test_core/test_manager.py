############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for `RecordedFutureManager`.

The manager is the only thing in the integration that talks to Recorded
Future, so these tests drive it against the in-memory API rather than mocking
psengine: a request the manager gets wrong reaches a route that does not serve
it, and a payload it gets wrong fails psengine's own validation. Assertions
are split between what the manager returned and what it sent, which
`script_session.request_history` records.
"""

from __future__ import annotations

import base64
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from recorded_future_intelligence.core.constants import (
    CI_DETECTION_TYPE,
    CI_INCIDENT_TYPE,
    PING_IP,
    SCREENSHOT_B64_BUDGET,
)
from recorded_future_intelligence.core.exceptions import (
    RecordedFutureManagerError,
    RecordedFutureNotFoundError,
)
from recorded_future_intelligence.core.RecordedFutureManager import RecordedFutureManager
from recorded_future_intelligence.tests.common import (
    make_alert_rule,
    make_classic_alert,
    make_enrichment_record,
    make_evidence,
    make_hash_report,
    make_playbook_alert,
    make_sandbox_flow,
    make_sandbox_signature,
    make_screenshot,
    make_soar_evidence,
    make_soar_record,
)
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.core.session import RecordedFutureSession, request_body

API_URL = "https://api.recordedfuture.com"
API_KEY = "0123456789abcdef0123456789abcdef"

CASE_ID = 4242
CASE_TITLE = "Suspicious outbound traffic"
CASE_CREATION_TIME = 1_767_315_845_000


@pytest.fixture
def siemplify() -> MagicMock:
    """Provide the SOAR side of the manager: a case, a logger and entity writes."""
    siemplify = MagicMock()
    siemplify.case = SimpleNamespace(
        identifier=CASE_ID,
        title=CASE_TITLE,
        creation_time=CASE_CREATION_TIME,
    )
    siemplify.get_cases_by_ticket_id.return_value = []
    return siemplify


@pytest.fixture
def manager(siemplify: MagicMock) -> RecordedFutureManager:
    """Build a manager against the in-memory API.

    The real `__init__` runs, so psengine's managers are constructed and
    configured exactly as they are in production.
    """
    return RecordedFutureManager(
        api_url=API_URL,
        api_key=API_KEY,
        verify_ssl=False,
        siemplify=siemplify,
    )


def requested_fields(session: RecordedFutureSession) -> list[str]:
    """Return the `fields` an enrichment lookup asked the API for.

    Args:
        session: The session the manager made its requests through.

    Returns:
        The requested field names.

    """
    lookups = [
        record
        for record in session.request_history
        if record.request.url.path.startswith("/v2/") and not record.request.url.path.startswith("/v2/alert")
    ]
    return lookups[-1].request.kwargs["params"]["fields"].split(",")


class TestEnrichEntity:
    def test_returns_entity_with_risk(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_enrichment(
            "ip",
            "1.1.1.1",
            make_enrichment_record(
                "1.1.1.1",
                "ip",
                score=95,
                evidence=[make_evidence("Current C&C Server")],
            ),
        )

        entity = manager.enrich_entity(
            entity_name="1.1.1.1",
            entity_type="ip",
            include_links=False,
            collective_insights_enabled=False,
        )

        assert entity.score == 95  # noqa: PLR2004
        assert entity.riskString == "1/70"
        assert entity.rule_names == ["Current C&C Server"]
        assert entity.intelCard is not None

    def test_requests_location_for_an_ip(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
        script_session: RecordedFutureSession,
    ) -> None:
        recorded_future.set_enrichment(
            "ip",
            "1.1.1.1",
            make_enrichment_record("1.1.1.1", "ip"),
        )

        manager.enrich_entity(
            entity_name="1.1.1.1",
            entity_type="ip",
            include_links=False,
            collective_insights_enabled=False,
        )

        fields = requested_fields(script_session)
        assert "location" in fields
        assert "intelCard" in fields
        assert "hashAlgorithm" not in fields
        assert "links" not in fields

    def test_requests_hash_algorithm_for_a_hash(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
        script_session: RecordedFutureSession,
    ) -> None:
        sha256 = "a" * 64
        recorded_future.set_enrichment(
            "hash",
            sha256,
            make_enrichment_record(sha256, "hash", hashAlgorithm="SHA-256"),
        )

        manager.enrich_entity(
            entity_name=sha256,
            entity_type="hash",
            include_links=False,
            collective_insights_enabled=False,
        )

        assert "hashAlgorithm" in requested_fields(script_session)

    def test_requests_links_when_asked(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
        script_session: RecordedFutureSession,
    ) -> None:
        recorded_future.set_enrichment(
            "domain",
            "bad-example.com",
            make_enrichment_record("bad-example.com", "domain"),
        )

        manager.enrich_entity(
            entity_name="bad-example.com",
            entity_type="domain",
            include_links=True,
            collective_insights_enabled=False,
        )

        assert "links" in requested_fields(script_session)

    def test_raises_not_found_for_an_unknown_entity(
        self,
        manager: RecordedFutureManager,
    ) -> None:
        with pytest.raises(RecordedFutureNotFoundError):
            manager.enrich_entity(
                entity_name="8.8.4.4",
                entity_type="ip",
                include_links=False,
                collective_insights_enabled=False,
            )

    def test_submits_a_collective_insights_detection(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_enrichment(
            "ip",
            "1.1.1.1",
            make_enrichment_record("1.1.1.1", "ip", score=95),
        )

        manager.enrich_entity(
            entity_name="1.1.1.1",
            entity_type="ip",
            include_links=False,
            collective_insights_enabled=True,
        )

        assert len(recorded_future.collective_insights) == 1
        submission = recorded_future.collective_insights[0]
        detection = submission["data"][0]
        assert detection["ioc"]["value"] == "1.1.1.1"
        assert detection["ioc"]["type"] == "ip"
        assert detection["detection"]["type"] == CI_DETECTION_TYPE
        assert detection["detection"]["name"] == CASE_TITLE
        assert detection["incident"]["id"] == str(CASE_ID)
        assert detection["incident"]["type"] == CI_INCIDENT_TYPE

    def test_does_not_submit_a_detection_when_disabled(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_enrichment(
            "ip",
            "1.1.1.1",
            make_enrichment_record("1.1.1.1", "ip"),
        )

        manager.enrich_entity(
            entity_name="1.1.1.1",
            entity_type="ip",
            include_links=False,
            collective_insights_enabled=False,
        )

        assert recorded_future.collective_insights == []

    def test_survives_a_collective_insights_outage(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
        siemplify: MagicMock,
    ) -> None:
        """A failed detection submission must cost the submission, not the enrichment."""
        recorded_future.set_enrichment(
            "ip",
            "1.1.1.1",
            make_enrichment_record("1.1.1.1", "ip", score=95),
        )
        recorded_future.collective_insights_available = False

        entity = manager.enrich_entity(
            entity_name="1.1.1.1",
            entity_type="ip",
            include_links=False,
            collective_insights_enabled=True,
        )

        assert entity.score == 95  # noqa: PLR2004
        assert recorded_future.collective_insights == []
        siemplify.LOGGER.error.assert_called()

    def test_escapes_a_case_it_cannot_build_an_insight_from(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
        siemplify: MagicMock,
    ) -> None:
        """A malformed case does take the enrichment down, unlike an API failure.

        `_create_ci_insight` reads `case.creation_time` before psengine sees
        it, and the manager guards only `ValidationError` and
        `CollectiveInsightsError`, so the `TypeError` escapes. Asserted as it
        behaves rather than as it arguably should: worth knowing that the
        Collective Insights guard does not cover this half.
        """
        recorded_future.set_enrichment(
            "ip",
            "1.1.1.1",
            make_enrichment_record("1.1.1.1", "ip", score=95),
        )
        siemplify.case = SimpleNamespace(identifier=CASE_ID, title=CASE_TITLE, creation_time=None)

        with pytest.raises(TypeError):
            manager.enrich_entity(
                entity_name="1.1.1.1",
                entity_type="ip",
                include_links=False,
                collective_insights_enabled=True,
            )


class TestEnrichSoar:
    def test_returns_every_seeded_entity(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_soar_enrichment(
            "ip",
            "1.1.1.1",
            make_soar_record(
                "1.1.1.1",
                "IpAddress",
                score=95,
                evidence={"recentValidatedCnc": make_soar_evidence("Validated C&C Server")},
            ),
        )
        recorded_future.set_soar_enrichment(
            "domain",
            "bad-example.com",
            make_soar_record("bad-example.com", "InternetDomainName", score=42),
        )

        entities = manager.enrich_soar(
            entities={"ip": ["1.1.1.1"], "domain": ["bad-example.com"]},
            collective_insights_enabled=False,
        )

        assert [entity.score for entity in entities] == [95, 42]
        assert entities[0].rule_names == ["Validated C&C Server"]

    def test_omits_an_entity_the_api_holds_nothing_on(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_soar_enrichment(
            "ip",
            "1.1.1.1",
            make_soar_record("1.1.1.1", "IpAddress", score=95),
        )

        entities = manager.enrich_soar(
            entities={"ip": ["1.1.1.1", "8.8.4.4"]},
            collective_insights_enabled=False,
        )

        assert len(entities) == 1

    def test_raises_not_found_when_nothing_comes_back(
        self,
        manager: RecordedFutureManager,
    ) -> None:
        with pytest.raises(RecordedFutureNotFoundError):
            manager.enrich_soar(
                entities={"ip": ["8.8.4.4"]},
                collective_insights_enabled=False,
            )

    def test_raises_manager_error_with_no_entities(
        self,
        manager: RecordedFutureManager,
    ) -> None:
        with pytest.raises(RecordedFutureManagerError, match="No entities found to enrich"):
            manager.enrich_soar(entities={}, collective_insights_enabled=False)

    def test_submits_one_detection_per_entity(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_soar_enrichment(
            "ip",
            "1.1.1.1",
            make_soar_record("1.1.1.1", "IpAddress", score=95),
        )
        recorded_future.set_soar_enrichment(
            "hash",
            "a" * 64,
            make_soar_record("a" * 64, "Hash", score=80),
        )

        manager.enrich_soar(
            entities={"ip": ["1.1.1.1"], "hash_": ["a" * 64]},
            collective_insights_enabled=True,
        )

        detections = recorded_future.collective_insights[0]["data"]
        assert {detection["ioc"]["type"] for detection in detections} == {"ip", "hash"}


class TestEnrichHashSample:
    def test_returns_a_found_report(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        sha256 = "a" * 64
        recorded_future.set_hash_report(
            sha256,
            [
                make_hash_report(
                    sha256,
                    score=8,
                    flows=[make_sandbox_flow("2.2.2.2", dst_port=8080)],
                    signatures=[make_sandbox_signature("Packed binary")],
                ),
            ],
        )

        report = manager.enrich_hash_sample(sha256=sha256, my_enterprise=False)

        assert report.found is True
        assert report.id == sha256
        summary = report.reports_summary[0]
        assert summary["score"] == 8  # noqa: PLR2004
        assert summary["net_flows"] == [
            {"dst_ip": "2.2.2.2", "dst_port": 8080, "layer_7": "tls", "proto": "tcp"},
        ]
        assert summary["signatures"][0]["name"] == "Packed binary"

    def test_reports_not_found_for_an_unknown_sample(
        self,
        manager: RecordedFutureManager,
    ) -> None:
        sha256 = "b" * 64

        report = manager.enrich_hash_sample(sha256=sha256, my_enterprise=False)

        assert report.found is False
        assert report.id == sha256
        assert report.reports_summary == []

    def test_drops_a_flow_with_no_destination(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        sha256 = "c" * 64
        recorded_future.set_hash_report(
            sha256,
            [
                make_hash_report(
                    sha256,
                    flows=[make_sandbox_flow("2.2.2.2"), {"dst_port": 53, "proto": "udp"}],
                ),
            ],
        )

        report = manager.enrich_hash_sample(sha256=sha256, my_enterprise=False)

        assert [flow["dst_ip"] for flow in report.reports_summary[0]["net_flows"]] == ["2.2.2.2"]

    def test_drops_a_signature_with_no_description(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        sha256 = "d" * 64
        recorded_future.set_hash_report(
            sha256,
            [
                make_hash_report(
                    sha256,
                    signatures=[
                        make_sandbox_signature("Described"),
                        # Built inline rather than through the factory: the
                        # point of the case is the absent `desc` key.
                        {"name": "Undescribed", "score": 1},
                    ],
                ),
            ],
        )

        report = manager.enrich_hash_sample(sha256=sha256, my_enterprise=False)

        assert [sig["name"] for sig in report.reports_summary[0]["signatures"]] == ["Described"]

    def test_forwards_the_enterprise_filter_and_dates(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
        script_session: RecordedFutureSession,
    ) -> None:
        sha256 = "e" * 64
        recorded_future.set_hash_report(sha256, [make_hash_report(sha256)])

        manager.enrich_hash_sample(
            sha256=sha256,
            my_enterprise=True,
            start_date="2026-01-01",
            end_date="2026-02-01",
        )

        payload = request_body(script_session.request_history[-1].request)
        assert payload["my_enterprise"] is True
        assert payload["start_date"] == "2026-01-01"
        assert payload["end_date"] == "2026-02-01"
        assert payload["sha256"] == sha256


class TestClassicAlerts:
    def test_fetches_one_alert(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_classic_alert(
            "alert-1",
            make_classic_alert("alert-1", title="Typosquat detected"),
        )

        details = manager.get_information_about_alert("alert-1")

        assert details.raw_data["id"] == "alert-1"
        assert details.raw_data["title"] == "Typosquat detected"
        assert details.raw_data["rule"]["name"] == "Typosquat rule"
        assert "recordedfuture.com" in details.alert_url

    def test_raises_manager_error_for_an_unknown_alert(
        self,
        manager: RecordedFutureManager,
    ) -> None:
        with pytest.raises(RecordedFutureManagerError, match="Unable to lookup or parse"):
            manager.get_information_about_alert("alert-missing")

    def test_searches_the_configured_rules_and_statuses(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.add_alert_rule(make_alert_rule("rule-1", "Typosquat rule"))
        recorded_future.set_classic_alert(
            "alert-1",
            make_classic_alert("alert-1", status="New", rule_id="rule-1"),
        )
        recorded_future.set_classic_alert(
            "alert-2",
            make_classic_alert("alert-2", status="Resolved", rule_id="rule-1"),
        )

        alerts = manager.get_alerts(
            existing_ids=[],
            start_timestamp=1_767_315_845_000,
            severity="High",
            extract_all_entities=False,
            fetch_statuses=["New"],
        )

        assert [alert.id for alert in alerts] == ["alert-1"]
        assert alerts[0].severity == "High"
        assert alerts[0].rule_name == "Typosquat rule"

    def test_skips_alerts_it_has_already_seen(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.add_alert_rule(make_alert_rule("rule-1", "Typosquat rule"))
        for alert_id in ("alert-1", "alert-2"):
            recorded_future.set_classic_alert(
                alert_id,
                make_classic_alert(alert_id, status="New", rule_id="rule-1"),
            )

        alerts = manager.get_alerts(
            existing_ids=["alert-1"],
            start_timestamp=1_767_315_845_000,
            severity="High",
            extract_all_entities=False,
            fetch_statuses=["New"],
        )

        assert [alert.id for alert in alerts] == ["alert-2"]

    def test_honours_the_limit(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.add_alert_rule(make_alert_rule("rule-1", "Typosquat rule"))
        for index in range(3):
            alert_id = f"alert-{index}"
            recorded_future.set_classic_alert(
                alert_id,
                make_classic_alert(alert_id, status="New", rule_id="rule-1"),
            )

        alerts = manager.get_alerts(
            existing_ids=[],
            start_timestamp=1_767_315_845_000,
            severity="High",
            extract_all_entities=False,
            limit=2,
            fetch_statuses=["New"],
        )

        assert len(alerts) == 2  # noqa: PLR2004

    def test_restricts_the_search_to_a_named_rule(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
        script_session: RecordedFutureSession,
    ) -> None:
        recorded_future.add_alert_rule(make_alert_rule("rule-1", "Typosquat rule"))
        recorded_future.add_alert_rule(make_alert_rule("rule-2", "Leaked credentials"))
        recorded_future.set_classic_alert(
            "alert-1",
            make_classic_alert("alert-1", status="New", rule_id="rule-1"),
        )
        recorded_future.set_classic_alert(
            "alert-2",
            make_classic_alert("alert-2", status="New", rule_id="rule-2"),
        )

        alerts = manager.get_alerts(
            existing_ids=[],
            start_timestamp=1_767_315_845_000,
            severity="High",
            extract_all_entities=False,
            rules=["Typosquat"],
            fetch_statuses=["New"],
        )

        assert [alert.id for alert in alerts] == ["alert-1"]
        searched_rules = {
            record.request.kwargs["params"].get("alertRule")
            for record in script_session.request_history
            if record.request.url.path == "/v3/alerts/"
        }
        assert searched_rules == {"rule-1"}

    def test_searches_every_rule_when_the_name_matches_none(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        """A rule filter that matches no rule widens the search rather than narrowing it.

        `fetch_rules` returns nothing, and psengine reads an empty `rule_id`
        list as "no rule filter", so the search runs unrestricted. A connector
        configured with a misspelled rule name therefore ingests every alert
        instead of none - worth knowing before trusting the rule filter.
        """
        recorded_future.add_alert_rule(make_alert_rule("rule-1", "Typosquat rule"))
        recorded_future.set_classic_alert(
            "alert-1",
            make_classic_alert("alert-1", status="New", rule_id="rule-1"),
        )

        alerts = manager.get_alerts(
            existing_ids=[],
            start_timestamp=1_767_315_845_000,
            severity="High",
            extract_all_entities=False,
            rules=["Nonexistent rule"],
            fetch_statuses=["New"],
        )

        assert [alert.id for alert in alerts] == ["alert-1"]

    def test_updates_an_alert(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        result = manager.update_alert(
            alert_id="alert-1",
            status="Resolved",
            assignee="uhash:analyst",
            note="Handled in SOAR",
        )

        assert result == {"success": {"id": "alert-1"}}
        assert recorded_future.alert_updates == [
            {
                "id": "alert-1",
                "assignee": "uhash:analyst",
                "note": "Handled in SOAR",
                "statusInPortal": "Resolved",
            },
        ]

    def test_omits_the_fields_it_was_not_given(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        manager.update_alert(alert_id="alert-1", status="Resolved", assignee=None, note=None)

        assert recorded_future.alert_updates == [{"id": "alert-1", "statusInPortal": "Resolved"}]

    def test_rejects_an_update_with_no_alert_id(
        self,
        manager: RecordedFutureManager,
    ) -> None:
        with pytest.raises(RecordedFutureManagerError, match="Alert id should be present"):
            manager.update_alert(alert_id="", status="Resolved", assignee=None, note=None)


class TestAnalystNotes:
    def test_publishes_a_note(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        note = manager.get_analyst_notes(
            title="SOAR triage",
            text="Investigated and closed.",
            topic="TXxxx1",
        )

        assert note.document_id == "note:published"
        assert recorded_future.published_notes[0]["attributes"]["title"] == "SOAR triage"
        assert recorded_future.published_notes[0]["attributes"]["text"] == ("Investigated and closed.")


class TestPlaybookAlerts:
    def test_fetches_alerts_by_category(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1", status="New", priority="High"),
        )

        alerts = manager.get_playbook_alerts(
            existing_ids=[],
            category=["domain_abuse"],
            statuses=["New"],
            priority=["High"],
            severity="High",
        )

        assert [alert.id for alert in alerts] == ["task:pa-1"]
        assert alerts[0].category == "domain_abuse"
        assert alerts[0].priority == "High"
        assert alerts[0].severity == "High"

    def test_filters_by_status(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1", status="New"),
        )
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-2",
            make_playbook_alert("task:pa-2", status="Resolved"),
        )

        alerts = manager.get_playbook_alerts(
            existing_ids=[],
            category=["domain_abuse"],
            statuses=["New"],
            priority=None,
            severity="High",
        )

        assert [alert.id for alert in alerts] == ["task:pa-1"]

    def test_skips_alerts_it_has_already_seen(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        for alert_id in ("task:pa-1", "task:pa-2"):
            recorded_future.set_playbook_alert(
                "domain_abuse",
                alert_id,
                make_playbook_alert(alert_id),
            )

        alerts = manager.get_playbook_alerts(
            existing_ids=["task:pa-1"],
            category=["domain_abuse"],
            statuses=None,
            priority=None,
            severity="High",
        )

        assert [alert.id for alert in alerts] == ["task:pa-2"]

    def test_fetches_one_alert(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1", entity_name="bad-example.com"),
        )

        alert = manager.get_pba_details("task:pa-1", "domain_abuse")

        assert alert.id == "task:pa-1"
        assert alert.title == "Domain Abuse - bad-example.com"
        assert alert.screenshots == {}

    def test_raises_manager_error_for_an_unknown_alert(
        self,
        manager: RecordedFutureManager,
    ) -> None:
        with pytest.raises(RecordedFutureManagerError, match="Unable to fetch Playbook Alert"):
            manager.get_pba_details("task:missing", "domain_abuse")

    def test_updates_an_alert(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1"),
        )

        result = manager.update_playbook_alert(
            alert_id="task:pa-1",
            category="domain_abuse",
            status="Resolved",
            assignee="uhash:analyst",
            log_entry="Closed in SOAR",
            priority="Informational",
        )

        assert result == {"success": {"id": "task:pa-1"}}
        assert recorded_future.playbook_alert_updates == [
            {
                "id": "task:pa-1",
                "priority": "Informational",
                "status": "Resolved",
                "assignee": "uhash:analyst",
                "log_entry": "Closed in SOAR",
            },
        ]

    def test_rejects_an_update_with_nothing_to_change(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        """An empty update is refused, but the refusal is not wrapped.

        psengine raises `ValueError`, which `update_playbook_alert` does not
        list among the exceptions it converts, so it escapes as-is rather than
        as a `RecordedFutureManagerError`. Asserted as it behaves; the
        important half is that nothing was sent.
        """
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1"),
        )

        with pytest.raises(ValueError, match="No update parameters were supplied"):
            manager.update_playbook_alert(alert_id="task:pa-1", category="domain_abuse")

        assert recorded_future.playbook_alert_updates == []


class TestRefreshPlaybookAlertCase:
    def test_adds_the_alert_entity_to_the_case(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
        siemplify: MagicMock,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert(
                "task:pa-1",
                entity_id="idn:bad-example.com",
                entity_name="bad-example.com",
            ),
        )

        manager.refresh_pba_case("task:pa-1", "domain_abuse")

        added = [call.kwargs["entity_identifier"] for call in siemplify.add_entity_to_case.mock_calls]
        assert "bad-example.com" in added

    def test_marks_a_risky_resolved_record_suspicious(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
        siemplify: MagicMock,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert(
                "task:pa-1",
                resolved_records=[
                    {"entity": "ip:9.9.9.9", "risk_score": 90, "record_type": "A"},
                    {"entity": "ip:8.8.8.8", "risk_score": 10, "record_type": "A"},
                ],
            ),
        )

        manager.refresh_pba_case("task:pa-1", "domain_abuse")

        suspicion = {
            call.kwargs["entity_identifier"]: call.kwargs["is_suspicous"]
            for call in siemplify.add_entity_to_case.mock_calls
        }
        assert suspicion["9.9.9.9"] is True
        assert suspicion["8.8.8.8"] is False

    def test_skips_a_value_that_is_not_a_lightweight_entity(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
        siemplify: MagicMock,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1", entity_id="bad-example.com"),
        )

        manager.refresh_pba_case("task:pa-1", "domain_abuse")

        siemplify.add_entity_to_case.assert_not_called()
        siemplify.warn.assert_called_once()

    def test_attaches_linked_cases(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
        siemplify: MagicMock,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1"),
        )
        siemplify.get_cases_by_ticket_id.return_value = [11, 12]

        alert = manager.refresh_pba_case("task:pa-1", "domain_abuse")

        assert alert.linked_cases == [11, 12]

    def test_raises_manager_error_for_an_unknown_alert(
        self,
        manager: RecordedFutureManager,
    ) -> None:
        with pytest.raises(RecordedFutureManagerError, match="Unable to refresh Playbook Alert"):
            manager.refresh_pba_case("task:missing", "domain_abuse")


class TestFetchScreenshots:
    def test_returns_encoded_screenshots(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        png = b"\x89PNG\r\n\x1a\n" + b"pixels"
        recorded_future.set_screenshot("img-1", png)
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert(
                "task:pa-1",
                screenshots=[make_screenshot("img-1", "Landing page")],
            ),
        )

        alert = manager.refresh_pba_case("task:pa-1", "domain_abuse", fetch_screenshots=True)

        screenshot = alert.screenshots["img-1"]
        assert screenshot["description"] == "Landing page"
        assert screenshot["mime_type"] == "image/png"
        assert base64.b64decode(screenshot["image_b64"]) == png

    def test_skips_an_image_the_api_will_not_serve(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        """One unavailable image must not cost the other screenshots or the refresh."""
        recorded_future.set_screenshot("img-1", b"\x89PNG\r\n\x1a\nfirst")
        recorded_future.set_screenshot("img-2", b"\x89PNG\r\n\x1a\nsecond")
        recorded_future.unavailable_screenshots.add("img-1")
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert(
                "task:pa-1",
                screenshots=[make_screenshot("img-1"), make_screenshot("img-2")],
            ),
        )

        alert = manager.refresh_pba_case("task:pa-1", "domain_abuse", fetch_screenshots=True)

        assert list(alert.screenshots) == ["img-2"]

    def test_skips_an_image_that_would_blow_the_budget(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        """A later, smaller screenshot still fits once an oversized one is skipped."""
        oversized = b"\x89PNG\r\n\x1a\n" + b"x" * SCREENSHOT_B64_BUDGET
        recorded_future.set_screenshot("img-big", oversized)
        recorded_future.set_screenshot("img-small", b"\x89PNG\r\n\x1a\nsmall")
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert(
                "task:pa-1",
                screenshots=[make_screenshot("img-big"), make_screenshot("img-small")],
            ),
        )

        alert = manager.refresh_pba_case("task:pa-1", "domain_abuse", fetch_screenshots=True)

        assert list(alert.screenshots) == ["img-small"]

    def test_does_not_fetch_screenshots_unless_asked(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
        script_session: RecordedFutureSession,
    ) -> None:
        recorded_future.set_screenshot("img-1", b"\x89PNG\r\n\x1a\nfirst")
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1", screenshots=[make_screenshot("img-1")]),
        )

        manager.refresh_pba_case("task:pa-1", "domain_abuse")

        image_requests = [record for record in script_session.request_history if "/image/" in record.request.url.path]
        assert image_requests == []


class TestTestConnectivity:
    def test_reports_success_when_the_ping_entity_enriches(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_enrichment("ip", PING_IP, make_enrichment_record(PING_IP, "ip"))

        assert manager.test_connectivity() is not False

    def test_reports_failure_when_the_api_rejects_the_token(
        self,
        manager: RecordedFutureManager,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.authorized = False

        assert manager.test_connectivity() is False
