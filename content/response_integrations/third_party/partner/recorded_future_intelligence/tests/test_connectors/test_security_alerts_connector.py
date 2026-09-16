############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the Classic Alerts Connector.

Fetching a classic alert takes three API calls - the rule catalogue, a search
per rule and status, then a fetch per alert ID - so these tests seed the rule
catalogue as well as the alerts, and a rule an alert points at but which is
absent from the catalogue is unreachable by design.
"""

from __future__ import annotations

import pytest
from integration_testing.platform.script_output import MockConnectorOutput
from integration_testing.set_meta import set_metadata

from recorded_future_intelligence.connectors import SecurityAlertsConnector
from recorded_future_intelligence.core.constants import (
    CLASSIC_ALERT_PRODUCT,
    SEVERITY_MAP,
)
from recorded_future_intelligence.tests.common import (
    make_alert_rule,
    make_classic_alert,
    make_classic_alert_hit,
)
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.test_connectors.common import (
    allowlist_context,
    classic_params,
)

RULE_ID = "rule-1"
RULE_NAME = "Typosquat rule"


def seed_alert(
    recorded_future: RecordedFuture,
    alert_id: str = "alert-1",
    status: str = "New",
    rule_id: str = RULE_ID,
    rule_name: str = RULE_NAME,
    with_hit: bool = True,
    **kwargs: object,
) -> None:
    """Seed one classic alert, and the catalogue rule needed to reach it.

    Args:
        recorded_future: The in-memory API to seed.
        alert_id: The Recorded Future alert ID.
        status: The alert's portal status.
        rule_id: The triggering rule's ID.
        rule_name: The triggering rule's name.
        with_hit: Whether to give the alert a hit, which is what becomes an
            event on the SecOps side.
        **kwargs: Passed through to `make_classic_alert`.

    """
    if not any(rule["id"] == rule_id for rule in recorded_future.alert_rules):
        recorded_future.add_alert_rule(make_alert_rule(rule_id, rule_name))

    recorded_future.set_classic_alert(
        alert_id,
        make_classic_alert(
            alert_id,
            status=status,
            rule_id=rule_id,
            rule_name=rule_name,
            hits=[make_classic_alert_hit(f"hit-{alert_id}")] if with_hit else [],
            **kwargs,
        ),
    )


def ticket_ids(output: MockConnectorOutput) -> list[str]:
    """Return the Recorded Future alert IDs the connector turned into cases.

    Args:
        output: The captured connector output.

    Returns:
        The ticket IDs, in the order the connector reported them.

    """
    return [alert.ticket_id for alert in output.results.json_output.alerts]


class TestFetching:
    @set_metadata(parameters=classic_params())
    def test_reports_a_new_alert(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future)

        SecurityAlertsConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["alert-1"]

    @set_metadata(parameters=classic_params())
    def test_reports_nothing_when_the_api_is_empty(
        self,
        connector_output: MockConnectorOutput,
    ) -> None:
        SecurityAlertsConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == []

    @set_metadata(parameters=classic_params(**{"Alert Statuses": "New"}))
    def test_filters_by_status(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future, alert_id="alert-new", status="New")
        seed_alert(recorded_future, alert_id="alert-resolved", status="Resolved")

        SecurityAlertsConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["alert-new"]

    @set_metadata(parameters=classic_params(**{"Alert Statuses": "New, Resolved"}))
    def test_accepts_several_statuses(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future, alert_id="alert-new", status="New")
        seed_alert(recorded_future, alert_id="alert-resolved", status="Resolved")

        SecurityAlertsConnector.main(is_test_run=False)

        assert sorted(ticket_ids(connector_output)) == ["alert-new", "alert-resolved"]

    @set_metadata(parameters=classic_params())
    def test_cannot_reach_an_alert_whose_rule_is_not_in_the_catalogue(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """The search runs per catalogued rule, so an uncatalogued one is invisible."""
        recorded_future.add_alert_rule(make_alert_rule(RULE_ID, RULE_NAME))
        recorded_future.set_classic_alert(
            "alert-orphan",
            make_classic_alert("alert-orphan", status="New", rule_id="rule-unknown"),
        )

        SecurityAlertsConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == []


class TestAllowlist:
    @set_metadata(
        parameters=classic_params(**{"Use whitelist as a blacklist": "false"}),
        input_context=allowlist_context([RULE_NAME]),
    )
    def test_an_allowlist_keeps_only_the_named_rule(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future, alert_id="alert-kept")
        seed_alert(
            recorded_future,
            alert_id="alert-dropped",
            rule_id="rule-2",
            rule_name="Leaked credentials",
        )

        SecurityAlertsConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["alert-kept"]

    @set_metadata(
        parameters=classic_params(**{"Use whitelist as a blacklist": "true"}),
        input_context=allowlist_context([RULE_NAME]),
    )
    def test_a_denylist_drops_the_named_rule(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future, alert_id="alert-dropped")
        seed_alert(
            recorded_future,
            alert_id="alert-kept",
            rule_id="rule-2",
            rule_name="Leaked credentials",
        )

        SecurityAlertsConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["alert-kept"]


class TestDeduplication:
    @set_metadata(parameters=classic_params())
    def test_does_not_report_the_same_alert_twice(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future)

        SecurityAlertsConnector.main(is_test_run=False)
        assert ticket_ids(connector_output) == ["alert-1"]

        connector_output.flush()
        SecurityAlertsConnector.main(is_test_run=False)
        assert ticket_ids(connector_output) == []

    @set_metadata(parameters=classic_params())
    def test_still_reports_an_alert_seen_only_in_a_test_run(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future)

        SecurityAlertsConnector.main(is_test_run=True)
        connector_output.flush()

        SecurityAlertsConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["alert-1"]


class TestLimits:
    @set_metadata(parameters=classic_params())
    def test_a_test_run_processes_one_alert(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        for index in range(3):
            seed_alert(recorded_future, alert_id=f"alert-{index}")

        SecurityAlertsConnector.main(is_test_run=True)

        assert len(ticket_ids(connector_output)) == 1

    @set_metadata(parameters=classic_params(**{"Max Alerts To Fetch": 2}))
    def test_honours_the_fetch_limit(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        for index in range(5):
            seed_alert(recorded_future, alert_id=f"alert-{index}")

        SecurityAlertsConnector.main(is_test_run=False)

        assert len(ticket_ids(connector_output)) == 2  # noqa: PLR2004


class TestAlertContents:
    @set_metadata(parameters=classic_params())
    def test_stamps_the_alert_for_the_platform(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future, title="Typosquat detected")

        SecurityAlertsConnector.main(is_test_run=False)

        alert = connector_output.results.json_output.alerts[0]
        assert alert.ticket_id == "alert-1"
        assert alert.name == "Typosquat detected"
        assert alert.device_product == CLASSIC_ALERT_PRODUCT
        assert alert.rule_generator == RULE_NAME

    @set_metadata(parameters=classic_params(**{"Severity": "Low"}))
    def test_applies_the_configured_severity(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future)

        SecurityAlertsConnector.main(is_test_run=False)

        assert connector_output.results.json_output.alerts[0].priority == SEVERITY_MAP["Low"]

    @set_metadata(parameters=classic_params())
    def test_stamps_every_event_with_the_alert_it_came_from(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future)

        SecurityAlertsConnector.main(is_test_run=False)

        events = connector_output.results.json_output.alerts[0].events
        assert events
        for event in events:
            assert event["alert_id"] == "alert-1"
            assert event["alert_url"].endswith("?id=alert-1")

    @set_metadata(parameters=classic_params())
    def test_carries_ai_insights_onto_the_events(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future, ai_insights={"text": "The domain mimics your brand."})

        SecurityAlertsConnector.main(is_test_run=False)

        events = connector_output.results.json_output.alerts[0].events
        assert events[0]["ai_insights_text"] == "The domain mimics your brand."

    @set_metadata(parameters=classic_params())
    def test_falls_back_to_the_comment_when_there_is_no_insight_text(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future, ai_insights={"comment": "Not enough evidence."})

        SecurityAlertsConnector.main(is_test_run=False)

        events = connector_output.results.json_output.alerts[0].events
        assert events[0]["ai_insights_text"] == "Not enough evidence."

    @set_metadata(parameters=classic_params())
    def test_says_so_when_an_alert_has_no_insights(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future)

        SecurityAlertsConnector.main(is_test_run=False)

        events = connector_output.results.json_output.alerts[0].events
        assert events[0]["ai_insights_text"] == "AI Insights is not available for this alert."

    @set_metadata(parameters=classic_params(**{"Extract all Entities": "true"}))
    def test_extracts_every_entity_when_asked(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.add_alert_rule(make_alert_rule(RULE_ID, RULE_NAME))
        recorded_future.set_classic_alert(
            "alert-1",
            make_classic_alert(
                "alert-1",
                status="New",
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                hits=[
                    make_classic_alert_hit(
                        "hit-1",
                        entities=[
                            {
                                "id": "idn:bad-example.com",
                                "name": "bad-example.com",
                                "type": "InternetDomainName",
                            },
                            {"id": "ip:9.9.9.9", "name": "9.9.9.9", "type": "IpAddress"},
                        ],
                    ),
                ],
            ),
        )

        SecurityAlertsConnector.main(is_test_run=False)

        event = connector_output.results.json_output.alerts[0].events[0]
        assert "bad-example.com" in str(event.values())
        assert "9.9.9.9" in str(event.values())


class TestApiFailures:
    @set_metadata(parameters=classic_params())
    def test_returns_an_empty_package_when_the_token_is_rejected(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future)
        recorded_future.authorized = False

        SecurityAlertsConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == []

    @set_metadata(parameters=classic_params())
    def test_raises_on_a_rejected_token_during_a_test_run(
        self,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future)
        recorded_future.authorized = False

        with pytest.raises(Exception, match="401"):
            SecurityAlertsConnector.main(is_test_run=True)
