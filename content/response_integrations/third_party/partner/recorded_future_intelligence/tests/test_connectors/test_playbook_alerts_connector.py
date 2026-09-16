############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the Playbook Alerts Connector.

Unlike the tracking connector, this one ingests playbook alerts on first
sighting, so the behaviour that matters is which alerts the configured filters
let through and that an alert is reported exactly once.
"""

from __future__ import annotations

import pytest
from integration_testing.platform.script_output import MockConnectorOutput
from integration_testing.set_meta import set_metadata

from recorded_future_intelligence.connectors import PlaybookAlertsConnector
from recorded_future_intelligence.core.constants import (
    PLAYBOOK_ALERT_PRODUCT,
    SEVERITY_MAP,
)
from recorded_future_intelligence.tests.common import make_playbook_alert
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.test_connectors.common import playbook_params


def ticket_ids(output: MockConnectorOutput) -> list[str]:
    """Return the Recorded Future alert IDs the connector turned into cases.

    Args:
        output: The captured connector output.

    Returns:
        The ticket IDs, in the order the connector reported them.

    """
    return [alert.ticket_id for alert in output.results.json_output.alerts]


class TestFetching:
    @set_metadata(parameters=playbook_params())
    def test_reports_a_new_alert(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1"),
        )

        PlaybookAlertsConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["task:pa-1"]

    @set_metadata(parameters=playbook_params())
    def test_reports_every_matching_alert(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        for index in range(3):
            alert_id = f"task:pa-{index}"
            recorded_future.set_playbook_alert(
                "domain_abuse",
                alert_id,
                make_playbook_alert(alert_id),
            )

        PlaybookAlertsConnector.main(is_test_run=False)

        assert sorted(ticket_ids(connector_output)) == ["task:pa-0", "task:pa-1", "task:pa-2"]

    @set_metadata(parameters=playbook_params())
    def test_reports_nothing_when_the_api_is_empty(
        self,
        connector_output: MockConnectorOutput,
    ) -> None:
        PlaybookAlertsConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == []


class TestFilters:
    @set_metadata(parameters=playbook_params(**{"Playbook Alert Statuses": "New"}))
    def test_filters_by_status(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-new",
            make_playbook_alert("task:pa-new", status="New"),
        )
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-resolved",
            make_playbook_alert("task:pa-resolved", status="Resolved"),
        )

        PlaybookAlertsConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["task:pa-new"]

    @set_metadata(parameters=playbook_params(**{"Playbook Alert Priorities": "High"}))
    def test_filters_by_priority(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-high",
            make_playbook_alert("task:pa-high", priority="High"),
        )
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-info",
            make_playbook_alert("task:pa-info", priority="Informational"),
        )

        PlaybookAlertsConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["task:pa-high"]

    @set_metadata(parameters=playbook_params(**{"Playbook Alert Categories": "domain_abuse"}))
    def test_filters_by_category(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-domain",
            make_playbook_alert("task:pa-domain"),
        )
        recorded_future.set_playbook_alert(
            "code_repo_leakage",
            "task:pa-repo",
            make_playbook_alert("task:pa-repo", category="code_repo_leakage"),
        )

        PlaybookAlertsConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["task:pa-domain"]

    @set_metadata(
        parameters=playbook_params(
            **{"Playbook Alert Categories": "domain_abuse, code_repo_leakage"},
        ),
    )
    def test_accepts_several_categories(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-domain",
            make_playbook_alert("task:pa-domain"),
        )
        recorded_future.set_playbook_alert(
            "code_repo_leakage",
            "task:pa-repo",
            make_playbook_alert("task:pa-repo", category="code_repo_leakage"),
        )

        PlaybookAlertsConnector.main(is_test_run=False)

        assert sorted(ticket_ids(connector_output)) == ["task:pa-domain", "task:pa-repo"]


class TestDeduplication:
    @set_metadata(parameters=playbook_params())
    def test_does_not_report_the_same_alert_twice(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1"),
        )

        PlaybookAlertsConnector.main(is_test_run=False)
        assert ticket_ids(connector_output) == ["task:pa-1"]

        connector_output.flush()
        PlaybookAlertsConnector.main(is_test_run=False)
        assert ticket_ids(connector_output) == []

    @set_metadata(parameters=playbook_params())
    def test_still_reports_an_alert_seen_only_in_a_test_run(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1"),
        )

        PlaybookAlertsConnector.main(is_test_run=True)
        connector_output.flush()

        PlaybookAlertsConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["task:pa-1"]


class TestLimits:
    @set_metadata(parameters=playbook_params())
    def test_a_test_run_processes_one_alert(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        for index in range(3):
            alert_id = f"task:pa-{index}"
            recorded_future.set_playbook_alert(
                "domain_abuse",
                alert_id,
                make_playbook_alert(alert_id),
            )

        PlaybookAlertsConnector.main(is_test_run=True)

        assert len(ticket_ids(connector_output)) == 1

    @set_metadata(parameters=playbook_params(**{"Max Alerts To Fetch": 2}))
    def test_honours_the_fetch_limit(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        for index in range(5):
            alert_id = f"task:pa-{index}"
            recorded_future.set_playbook_alert(
                "domain_abuse",
                alert_id,
                make_playbook_alert(alert_id),
            )

        PlaybookAlertsConnector.main(is_test_run=False)

        assert len(ticket_ids(connector_output)) == 2  # noqa: PLR2004


class TestAlertContents:
    @set_metadata(parameters=playbook_params())
    def test_stamps_the_alert_for_the_platform(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1", entity_name="bad-example.com"),
        )

        PlaybookAlertsConnector.main(is_test_run=False)

        alert = connector_output.results.json_output.alerts[0]
        assert alert.ticket_id == "task:pa-1"
        assert alert.name == "Domain Abuse - bad-example.com"
        assert alert.device_product == PLAYBOOK_ALERT_PRODUCT
        assert alert.rule_generator == "Domain Abuse"
        assert alert.events

    @set_metadata(parameters=playbook_params(**{"Severity": "High"}))
    def test_applies_the_configured_severity(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1"),
        )

        PlaybookAlertsConnector.main(is_test_run=False)

        assert connector_output.results.json_output.alerts[0].priority == SEVERITY_MAP["High"]


class TestApiFailures:
    @set_metadata(parameters=playbook_params())
    def test_returns_an_empty_package_when_the_token_is_rejected(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1"),
        )
        recorded_future.authorized = False

        PlaybookAlertsConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == []

    @set_metadata(parameters=playbook_params())
    def test_raises_on_a_rejected_token_during_a_test_run(
        self,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1"),
        )
        recorded_future.authorized = False

        with pytest.raises(Exception, match="401"):
            PlaybookAlertsConnector.main(is_test_run=True)
