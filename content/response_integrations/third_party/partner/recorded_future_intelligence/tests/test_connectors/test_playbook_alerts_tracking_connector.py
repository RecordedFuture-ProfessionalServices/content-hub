############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the Playbook Alerts Tracking Connector.

This connector exists to create a case when an *already known* playbook alert
changes in a way the operator cares about, so its whole job is deciding what
not to ingest. These tests drive `main` against the in-memory API and assert on
the package it returned, which is what the platform acts on.
"""

from __future__ import annotations

import pytest
from integration_testing.platform.script_output import MockConnectorOutput
from integration_testing.set_meta import set_metadata

from recorded_future_intelligence.connectors import PlaybookAlertsTrackingConnector
from recorded_future_intelligence.core.constants import (
    PLAYBOOK_ALERT_PRODUCT,
    SEVERITY_MAP,
)
from recorded_future_intelligence.tests.common import (
    make_assessment_change,
    make_entities_change,
    make_panel_log,
    make_playbook_alert,
    make_priority_change,
    make_status_change,
)
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.test_connectors.common import (
    connector_params,
    minutes_ago,
)


def seed_alert(
    recorded_future: RecordedFuture,
    alert_id: str = "task:pa-1",
    changes: list | None = None,
    created: str | None = None,
    **kwargs: object,
) -> None:
    """Seed one Domain Abuse alert carrying a single log entry.

    Args:
        recorded_future: The in-memory API to seed.
        alert_id: The playbook alert ID.
        changes: The changes the log entry records. Defaults to a reopen.
        created: When the change was logged. Defaults to five minutes ago,
            inside the connector's update window.
        **kwargs: Passed through to `make_playbook_alert`.

    """
    recorded_future.set_playbook_alert(
        "domain_abuse",
        alert_id,
        make_playbook_alert(
            alert_id,
            logs=[
                make_panel_log(
                    changes if changes is not None else [make_status_change()],
                    created=created or minutes_ago(5),
                ),
            ],
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


class TestUpdateFilters:
    @set_metadata(parameters=connector_params(**{"Playbook Alert Reopened": "true"}))
    def test_creates_a_case_for_a_reopened_alert(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future, changes=[make_status_change("Resolved", "New")])

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["task:pa-1"]

    @set_metadata(parameters=connector_params(**{"Playbook Alert Reopened": "true"}))
    def test_ignores_a_status_change_that_is_not_a_reopen(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future, changes=[make_status_change("New", "Resolved")])

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == []

    @set_metadata(parameters=connector_params(**{"Priority Increased": "true"}))
    def test_creates_a_case_for_a_priority_increase(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(
            recorded_future,
            changes=[make_priority_change("Informational", "Moderate")],
        )

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["task:pa-1"]

    @set_metadata(parameters=connector_params(**{"Priority Increased": "true"}))
    def test_ignores_a_priority_decrease(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future, changes=[make_priority_change("High", "Informational")])

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == []

    @set_metadata(parameters=connector_params(**{"New Assessment Added": "true"}))
    def test_creates_a_case_for_a_new_assessment(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future, changes=[make_assessment_change(added=["assessment-1"])])

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["task:pa-1"]

    @set_metadata(parameters=connector_params(**{"Entity Added": "true"}))
    def test_creates_a_case_for_an_added_entity(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future, changes=[make_entities_change()])

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["task:pa-1"]

    @set_metadata(parameters=connector_params(**{"Entity Added": "true"}))
    def test_ignores_an_entity_removal(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(
            recorded_future,
            changes=[
                make_entities_change(
                    added=[],
                    removed=[{"id": "ip:9.9.9.9", "name": "9.9.9.9", "type": "IpAddress"}],
                ),
            ],
        )

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == []

    @set_metadata(parameters=connector_params())
    def test_creates_nothing_with_every_filter_off(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """The connector's own description warns that it needs a filter enabled."""
        seed_alert(recorded_future, changes=[make_status_change()])

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == []

    @set_metadata(
        parameters=connector_params(
            **{"Playbook Alert Reopened": "true", "Entity Added": "true"},
        ),
    )
    def test_any_enabled_filter_is_enough(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future, changes=[make_entities_change()])

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["task:pa-1"]


class TestUpdateWindow:
    @set_metadata(parameters=connector_params(**{"Playbook Alert Reopened": "true"}))
    def test_ignores_a_change_older_than_the_window(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """A reopen from before the window is somebody else's already-built case."""
        seed_alert(recorded_future, created=minutes_ago(60 * 48))

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == []

    @set_metadata(
        parameters=connector_params(
            **{"Playbook Alert Reopened": "true", "Search Max Hours Backwards": 72},
        ),
    )
    def test_a_wider_window_reaches_an_older_change(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future, created=minutes_ago(60 * 48))

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["task:pa-1"]

    @set_metadata(parameters=connector_params(**{"Playbook Alert Reopened": "true"}))
    def test_keeps_a_matching_change_among_stale_ones(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert(
                "task:pa-1",
                logs=[
                    make_panel_log(
                        [make_status_change("New", "Resolved")],
                        created=minutes_ago(60 * 48),
                        log_id="uuid:old",
                    ),
                    make_panel_log(
                        [make_status_change("Resolved", "New")],
                        created=minutes_ago(5),
                        log_id="uuid:new",
                    ),
                ],
            ),
        )

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["task:pa-1"]


class TestLogTimestampHandling:
    @pytest.mark.xfail(
        strict=True,
        reason="Bug: a log timestamped on a whole second silently loses the "
        "alert. psengine round-trips `created` through a datetime and pydantic "
        "omits a zero microsecond component, so the value dumps as "
        "'...T03:04:05Z'; the connector parses it with "
        "'%Y-%m-%dT%H:%M:%S.%f' (PlaybookAlertsTrackingConnector.py:284), "
        "which cannot read it. The ValueError is swallowed by the per-alert "
        "handler, so the update is dropped with only a log line. Remove this "
        "marker once the parse tolerates an absent fractional part.",
    )
    @set_metadata(parameters=connector_params(**{"Playbook Alert Reopened": "true"}))
    def test_handles_a_change_logged_on_a_whole_second(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future, created=minutes_ago(5).split(".")[0] + "Z")

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["task:pa-1"]

    @set_metadata(parameters=connector_params(**{"Playbook Alert Reopened": "true"}))
    def test_survives_an_alert_fetched_without_its_log_panel(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """A log-less alert is skipped, and must not take the run with it."""
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1"),
        )
        seed_alert(recorded_future, alert_id="task:pa-2")

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["task:pa-2"]

    @set_metadata(parameters=connector_params(**{"Playbook Alert Reopened": "true"}))
    def test_skips_an_alert_whose_log_panel_is_empty(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1", logs=[]),
        )

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == []


class TestDeduplication:
    @set_metadata(parameters=connector_params(**{"Playbook Alert Reopened": "true"}))
    def test_does_not_report_the_same_alert_twice(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """The IDs written on the first run must suppress the alert on the second."""
        seed_alert(recorded_future)

        PlaybookAlertsTrackingConnector.main(is_test_run=False)
        assert ticket_ids(connector_output) == ["task:pa-1"]

        connector_output.flush()
        PlaybookAlertsTrackingConnector.main(is_test_run=False)
        assert ticket_ids(connector_output) == []

    @set_metadata(parameters=connector_params(**{"Playbook Alert Reopened": "true"}))
    def test_a_test_run_does_not_suppress_the_next_run(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """A test run must not write IDs, or trying the connector would hide alerts."""
        seed_alert(recorded_future)

        PlaybookAlertsTrackingConnector.main(is_test_run=True)
        connector_output.flush()

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["task:pa-1"]


class TestLimits:
    @set_metadata(parameters=connector_params(**{"Playbook Alert Reopened": "true"}))
    def test_a_test_run_processes_one_alert(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        for index in range(3):
            seed_alert(recorded_future, alert_id=f"task:pa-{index}")

        PlaybookAlertsTrackingConnector.main(is_test_run=True)

        assert len(ticket_ids(connector_output)) == 1

    @set_metadata(
        parameters=connector_params(
            **{"Playbook Alert Reopened": "true", "Max Alerts To Fetch": 2},
        ),
    )
    def test_honours_the_fetch_limit(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        for index in range(5):
            seed_alert(recorded_future, alert_id=f"task:pa-{index}")

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert len(ticket_ids(connector_output)) == 2  # noqa: PLR2004


class TestAlertContents:
    @set_metadata(parameters=connector_params(**{"Playbook Alert Reopened": "true"}))
    def test_stamps_the_alert_for_the_platform(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future, entity_name="bad-example.com")

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        alert = connector_output.results.json_output.alerts[0]
        assert alert.ticket_id == "task:pa-1"
        assert alert.name == "Domain Abuse - bad-example.com"
        assert alert.device_product == PLAYBOOK_ALERT_PRODUCT
        assert alert.rule_generator == "Domain Abuse"
        assert alert.events

    @set_metadata(
        parameters=connector_params(
            **{"Playbook Alert Reopened": "true", "Severity": "Critical"},
        ),
    )
    def test_applies_the_configured_severity(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future)

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        alert = connector_output.results.json_output.alerts[0]
        assert alert.priority == SEVERITY_MAP["Critical"]


class TestCategoryFilter:
    @set_metadata(
        parameters=connector_params(
            **{
                "Playbook Alert Reopened": "true",
                "Playbook Alert Categories": "domain_abuse",
            },
        ),
    )
    def test_asks_only_for_the_configured_categories(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        seed_alert(recorded_future)
        recorded_future.set_playbook_alert(
            "code_repo_leakage",
            "task:pa-other",
            make_playbook_alert(
                "task:pa-other",
                category="code_repo_leakage",
                logs=[make_panel_log([make_status_change()], created=minutes_ago(5))],
            ),
        )

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == ["task:pa-1"]


class TestApiFailures:
    @set_metadata(parameters=connector_params(**{"Playbook Alert Reopened": "true"}))
    def test_returns_an_empty_package_when_the_token_is_rejected(
        self,
        connector_output: MockConnectorOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """A 401 must end the run cleanly rather than crash the connector."""
        seed_alert(recorded_future)
        recorded_future.authorized = False

        PlaybookAlertsTrackingConnector.main(is_test_run=False)

        assert ticket_ids(connector_output) == []

    @set_metadata(parameters=connector_params(**{"Playbook Alert Reopened": "true"}))
    def test_raises_on_a_rejected_token_during_a_test_run(
        self,
        recorded_future: RecordedFuture,
    ) -> None:
        """A test run re-raises, so the operator configuring it sees the failure."""
        seed_alert(recorded_future)
        recorded_future.authorized = False

        with pytest.raises(Exception, match="401"):
            PlaybookAlertsTrackingConnector.main(is_test_run=True)
