############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the Update Playbook Alert action.

The action reports only the alert ID back, so these assert on the update the
API received - `recorded_future.playbook_alert_updates`.
"""

from __future__ import annotations

from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from TIPCommon.base.action import ExecutionState

from recorded_future_intelligence.actions import UpdatePlaybookAlert
from recorded_future_intelligence.tests.common import CONFIG_PATH
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.core.session import RecordedFutureSession


class TestUpdatePlaybookAlert:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={
            "Playbook Alert ID": "pba-1",
            "Status": "Resolved",
            "Priority": "High",
            "Assign To": "analyst@example.com",
            "Log Entry": "Closed after triage.",
            "Reopen Strategy": "Never",
        },
    )
    def test_submits_every_field_it_was_given(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        UpdatePlaybookAlert.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True
        assert action_output.results.json_output.json_result == {"success": {"id": "pba-1"}}
        assert recorded_future.playbook_alert_updates == [
            {
                "id": "pba-1",
                "priority": "High",
                "status": "Resolved",
                "assignee": "analyst@example.com",
                "log_entry": "Closed after triage.",
                "reopen": "Never",
            },
        ]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Playbook Alert ID": "pba-1", "Status": "In Progress"},
    )
    def test_strips_the_spaces_out_of_a_dropdown_status(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """The dropdown reads "In Progress"; the API wants `InProgress`.

        `clean_input` removes the spaces, so the display form the analyst picks
        is not what gets sent.
        """
        UpdatePlaybookAlert.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert recorded_future.playbook_alert_updates == [
            {"id": "pba-1", "status": "InProgress"},
        ]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Playbook Alert ID": "pba-1", "Status": "None", "Priority": "None"},
    )
    def test_fails_when_every_field_is_left_unset(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """An update with nothing in it is rejected before it reaches the API.

        Both dropdowns carry a literal "None" for "leave alone", which
        `clean_input` turns back into a real None - leaving psengine with an
        empty body, which it refuses with a `ValueError`.
        """
        UpdatePlaybookAlert.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False
        assert "ValueError" in action_output.results.output_message
        assert recorded_future.playbook_alert_updates == []

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Playbook Alert ID": "pba-1", "Status": "Resolved"},
    )
    def test_fails_on_a_rejected_token(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.authorized = False

        UpdatePlaybookAlert.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False
        assert recorded_future.playbook_alert_updates == []
