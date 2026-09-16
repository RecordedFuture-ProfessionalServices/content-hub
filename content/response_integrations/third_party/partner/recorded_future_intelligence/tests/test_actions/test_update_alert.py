############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the Update Alert action.

The action's output says nothing about what actually changed, so these assert
on the payload the API received - `recorded_future.alert_updates` - as well as
on the action's own result.
"""

from __future__ import annotations

from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from TIPCommon.base.action import ExecutionState

from recorded_future_intelligence.actions import UpdateAlert
from recorded_future_intelligence.tests.common import CONFIG_PATH
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.core.session import RecordedFutureSession


class TestUpdateAlert:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={
            "Alert ID": "alert-1",
            "Assign To": "analyst@example.com",
            "Note": "Triaged in SOAR.",
            "Status": "Resolved",
        },
    )
    def test_submits_every_field_it_was_given(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        UpdateAlert.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True
        assert action_output.results.json_output.json_result == {"success": {"id": "alert-1"}}
        assert recorded_future.alert_updates == [
            {
                "id": "alert-1",
                "assignee": "analyst@example.com",
                "note": "Triaged in SOAR.",
                "statusInPortal": "Resolved",
            },
        ]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Alert ID": "alert-1", "Status": "Resolved"},
    )
    def test_omits_the_fields_it_was_not_given(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        UpdateAlert.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert recorded_future.alert_updates == [{"id": "alert-1", "statusInPortal": "Resolved"}]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Alert ID": "alert-1", "Status": "None"},
    )
    def test_treats_the_unset_status_option_as_no_status(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """The Status dropdown offers a literal "None" for leaving it alone.

        `clean_input` turns that string back into a real None so the field is
        dropped from the payload rather than sent as the word "None".
        """
        UpdateAlert.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert recorded_future.alert_updates == [{"id": "alert-1"}]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Alert ID": "alert-1", "Status": "Resolved"},
    )
    def test_fails_on_a_rejected_token(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.authorized = False

        UpdateAlert.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False
        assert recorded_future.alert_updates == []
