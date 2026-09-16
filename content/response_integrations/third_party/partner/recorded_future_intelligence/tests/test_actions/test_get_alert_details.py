############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the Get Alert Details action.

The action's whole job is to put one classic alert's details into the case, so
the tests assert on the JSON result the analyst sees rather than on the call
the manager made.
"""

from __future__ import annotations

from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from TIPCommon.base.action import ExecutionState

from recorded_future_intelligence.actions import GetAlertDetails
from recorded_future_intelligence.tests.common import (
    CONFIG_PATH,
    make_classic_alert,
    make_classic_alert_hit,
)
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.core.session import RecordedFutureSession


class TestGetAlertDetails:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Alert ID": "alert-1"},
    )
    def test_returns_the_alert_details(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_classic_alert(
            "alert-1",
            make_classic_alert(
                "alert-1",
                title="Typosquat detected",
                rule_name="Typosquat rule",
                hits=[make_classic_alert_hit()],
            ),
        )

        GetAlertDetails.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True
        assert "alert-1" in action_output.results.output_message

        details = action_output.results.json_output.json_result
        assert details["id"] == "alert-1"
        assert details["title"] == "Typosquat detected"
        assert details["rule"]["name"] == "Typosquat rule"
        assert len(details["hits"]) == 1

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Alert ID": "alert-1"},
    )
    def test_reports_an_alert_the_api_does_not_hold(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """A 404 fails the action.

        The manager wraps psengine's fetch error in a
        `RecordedFutureManagerError`, which is not one of the two errors the
        action names, so it lands in the catch-all branch rather than the
        "wasn't found" one written for it.
        """
        GetAlertDetails.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False
        assert "Error executing action" in action_output.results.output_message

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Alert ID": "alert-1"},
    )
    def test_reports_a_rejected_token(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.authorized = False

        GetAlertDetails.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False
