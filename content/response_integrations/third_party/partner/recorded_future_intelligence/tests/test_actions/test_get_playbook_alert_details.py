############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the Get Playbook Alert Details action."""

from __future__ import annotations

from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from TIPCommon.base.action import ExecutionState

from recorded_future_intelligence.actions import GetPlaybookAlertDetails
from recorded_future_intelligence.tests.common import CONFIG_PATH, make_playbook_alert
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.core.session import RecordedFutureSession


class TestGetPlaybookAlertDetails:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Playbook Alert ID": "pba-1", "Category": "domain_abuse"},
    )
    def test_returns_the_alert_details(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "pba-1",
            make_playbook_alert("pba-1", entity_name="bad-example.com"),
        )

        GetPlaybookAlertDetails.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True
        assert "pba-1" in action_output.results.output_message

        details = action_output.results.json_output.json_result
        assert details["playbook_alert_id"] == "pba-1"
        assert details["panel_status"]["entity_name"] == "bad-example.com"

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Playbook Alert ID": "pba-1", "Category": "domain_abuse"},
    )
    def test_does_not_fetch_screenshots(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """The action has no widget for screenshots, so it must not request them.

        psengine's `fetch_images` defaults to on, which would cost an extra
        call per screenshot and add a failure path for bytes this action never
        emits.
        """
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "pba-1",
            make_playbook_alert("pba-1"),
        )

        GetPlaybookAlertDetails.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert not [record for record in script_session.request_history if "/image/" in record.request.url.path]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Playbook Alert ID": "pba-1", "Category": "domain_abuse"},
    )
    def test_reports_an_alert_the_api_does_not_hold(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        GetPlaybookAlertDetails.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False
        assert "Error executing action" in action_output.results.output_message
