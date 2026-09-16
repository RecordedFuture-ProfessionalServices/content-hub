############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the two detection rule actions.

Both read Recorded Future's rule catalogue; Search Detection Rules also
decides which entities to filter on, which is where a playbook goes wrong.
"""

from __future__ import annotations

import pytest
from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from soar_sdk.SiemplifyDataModel import EntityTypes
from TIPCommon.base.action import ExecutionState
from TIPCommon.exceptions import ParameterValidationError

from recorded_future_intelligence.actions import FetchDetectionRule, SearchDetectionRules
from recorded_future_intelligence.tests.common import (
    CONFIG_PATH,
    make_detection_rule,
    make_entity,
)
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.core.session import RecordedFutureSession, request_body


def searched_filter(session: RecordedFutureSession) -> dict:
    """Return the filter the last detection rule search sent.

    Args:
        session: The session the action made its requests through.

    Returns:
        The `filter` object of the request body.

    """
    searches = [record for record in session.request_history if record.request.url.path == "/detection-rule/search"]
    return request_body(searches[-1].request)["filter"]


class TestSearchDetectionRules:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Detection Rule Type": "sigma", "Max Results": 10},
    )
    def test_returns_every_rule_of_the_requested_type(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.add_detection_rule(make_detection_rule("doc:rule-1", "sigma"))
        recorded_future.add_detection_rule(make_detection_rule("doc:rule-2", "yara"))

        SearchDetectionRules.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert [rule["id"] for rule in action_output.results.json_output.json_result] == ["doc:rule-1"]
        assert "Found 1 rule(s)" in action_output.results.output_message

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Detection Rule Title": "PowerShell", "Max Results": 10},
    )
    def test_narrows_the_search_by_title(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.add_detection_rule(
            make_detection_rule("doc:rule-1", title="Suspicious PowerShell"),
        )
        recorded_future.add_detection_rule(
            make_detection_rule("doc:rule-2", title="Suspicious DNS"),
        )

        SearchDetectionRules.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert [rule["id"] for rule in action_output.results.json_output.json_result] == ["doc:rule-1"]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Filter on Target Entities": True, "Max Results": 10},
        entities=[make_entity("1.1.1.1", EntityTypes.ADDRESS)],
    )
    def test_filters_on_the_cases_entities_when_asked(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.add_detection_rule(make_detection_rule("doc:rule-1"))

        SearchDetectionRules.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert searched_filter(script_session)["entities"] == ["ip:1.1.1.1"]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        # "false" as a string, not a bool: `extract_action_param` treats a
        # falsy value as an absent one and would fall back to its default.
        parameters={"Entity ID": "ip:9.9.9.9", "Filter on Target Entities": "false", "Max Results": 10},
    )
    def test_filters_on_the_entity_ids_it_was_given(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.add_detection_rule(make_detection_rule("doc:rule-1"))

        SearchDetectionRules.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert searched_filter(script_session)["entities"] == ["ip:9.9.9.9"]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Entity ID": "ip:9.9.9.9", "Max Results": 10},
    )
    def test_uses_the_entity_ids_when_the_target_filter_is_left_unset(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """The target entity filter is off unless a playbook turns it on.

        The two entity sources are mutually exclusive, so the default decides
        which of them a playbook that sets only one of them gets.
        """
        recorded_future.add_detection_rule(make_detection_rule("doc:rule-1"))

        SearchDetectionRules.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert searched_filter(script_session)["entities"] == ["ip:9.9.9.9"]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Detection Rule Type": "sigma", "Max Results": 10},
    )
    def test_reports_an_empty_catalogue_as_a_success(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        SearchDetectionRules.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.json_output.json_result == []
        assert "Found 0 rule(s)" in action_output.results.output_message

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Detection Rule Type": "carbon-black", "Max Results": 10},
    )
    def test_rejects_a_rule_type_recorded_future_does_not_have(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """An unsupported type is caught before any request is made.

        The validation runs during parameter extraction, outside the action's
        try, so the error leaves `main` rather than being reported as a failed
        run with a message.
        """
        with pytest.raises(ParameterValidationError, match="detection_rule"):
            SearchDetectionRules.main()

        assert script_session.request_history == []


class TestFetchDetectionRule:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Rule ID": "doc:rule-1"},
    )
    def test_returns_the_rule(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.add_detection_rule(
            make_detection_rule("doc:rule-1", title="Suspicious PowerShell"),
        )
        recorded_future.add_detection_rule(make_detection_rule("doc:rule-2"))

        FetchDetectionRule.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True

        rule = action_output.results.json_output.json_result
        assert rule["id"] == "doc:rule-1"
        assert rule["title"] == "Suspicious PowerShell"

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Rule ID": "doc:nothing-here"},
    )
    def test_reports_a_rule_the_catalogue_does_not_hold_as_a_success(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """An unknown rule ID is an empty answer, not a failure.

        psengine's fetch searches by ID and returns None for no hit, so the
        action reports success with nothing in it.
        """
        FetchDetectionRule.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Rule ID": "doc:rule-1"},
    )
    def test_fails_on_a_rejected_token(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.authorized = False

        FetchDetectionRule.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False
