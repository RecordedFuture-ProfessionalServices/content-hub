############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the Entity Lookup and Entity Match actions.

Both sit on the entity match API: one resolves a name to Recorded Future
entities, the other reads one back by ID.
"""

from __future__ import annotations

from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from TIPCommon.base.action import ExecutionState

from recorded_future_intelligence.actions import EntityLookup, EntityMatch
from recorded_future_intelligence.tests.common import (
    CONFIG_PATH,
    make_entity_lookup,
    make_entity_match,
)
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.core.session import RecordedFutureSession


class TestEntityLookup:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Entity ID": "L37nw-"},
    )
    def test_returns_the_entity(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_entity_lookup("L37nw-", make_entity_lookup("L37nw-", "BlueDelta"))

        EntityLookup.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True
        assert "Matched Entity ID" in action_output.results.output_message

        entity = action_output.results.json_output.json_result
        assert entity["id"] == "L37nw-"
        assert entity["attributes"]["name"] == "BlueDelta"

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Entity ID": "nothing-here"},
    )
    def test_reports_an_id_the_api_does_not_hold_as_no_match(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """An unknown ID is an answer, not a failure.

        psengine treats the 404 as "no such entity" and returns None rather
        than raising, so the action reports an empty result and succeeds.
        """
        EntityLookup.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True
        assert "Did not match Entity ID" in action_output.results.output_message
        assert action_output.results.json_output.json_result == {}


class TestEntityMatch:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Entity Name": "BlueDelta", "Limit": 10},
    )
    def test_returns_every_match_for_a_name(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_entity_match(
            "BlueDelta",
            [
                make_entity_match("L37nw-", "BlueDelta", "Organization"),
                make_entity_match("K8mKs-", "BlueDelta", "Malware"),
            ],
        )

        EntityMatch.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert {match["content"]["id"] for match in action_output.results.json_output.json_result} == {
            "L37nw-",
            "K8mKs-",
        }

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Entity Name": "BlueDelta", "Entity Type": "Organization", "Limit": 10},
    )
    def test_narrows_the_match_by_type(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_entity_match(
            "BlueDelta",
            [
                make_entity_match("L37nw-", "BlueDelta", "Organization"),
                make_entity_match("K8mKs-", "BlueDelta", "Malware"),
            ],
        )

        EntityMatch.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert [match["content"]["id"] for match in action_output.results.json_output.json_result] == [
            "L37nw-",
        ]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Entity Name": "BlueDelta", "Limit": 1},
    )
    def test_honours_the_limit(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_entity_match(
            "BlueDelta",
            [
                make_entity_match("L37nw-", "BlueDelta", "Organization"),
                make_entity_match("K8mKs-", "BlueDelta", "Malware"),
            ],
        )

        EntityMatch.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert len(action_output.results.json_output.json_result) == 1

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Entity Name": "Nothing Known", "Limit": 10},
    )
    def test_reports_no_match_as_a_success(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """A name with no match comes back as one unfound result, not an error."""
        EntityMatch.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.json_output.json_result == [
            {"entity": "Nothing Known", "is_found": False, "content": "Entity ID not found"},
        ]
