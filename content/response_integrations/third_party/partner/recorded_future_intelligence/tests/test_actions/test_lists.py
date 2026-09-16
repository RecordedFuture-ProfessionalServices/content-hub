############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the seven List API actions.

They share one API area and one failure vocabulary, so they share a module.
The membership actions get the most attention: they choose their target from
three different sources, and that choice is the part a playbook gets wrong.
"""

from __future__ import annotations

from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from soar_sdk.SiemplifyDataModel import EntityTypes
from TIPCommon.base.action import ExecutionState

from recorded_future_intelligence.actions import (
    AddListEntity,
    CreateList,
    FetchList,
    GetListEntities,
    GetListStatus,
    RemoveListEntity,
    SearchList,
)
from recorded_future_intelligence.tests.common import (
    CONFIG_PATH,
    make_entity,
    make_entity_list,
    make_entity_match,
    make_list_member,
)
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.core.session import RecordedFutureSession


class TestCreateList:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List Name": "SOAR blocklist", "List Type": "entity"},
    )
    def test_creates_the_list(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        CreateList.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True

        created = action_output.results.json_output.json_result
        assert created["name"] == "SOAR blocklist"
        assert created["type"] == "entity"
        assert recorded_future.get_entity_list(created["id"]) is not None

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List Name": "SOAR blocklist", "List Type": "entity"},
    )
    def test_fails_on_a_rejected_token(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.authorized = False

        CreateList.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert recorded_future.entity_lists == {}


class TestFetchList:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List ID": "list-1"},
    )
    def test_returns_the_list_details(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_entity_list("list-1", make_entity_list("list-1", "SOAR blocklist"))

        FetchList.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.json_output.json_result["name"] == "SOAR blocklist"

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List ID": "list-1"},
    )
    def test_reports_a_list_the_api_does_not_hold(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        FetchList.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False


class TestSearchList:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List Name": "blocklist"},
    )
    def test_returns_every_list_matching_the_name(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_entity_list("list-1", make_entity_list("list-1", "SOAR blocklist"))
        recorded_future.set_entity_list("list-2", make_entity_list("list-2", "SOAR allowlist"))

        SearchList.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert [found["id"] for found in action_output.results.json_output.json_result] == ["list-1"]
        assert "1 list(s)" in action_output.results.output_message

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List Name": "blocklist", "List Type": "hash"},
    )
    def test_narrows_the_search_by_type(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_entity_list(
            "list-1",
            make_entity_list("list-1", "SOAR blocklist", list_type="entity"),
        )

        SearchList.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.json_output.json_result == []

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List Name": "nothing here"},
    )
    def test_reports_no_matches_as_a_success(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """An empty search is an answer, not a failure."""
        SearchList.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.json_output.json_result == []
        assert "0 list(s)" in action_output.results.output_message


class TestGetListStatus:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List ID": "list-1"},
    )
    def test_returns_the_size_and_build_status(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_entity_list(
            "list-1",
            make_entity_list("list-1"),
            entities=[make_list_member("ip:1.1.1.1"), make_list_member("ip:2.2.2.2")],
        )

        GetListStatus.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.json_output.json_result == {"size": 2, "status": "ready"}

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List ID": "list-1"},
    )
    def test_reports_a_list_the_api_does_not_hold(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        GetListStatus.main()

        assert action_output.results.execution_state == ExecutionState.FAILED


class TestGetListEntities:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List ID": "list-1"},
    )
    def test_returns_every_member(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_entity_list(
            "list-1",
            make_entity_list("list-1"),
            entities=[make_list_member("ip:1.1.1.1"), make_list_member("ip:2.2.2.2")],
        )

        GetListEntities.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert [member["entity"]["id"] for member in action_output.results.json_output.json_result] == [
            "ip:1.1.1.1",
            "ip:2.2.2.2",
        ]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List ID": "list-1"},
    )
    def test_returns_an_empty_list_for_an_empty_one(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_entity_list("list-1", make_entity_list("list-1"))

        GetListEntities.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.json_output.json_result == []


class TestAddListEntity:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List ID": "list-1", "Entity ID": "ip:1.1.1.1"},
    )
    def test_adds_the_entity_it_was_given_by_id(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_entity_list("list-1", make_entity_list("list-1"))

        AddListEntity.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.json_output.json_result["added"] == ["ip:1.1.1.1"]
        assert recorded_future.list_operations == [
            {"list_id": "list-1", "operation": "added", "entity": "ip:1.1.1.1"},
        ]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={
            "List ID": "list-1",
            "Entity Name": "BlueDelta",
            "Entity Type": "Organization",
        },
    )
    def test_resolves_a_name_and_type_to_an_id_first(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """A name and type pair is resolved through the entity match API.

        The List API only accepts prefixed IDs, so psengine looks the name up
        before it can add anything.
        """
        recorded_future.set_entity_list("list-1", make_entity_list("list-1"))
        recorded_future.set_entity_match(
            "BlueDelta",
            [make_entity_match("L37nw-", "BlueDelta", "Organization")],
        )

        AddListEntity.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert recorded_future.list_operations == [
            {"list_id": "list-1", "operation": "added", "entity": "L37nw-"},
        ]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={
            "List ID": "list-1",
            "Entity Name": "Nothing Known",
            "Entity Type": "Organization",
        },
    )
    def test_reports_a_name_it_cannot_resolve_as_an_error_not_a_failure(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """A name with no match is reported per entity, and the action succeeds.

        This is deliberate: a bulk add has to be able to report some entities
        added and others not.
        """
        recorded_future.set_entity_list("list-1", make_entity_list("list-1"))

        AddListEntity.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        result = action_output.results.json_output.json_result
        assert result["added"] == []
        assert len(result["error"]) == 1
        assert recorded_future.list_operations == []

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List ID": "list-1"},
        entities=[
            make_entity("1.1.1.1", EntityTypes.ADDRESS),
            make_entity("bad-example.com", EntityTypes.DOMAIN),
            make_entity("Some Analyst", EntityTypes.USER),
        ],
    )
    def test_falls_back_to_the_cases_entities(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """With no entity parameters, the case's own entities are added.

        Only the types Recorded Future has a prefix for are mapped, so the
        analyst entity is dropped rather than sent as an unprefixed ID.
        """
        recorded_future.set_entity_list("list-1", make_entity_list("list-1"))

        AddListEntity.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert [operation["entity"] for operation in recorded_future.list_operations] == [
            "ip:1.1.1.1",
            "idn:bad-example.com",
        ]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List ID": "list-1", "Entity ID": "ip:1.1.1.1"},
    )
    def test_reports_an_entity_already_on_the_list_as_unchanged(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_entity_list(
            "list-1",
            make_entity_list("list-1"),
            entities=[make_list_member("ip:1.1.1.1")],
        )

        AddListEntity.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        result = action_output.results.json_output.json_result
        assert result["added"] == []
        assert result["unchanged"] == ["ip:1.1.1.1"]
        assert "1 entities unchanged" in action_output.results.output_message


class TestRemoveListEntity:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List ID": "list-1", "Entity ID": "ip:1.1.1.1"},
    )
    def test_removes_the_entity_it_was_given(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_entity_list(
            "list-1",
            make_entity_list("list-1"),
            entities=[make_list_member("ip:1.1.1.1")],
        )

        RemoveListEntity.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.json_output.json_result["removed"] == ["ip:1.1.1.1"]
        assert recorded_future.get_list_entities("list-1") == []

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List ID": "list-1", "Entity ID": "ip:9.9.9.9"},
    )
    def test_reports_an_entity_that_was_never_on_the_list_as_unchanged(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_entity_list(
            "list-1",
            make_entity_list("list-1"),
            entities=[make_list_member("ip:1.1.1.1")],
        )

        RemoveListEntity.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.json_output.json_result["unchanged"] == ["ip:9.9.9.9"]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"List ID": "list-1", "Entity ID": "ip:1.1.1.1"},
    )
    def test_fails_on_a_rejected_token(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.authorized = False

        RemoveListEntity.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert recorded_future.list_operations == []
