############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the Search Links action.

The Links API only takes Recorded Future entity IDs, so which entities the
action resolves - and how it reports one the API could not answer for - is the
behaviour worth pinning.
"""

from __future__ import annotations

from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from soar_sdk.SiemplifyDataModel import EntityTypes
from TIPCommon.base.action import ExecutionState

from recorded_future_intelligence.actions import SearchLinks
from recorded_future_intelligence.tests.common import (
    CONFIG_PATH,
    make_entity,
    make_links_result,
)
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.core.session import RecordedFutureSession, request_body


def searched_entities(session: RecordedFutureSession) -> list[str]:
    """Return the entities the last links search asked about.

    Args:
        session: The session the action made its requests through.

    Returns:
        The entity IDs of the request body.

    """
    searches = [record for record in session.request_history if record.request.url.path == "/links/search"]
    return request_body(searches[-1].request)["entities"]


class TestSearchLinks:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Entities": "ip:1.1.1.1"},
    )
    def test_returns_the_links_for_the_entity_it_was_given(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_links("ip:1.1.1.1", make_links_result("ip:1.1.1.1"))

        SearchLinks.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True

        results = action_output.results.json_output.json_result
        assert results[0]["entity"]["id"] == "ip:1.1.1.1"
        assert results[0]["links"][0]["name"] == "Example Stealer"

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Entities": "ip:1.1.1.1,idn:bad-example.com"},
    )
    def test_searches_every_entity_of_a_comma_separated_list(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_links("ip:1.1.1.1", make_links_result("ip:1.1.1.1"))
        recorded_future.set_links(
            "idn:bad-example.com",
            make_links_result("idn:bad-example.com", "bad-example.com", "InternetDomainName"),
        )

        SearchLinks.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert searched_entities(script_session) == ["ip:1.1.1.1", "idn:bad-example.com"]
        assert len(action_output.results.json_output.json_result) == 2

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Filter on Target Entities": True},
        entities=[
            make_entity("1.1.1.1", EntityTypes.ADDRESS),
            make_entity("Some Analyst", EntityTypes.USER),
        ],
    )
    def test_resolves_the_cases_entities_to_recorded_future_ids(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """Only the case entities with a Recorded Future prefix are searchable.

        An entity type with no prefix is dropped rather than sent as a bare
        name, which the Links API would reject.
        """
        recorded_future.set_links("ip:1.1.1.1", make_links_result("ip:1.1.1.1"))

        SearchLinks.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert searched_entities(script_session) == ["ip:1.1.1.1"]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Entities": "ip:1.1.1.1", "Sections": "Actors, Tools & TTPs"},
    )
    def test_forwards_the_section_filter(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """A section name containing a comma is split by the CSV parser.

        The action parses Sections as a comma separated list, so the one
        section name that itself contains commas - "Actors, Tools & TTPs" -
        arrives at the API as three separate sections. Asserted as-is: the
        Links API ignores sections it does not know, so the search widens
        rather than failing outright.
        """
        recorded_future.set_links("ip:1.1.1.1", make_links_result("ip:1.1.1.1"))

        SearchLinks.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert len(action_output.results.json_output.json_result) == 1

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Entities": "ip:1.1.1.1"},
    )
    def test_reports_a_per_entity_error_without_failing_the_action(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """One entity the API cannot answer for must not sink the batch."""
        recorded_future.set_links(
            "ip:1.1.1.1",
            make_links_result(
                "ip:1.1.1.1",
                links=[],
                error={"message": "Entity not found", "status_code": 404},
            ),
        )

        SearchLinks.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        result = action_output.results.json_output.json_result[0]
        assert result["links"] == []
        assert result["error"]["status_code"] == 404

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Entities": "ip:9.9.9.9"},
    )
    def test_reports_an_entity_with_no_links_as_a_success(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        SearchLinks.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.json_output.json_result == []

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Entities": "ip:1.1.1.1"},
    )
    def test_fails_on_a_rejected_token(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.authorized = False

        SearchLinks.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False
