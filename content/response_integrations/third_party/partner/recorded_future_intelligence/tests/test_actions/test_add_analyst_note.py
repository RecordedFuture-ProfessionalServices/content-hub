############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the Add Analyst Note action.

The action appends the case's entities to the note body, so these assert on
what the API was asked to publish - `recorded_future.published_notes` - rather
than only on the action's result.
"""

from __future__ import annotations

from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from TIPCommon.base.action import ExecutionState

from recorded_future_intelligence.actions import AddAnalystNote
from recorded_future_intelligence.core.constants import TOPIC_MAP
from recorded_future_intelligence.tests.common import CONFIG_PATH, make_entity
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.core.session import RecordedFutureSession

NOTE_PARAMETERS = {"Note Title": "SOAR triage", "Note Text": "Investigated and closed."}


class TestAddAnalystNote:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters=NOTE_PARAMETERS,
    )
    def test_publishes_the_note(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        AddAnalystNote.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True
        assert "note:published" in action_output.results.output_message

        published = recorded_future.published_notes[0]["attributes"]
        assert published["title"] == "SOAR triage"
        assert published["text"].startswith("Investigated and closed.")

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters=NOTE_PARAMETERS,
        entities=[
            make_entity("bad-example.com"),
            make_entity("worse-example.com"),
        ],
    )
    def test_appends_the_cases_entities_to_the_note_text(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        AddAnalystNote.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED

        text = recorded_future.published_notes[0]["attributes"]["text"]
        assert "Entities collected from case: bad-example.com\nworse-example.com" in text

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={**NOTE_PARAMETERS, "Topic": TOPIC_MAP["Flash Report"]},
    )
    def test_publishes_under_the_chosen_topic(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        AddAnalystNote.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        # psengine accepts one topic or several, and normalises to a list.
        assert recorded_future.published_notes[0]["attributes"]["topic"] == [
            TOPIC_MAP["Flash Report"],
        ]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters=NOTE_PARAMETERS,
    )
    def test_fails_on_a_rejected_token(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.authorized = False

        AddAnalystNote.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False
        assert recorded_future.published_notes == []
