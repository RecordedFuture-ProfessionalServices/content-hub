############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the Submit Collective Insights action.

The action turns a case's target entities into detections and sends them back
to Recorded Future, so these assert on the submission the API received -
`recorded_future.collective_insights`.
"""

from __future__ import annotations

import pytest
from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from soar_sdk.SiemplifyDataModel import EntityTypes
from TIPCommon.base.action import ExecutionState

from recorded_future_intelligence.actions import SubmitCollectiveInsights
from recorded_future_intelligence.core.constants import (
    CI_DETECTION_TYPE,
    CI_DETECTION_TYPE_RULE,
    CI_INCIDENT_TYPE,
)
from recorded_future_intelligence.tests.common import CONFIG_PATH, make_entity
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.core.session import RecordedFutureSession

SHA256 = "a" * 64


class TestSubmitCollectiveInsights:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={
            "Incident ID": "4242",
            "Incident Name": "Suspicious outbound traffic",
            "Incident Type": CI_INCIDENT_TYPE,
        },
        entities=[
            make_entity("1.1.1.1", EntityTypes.ADDRESS),
            make_entity("bad-example.com", EntityTypes.DOMAIN),
        ],
    )
    def test_submits_one_detection_per_supported_entity(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        SubmitCollectiveInsights.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True
        assert "2 detections" in action_output.results.output_message

        detections = recorded_future.collective_insights[0]["data"]
        assert [(detection["ioc"]["value"], detection["ioc"]["type"]) for detection in detections] == [
            ("1.1.1.1", "ip"),
            ("bad-example.com", "domain"),
        ]
        assert detections[0]["incident"]["id"] == "4242"

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={},
        entities=[
            make_entity("1.1.1.1", EntityTypes.ADDRESS),
            make_entity("Some Analyst", EntityTypes.USER),
        ],
    )
    def test_skips_an_entity_type_collective_insights_has_no_ioc_for(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """An unsupported entity is reported back, not silently dropped.

        A playbook that submits a whole case needs to know which of its
        entities were left out.
        """
        SubmitCollectiveInsights.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert "Skipped 1 target entities" in action_output.results.output_message
        assert action_output.results.json_output.json_result["skipped_entities"] == [
            {"identifier": "Some Analyst", "entity_type": EntityTypes.USER},
        ]
        assert len(recorded_future.collective_insights[0]["data"]) == 1

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={},
        entities=[make_entity("Some Analyst", EntityTypes.USER)],
    )
    def test_fails_when_no_entity_can_be_submitted(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """Nothing to submit is a failure, and nothing is sent."""
        SubmitCollectiveInsights.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert "No supported target entities" in action_output.results.output_message
        assert recorded_future.collective_insights == []

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Detection Type": CI_DETECTION_TYPE_RULE},
        entities=[make_entity("1.1.1.1", EntityTypes.ADDRESS)],
    )
    def test_rejects_a_rule_detection_with_no_rule_identified(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """A `detection_rule` submission has to say which rule fired.

        Recorded Future attributes the detection to the rule, so the action
        refuses the submission rather than sending an unattributable one.
        """
        SubmitCollectiveInsights.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert "Detection ID and Detection Sub Type are mandatory" in action_output.results.output_message
        assert recorded_future.collective_insights == []

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={
            "Detection Type": CI_DETECTION_TYPE_RULE,
            "Detection ID": "rule-42",
            "Detection Sub Type": "sigma",
        },
        entities=[make_entity(SHA256, EntityTypes.FILEHASH)],
    )
    def test_submits_a_rule_detection_when_the_rule_is_identified(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        SubmitCollectiveInsights.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED

        detection = recorded_future.collective_insights[0]["data"][0]["detection"]
        assert detection["type"] == CI_DETECTION_TYPE_RULE
        assert detection["id"] == "rule-42"
        assert detection["sub_type"] == "sigma"

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Detection Sub Type": "None", "Incident ID": "None"},
        entities=[make_entity("1.1.1.1", EntityTypes.ADDRESS)],
    )
    def test_omits_the_fields_left_on_the_unset_dropdown_option(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """The literal "None" a dropdown sends must not reach the API.

        Submitting it verbatim would record a detection sub type of "None"
        against the customer's insights.
        """
        SubmitCollectiveInsights.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED

        submitted = recorded_future.collective_insights[0]["data"][0]
        assert submitted["detection"]["type"] == CI_DETECTION_TYPE
        assert "sub_type" not in submitted["detection"]
        assert "incident" not in submitted

    @pytest.mark.xfail(
        strict=True,
        reason="Bug: an Incident ID with no Incident Type fails the whole "
        "submission. The Incident Type parameter has no default "
        "(actions/SubmitCollectiveInsights.py:132) so it arrives as None, and "
        "psengine's `IdNameType.type_` is annotated `str` - passing None "
        "explicitly is a ValidationError, not a defaulted field. "
        "`CI_INCIDENT_TYPE` exists in core/constants.py for this and is what "
        "the connectors send. Remove this marker once the parameter defaults "
        "to it.",
    )
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Incident ID": "4242", "Incident Name": "Suspicious outbound traffic"},
        entities=[make_entity("1.1.1.1", EntityTypes.ADDRESS)],
    )
    def test_submits_an_incident_id_without_being_told_its_type(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        SubmitCollectiveInsights.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert recorded_future.collective_insights[0]["data"][0]["incident"]["id"] == "4242"

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Timestamp": "2026-09-01T03:04:05Z"},
        entities=[make_entity("1.1.1.1", EntityTypes.ADDRESS)],
    )
    def test_records_the_source_events_own_timestamp(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """When the source tool supplied a detection time, that is what is sent.

        Recorded Future records this as when the detection happened, so
        stamping it with the action's run time would misreport it.
        """
        SubmitCollectiveInsights.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert recorded_future.collective_insights[0]["data"][0]["timestamp"] == ("2026-09-01T03:04:05Z")

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"MITRE Codes": "T1027, T1055", "Malware": "Example Stealer"},
        entities=[make_entity("1.1.1.1", EntityTypes.ADDRESS)],
    )
    def test_splits_the_comma_separated_context_fields(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        SubmitCollectiveInsights.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED

        detection = recorded_future.collective_insights[0]["data"][0]
        assert detection["mitre_codes"] == ["T1027", "T1055"]
        assert detection["malwares"] == ["Example Stealer"]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Debug": True},
        entities=[make_entity("1.1.1.1", EntityTypes.ADDRESS)],
    )
    def test_reports_a_debug_submission_as_such(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """A debug submission is not recorded, so the analyst has to be told."""
        SubmitCollectiveInsights.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert "debug mode" in action_output.results.output_message
        assert recorded_future.collective_insights[0]["options"]["debug"] is True

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={},
        entities=[make_entity("1.1.1.1", EntityTypes.ADDRESS)],
    )
    def test_fails_when_the_api_is_unavailable(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.collective_insights_available = False

        SubmitCollectiveInsights.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False
