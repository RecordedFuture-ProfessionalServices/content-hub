############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the Auto Sigma and Auto YARA rule generation actions.

Both create a job and then poll it to completion, so the interesting cases are
what they submit and what they do with a job that does not finish cleanly.
"""

from __future__ import annotations

from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from soar_sdk.SiemplifyDataModel import EntityTypes
from TIPCommon.base.action import ExecutionState

from recorded_future_intelligence.actions import CreateAutoSigmaRule, CreateAutoYARARule
from recorded_future_intelligence.tests.common import (
    CONFIG_PATH,
    make_entity,
    make_sigma_job,
    make_yara_job,
)
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.core.session import RecordedFutureSession

SHA256 = "a" * 64

SIGMA_PARAMETERS = {
    "Job Name": "SOAR Sigma job",
    "Query": "malwareFamily:ExampleStealer",
    "Start Date": "2026-08-01",
}


class TestCreateAutoSigmaRule:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters=SIGMA_PARAMETERS,
    )
    def test_creates_the_job_and_returns_the_finished_rule(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_sigma_job("sigma-job-1", make_sigma_job("sigma-job-1"))

        CreateAutoSigmaRule.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True
        assert "sigma-job-1" in action_output.results.output_message
        assert action_output.results.json_output.json_result["status"] == "FINISHED"

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={**SIGMA_PARAMETERS, "End Date": "2026-09-01"},
    )
    def test_submits_the_query_and_date_range(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_sigma_job("sigma-job-1", make_sigma_job("sigma-job-1"))

        CreateAutoSigmaRule.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert recorded_future.rule_job_requests == [
            {
                "kind": "sigma",
                "name": "SOAR Sigma job",
                "query": "malwareFamily:ExampleStealer",
                "start_date": "2026-08-01",
                "end_date": "2026-09-01",
            },
        ]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters=SIGMA_PARAMETERS,
    )
    def test_omits_an_end_date_it_was_not_given(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """An open-ended range is sent as no end date, not as an empty one."""
        recorded_future.set_sigma_job("sigma-job-1", make_sigma_job("sigma-job-1"))

        CreateAutoSigmaRule.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert "end_date" not in recorded_future.rule_job_requests[0]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters=SIGMA_PARAMETERS,
    )
    def test_fails_when_the_job_fails(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_sigma_job(
            "sigma-job-1",
            make_sigma_job("sigma-job-1", status="FAILED"),
        )

        CreateAutoSigmaRule.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters=SIGMA_PARAMETERS,
    )
    def test_fails_on_a_rejected_token(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.authorized = False

        CreateAutoSigmaRule.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert recorded_future.rule_job_requests == []


class TestCreateAutoYARARule:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Job Name": "SOAR YARA job"},
        entities=[make_entity(SHA256, EntityTypes.FILEHASH)],
    )
    def test_creates_the_job_from_the_cases_hashes(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_yara_job("yara-job-1", make_yara_job("yara-job-1"))

        CreateAutoYARARule.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True
        assert "yara-job-1" in action_output.results.output_message
        assert recorded_future.rule_job_requests == [
            {"kind": "yara", "hashes": [SHA256], "name": "SOAR YARA job"},
        ]
        assert action_output.results.json_output.json_result["job"]["yara_rule_str"]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Job Name": "SOAR YARA job"},
        entities=[
            make_entity(SHA256, EntityTypes.FILEHASH),
            make_entity("1.1.1.1", EntityTypes.ADDRESS),
        ],
    )
    def test_ignores_case_entities_that_are_not_hashes(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_yara_job("yara-job-1", make_yara_job("yara-job-1"))

        CreateAutoYARARule.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert recorded_future.rule_job_requests[0]["hashes"] == [SHA256]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Job Name": "SOAR YARA job"},
        entities=[make_entity(SHA256, EntityTypes.FILEHASH)],
    )
    def test_fails_when_the_job_fails(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """A failed job has no rule in it, so the action must not report one."""
        recorded_future.set_yara_job(
            "yara-job-1",
            make_yara_job("yara-job-1", status="FAILED", rule=None),
        )

        CreateAutoYARARule.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Job Name": "SOAR YARA job"},
        entities=[make_entity(SHA256, EntityTypes.FILEHASH)],
    )
    def test_fails_on_a_rejected_token(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.authorized = False

        CreateAutoYARARule.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert recorded_future.rule_job_requests == []
