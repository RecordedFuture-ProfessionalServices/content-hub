############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the seven Identity Intelligence actions.

Each one either takes its target from a parameter or reads it off the case, and
they disagree about what happens when the case has nothing usable on it. That
disagreement is what these tests pin down.
"""

from __future__ import annotations

import pytest
from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from soar_sdk.SiemplifyDataModel import EntityTypes
from TIPCommon.base.action import ExecutionState

from recorded_future_intelligence.actions import (
    FetchIncidentReport,
    LookupCredentials,
    LookupHostnameCredentials,
    LookupIPCredentials,
    LookupPassword,
    SearchCredentials,
    SearchDump,
)
from recorded_future_intelligence.tests.common import (
    CONFIG_PATH,
    make_credential_search_hit,
    make_dump,
    make_entity,
    make_incident_report,
    make_leaked_identity,
    make_password_exposure,
)
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.core.session import RecordedFutureSession, request_body


def request_to(session: RecordedFutureSession, path: str) -> dict:
    """Return the body of the last request the action sent to `path`.

    Args:
        session: The session the action made its requests through.
        path: The endpoint path.

    Returns:
        The decoded request body.

    """
    matching = [record for record in session.request_history if record.request.url.path == path]
    return request_body(matching[-1].request)


class TestLookupCredentials:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Subjects": "user@example.com", "Max Results": 10},
    )
    def test_returns_the_exposures_for_the_subject(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_leaked_identity(
            "user@example.com",
            make_leaked_identity("user@example.com"),
        )

        LookupCredentials.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True

        exposures = action_output.results.json_output.json_result
        assert exposures[0]["identity"]["subjects"] == ["user@example.com"]
        assert exposures[0]["credentials"][0]["subject"] == "user@example.com"

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Filter on Target Entities": True, "Max Results": 10},
        entities=[
            make_entity("user@example.com", EntityTypes.EMAILMESSAGE),
            make_entity("1.1.1.1", EntityTypes.ADDRESS),
        ],
    )
    def test_reads_only_the_email_entities_off_the_case(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_leaked_identity(
            "user@example.com",
            make_leaked_identity("user@example.com"),
        )

        LookupCredentials.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert request_to(script_session, "/identity/credentials/lookup")["subjects"] == [
            "user@example.com",
        ]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Subjects": "clean@example.com", "Max Results": 10},
    )
    def test_reports_an_unexposed_subject_as_a_success(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """No exposure is the answer an analyst wants, not an error."""
        LookupCredentials.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.json_output.json_result == []

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Subjects": "user@example.com", "Max Results": 10},
    )
    def test_fails_on_a_rejected_token(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.authorized = False

        LookupCredentials.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False


class TestLookupHostnameCredentials:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Hostname": "workstation-1", "Max Results": 10},
    )
    def test_returns_the_exposures_for_the_hostname(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_leaked_identity(
            "workstation-1",
            make_leaked_identity("user@example.com"),
        )

        LookupHostnameCredentials.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert request_to(script_session, "/identity/hostname/lookup")["hostname"] == "workstation-1"
        assert len(action_output.results.json_output.json_result) == 1

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Filter on Target Entities": True, "Max Results": 10},
        entities=[
            make_entity("workstation-1", EntityTypes.HOSTNAME),
            make_entity("workstation-2", EntityTypes.HOSTNAME),
        ],
    )
    def test_looks_up_only_the_first_of_several_case_entities(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """The endpoint takes one hostname, so the rest of the case is ignored.

        The action logs that it is doing so, but a case with several affected
        machines still only gets one of them looked up.
        """
        recorded_future.set_leaked_identity(
            "workstation-1",
            make_leaked_identity("user@example.com"),
        )

        LookupHostnameCredentials.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert request_to(script_session, "/identity/hostname/lookup")["hostname"] == "workstation-1"

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Filter on Target Entities": True, "Max Results": 10},
        entities=[make_entity("1.1.1.1", EntityTypes.ADDRESS)],
    )
    def test_takes_the_first_case_entity_whatever_its_type(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """The case entity is not filtered by type before being used.

        Unlike Lookup Credentials, which picks the email entities out, this
        action takes whatever is first - so an IP on the case is sent to the
        API as a hostname. Asserted as-is: the API answers with no exposures
        rather than an error, so the run succeeds with an empty result and the
        analyst is told nothing was found.
        """
        LookupHostnameCredentials.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert request_to(script_session, "/identity/hostname/lookup")["hostname"] == "1.1.1.1"
        assert action_output.results.json_output.json_result == []

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Filter on Target Entities": True, "Max Results": 10},
    )
    def test_reports_an_empty_case_as_a_failure(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """Asked to read the case with nothing on it, the action stops.

        It indexes the first target entity, so an empty case raises an
        IndexError - which the action catches and reports rather than sending
        a request with no hostname in it.
        """
        LookupHostnameCredentials.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert "target entities" in action_output.results.output_message
        assert script_session.request_history == []


class TestLookupIPCredentials:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"IP": "1.1.1.1"},
    )
    def test_returns_the_exposures_for_the_ip(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_leaked_identity("1.1.1.1", make_leaked_identity("user@example.com"))

        LookupIPCredentials.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert request_to(script_session, "/identity/ip/lookup")["ip"] == "1.1.1.1"
        assert len(action_output.results.json_output.json_result) == 1

    @pytest.mark.xfail(
        strict=True,
        reason="Bug: a Max Results of 10 makes the lookup fail with KeyError: "
        "'limit'. `IdentityMgr.lookup_ip` dumps its payload with "
        "`exclude_defaults=True`, and the limit it computes - "
        "`min(max_results, 20)` - equals psengine's own default of 10 at that "
        "setting, so `limit` is dropped from the body; "
        "`RFClient.request_paged` then reads `data['limit']` unguarded. Only "
        "bites once the API has exposures to report, because an empty result "
        "returns before that line. Remove this marker once fixed.",
    )
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"IP": "1.1.1.1", "Max Results": 10},
    )
    def test_honours_a_max_results_of_ten(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_leaked_identity("1.1.1.1", make_leaked_identity("user@example.com"))

        LookupIPCredentials.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert len(action_output.results.json_output.json_result) == 1

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"IP": "not-an-ip"},
    )
    def test_sends_a_value_that_is_not_an_ip_anyway(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        """Neither the action nor psengine checks that the IP is one.

        psengine types the field as a plain string, so a typo reaches the API
        and comes back as "no exposures" - indistinguishable, to a playbook,
        from a clean IP. Asserted as-is rather than xfailed: validating the
        parameter is the action's call to make, not a defect in what it does
        with what it was given.
        """
        LookupIPCredentials.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert request_to(script_session, "/identity/ip/lookup")["ip"] == "not-an-ip"
        assert action_output.results.json_output.json_result == []

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Filter on Target Entities": True, "Max Results": 10},
    )
    def test_reports_an_empty_case_as_a_failure(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        LookupIPCredentials.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert script_session.request_history == []


class TestLookupPassword:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Algorithm": "SHA1"},
        entities=[make_entity("abc123", EntityTypes.FILEHASH)],
    )
    def test_returns_the_exposure_status_of_the_cases_hashes(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_password_exposure(
            "abc123",
            make_password_exposure("abc123", exposure_status="Common"),
        )

        LookupPassword.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True
        assert "1 hash(es)" in action_output.results.output_message

        results = action_output.results.json_output.json_result
        assert results[0]["exposure_status"] == "Common"

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Algorithm": "SHA1"},
        entities=[
            make_entity("abc123", EntityTypes.FILEHASH),
            make_entity("user@example.com", EntityTypes.EMAILMESSAGE),
        ],
    )
    def test_ignores_case_entities_that_are_not_hashes(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_password_exposure("abc123", make_password_exposure("abc123"))

        LookupPassword.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert [
            password["hash_prefix"] for password in request_to(script_session, "/identity/password/lookup")["passwords"]
        ] == ["abc123"]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Algorithm": "SHA1"},
        entities=[make_entity("abc123", EntityTypes.FILEHASH)],
    )
    def test_reports_a_hash_the_api_holds_nothing_on_as_a_success(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        LookupPassword.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.json_output.json_result == []
        assert "0 hash(es)" in action_output.results.output_message


class TestSearchCredentials:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Domains": "example.com", "Max Results": 10},
    )
    def test_returns_the_exposed_logins_of_the_domain(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_credential_search(
            "example.com",
            [
                make_credential_search_hit("user", "example.com"),
                make_credential_search_hit("admin", "example.com"),
            ],
        )

        SearchCredentials.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert [hit["login"] for hit in action_output.results.json_output.json_result] == [
            "user",
            "admin",
        ]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Filter on Target Entities": True, "Max Results": 10},
        entities=[
            make_entity("example.com", EntityTypes.DOMAIN),
            make_entity("1.1.1.1", EntityTypes.ADDRESS),
        ],
    )
    def test_reads_only_the_domain_entities_off_the_case(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_credential_search(
            "example.com",
            [make_credential_search_hit("user", "example.com")],
        )

        SearchCredentials.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert request_to(script_session, "/identity/credentials/search")["domains"] == [
            "example.com",
        ]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Domains": "clean.example.com", "Max Results": 10},
    )
    def test_reports_a_domain_with_no_exposures_as_a_success(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        SearchCredentials.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.json_output.json_result == []


class TestSearchDump:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Names": "Example Stealer Log", "Max Results": 10},
    )
    def test_returns_the_dump_metadata(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_dump("Example Stealer Log", make_dump("Example Stealer Log"))

        SearchDump.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True
        assert "Found 1 dump(s)" in action_output.results.output_message
        assert action_output.results.json_output.json_result[0]["name"] == "Example Stealer Log"

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Names": "Nothing Known", "Max Results": 10},
    )
    def test_reports_an_unknown_dump_as_a_success(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        SearchDump.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert "Found 0 dump(s)" in action_output.results.output_message

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Names": "Example Stealer Log", "Max Results": 10},
    )
    def test_fails_on_a_rejected_token(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.authorized = False

        SearchDump.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False


class TestFetchIncidentReport:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Source": "Example Stealer Log", "Max Results": 10},
    )
    def test_returns_the_report_for_the_malware_log(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_incident_report(
            "Example Stealer Log",
            make_incident_report("user@example.com"),
        )

        FetchIncidentReport.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True

        report = action_output.results.json_output.json_result
        assert report["credentials"][0]["email_or_login"] == "user@example.com"
        # The endpoint returns the infected machine's details as a list of one,
        # which psengine flattens into a single object.
        assert report["details"]["malware_family"] == "Example Stealer"

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        # "false" as a string, not a bool: `extract_action_param` treats a
        # falsy value as an absent one and would fall back to its default.
        parameters={"Source": "Example Stealer Log", "Include Details": "false", "Max Results": 10},
    )
    def test_can_leave_the_infected_machine_details_out(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_incident_report(
            "Example Stealer Log",
            make_incident_report("user@example.com", include_details=False),
        )

        FetchIncidentReport.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert request_to(script_session, "/identity/incident/report")["include_details"] is False
        assert "details" not in action_output.results.json_output.json_result

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Source": "Nothing Known", "Max Results": 10},
    )
    def test_fails_on_a_source_the_api_does_not_hold(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        FetchIncidentReport.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False
