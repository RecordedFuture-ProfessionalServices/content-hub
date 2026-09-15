############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the status sync machinery shared by both Recorded Future sync jobs.

The classic alert job is used as the concrete vehicle because its
`_fetch_product_statuses` is the simpler of the two; the behaviour under test
lives entirely in `RecordedFutureBaseSyncJob`.
"""

from __future__ import annotations

import json

import pytest
from TIPCommon.data_models import CaseDataStatus

from recorded_future_intelligence.core.constants import (
    CLASSIC_ALERT_PRODUCT,
    PLAYBOOK_ALERT_PRODUCT,
    SYNC_CASE_CLOSE_REASON,
    SYNC_COMMENT_PREFIX,
    SYNC_DEFAULT_CLOSE_REASON,
    SYNC_DEFAULT_CLOSE_ROOT_CAUSE,
    SYNC_DEFAULT_MAX_HOURS_BACKWARDS,
    SYNC_OUTBOUND_CLOSED_STATUS,
    SYNC_REOPEN_ALERT_ENDPOINT,
    SYNC_REOPEN_CASE_ENDPOINT,
    SYNC_STATE_CLOSED_BY_JOB_KEY,
    SYNC_STATE_PRODUCT_ID_KEY,
    SYNC_STATE_STATUS_KEY,
)
from recorded_future_intelligence.core.RecordedFutureSyncCommon import (
    is_soar_alert_closed,
)
from recorded_future_intelligence.jobs.SyncClassicAlertStatus import (
    SyncClassicAlertStatusJob,
)

from ..common import SOAR_API_ROOT, build_job, make_alert, make_job_case, make_params


@pytest.fixture(name="job")
def sync_job() -> SyncClassicAlertStatusJob:
    """Provide a classic alert sync job wired to doubles."""
    return build_job(SyncClassicAlertStatusJob)


def _statuses(job: SyncClassicAlertStatusJob, mapping: dict[str, str]) -> None:
    """Make the job report the given Recorded Future statuses."""
    job._fetch_product_statuses = lambda alert_ids: {  # type: ignore[method-assign]
        alert_id: mapping[alert_id] for alert_id in alert_ids if alert_id in mapping
    }


# ---------------------------------------------------------------------------
# Job wiring
# ---------------------------------------------------------------------------


def test_job_uses_no_tag_prefilter(job: SyncClassicAlertStatusJob) -> None:
    """The Recorded Future connectors do not tag cases, so there is no prefilter."""
    assert job.tags_identifiers == []


def test_state_context_identifier_is_distinct_from_tracked_ids(
    job: SyncClassicAlertStatusJob,
) -> None:
    """Sync state must not overwrite BaseSyncJob's tracked-ID context entry."""
    assert job.state_context_identifier != job.context_identifier
    assert job.state_context_identifier.startswith(job.context_identifier)


# ---------------------------------------------------------------------------
# Parameter normalization
# ---------------------------------------------------------------------------


def test_validate_params_normalizes_cleared_optional_params() -> None:
    """Optional parameters cleared by the operator fall back to their defaults."""
    job = build_job(
        SyncClassicAlertStatusJob,
        params=make_params(
            max_hours_backwards=None,
            closed_alert_reason="",
            closed_alert_root_cause="",
            close_case_when_all_alerts_closed="",
        ),
    )

    job._validate_params()

    assert job.params.max_hours_backwards == SYNC_DEFAULT_MAX_HOURS_BACKWARDS
    assert job.params.closed_alert_reason == SYNC_DEFAULT_CLOSE_REASON
    assert job.params.closed_alert_root_cause == SYNC_DEFAULT_CLOSE_ROOT_CAUSE
    assert job.params.close_case_when_all_alerts_closed is False


def test_validate_params_keeps_operator_supplied_values() -> None:
    """Explicit parameter values survive normalization."""
    job = build_job(
        SyncClassicAlertStatusJob,
        params=make_params(
            max_hours_backwards=72,
            closed_alert_reason="Malicious",
            closed_alert_root_cause="Confirmed threat",
            close_case_when_all_alerts_closed=True,
        ),
    )

    job._validate_params()

    assert job.params.max_hours_backwards == 72
    assert job.params.closed_alert_reason == "Malicious"
    assert job.params.closed_alert_root_cause == "Confirmed threat"
    assert job.params.close_case_when_all_alerts_closed is True


# ---------------------------------------------------------------------------
# Alert ownership and product ID extraction
# ---------------------------------------------------------------------------


def test_extract_product_ids_returns_only_owned_alerts(
    job: SyncClassicAlertStatusJob,
) -> None:
    """Only alerts from this job's alert family contribute product IDs."""
    job_case = make_job_case(
        [
            make_alert("a-1", "classic-2"),
            make_alert("a-2", "classic-1"),
            make_alert("a-3", "playbook-1", device_product=PLAYBOOK_ALERT_PRODUCT),
            make_alert("a-4", "other-1", device_product="Some Other Product"),
        ],
    )

    assert job._extract_product_ids_from_case(job_case) == ["classic-1", "classic-2"]


def test_extract_product_ids_deduplicates_and_drops_missing_ids(
    job: SyncClassicAlertStatusJob,
) -> None:
    """Duplicate Recorded Future IDs collapse and alerts without one are dropped."""
    job_case = make_job_case(
        [
            make_alert("a-1", "classic-1"),
            make_alert("a-2", "classic-1"),
            make_alert("a-3", None),
        ],
    )

    assert job._extract_product_ids_from_case(job_case) == ["classic-1"]


def test_extract_product_ids_returns_empty_for_unrelated_case(
    job: SyncClassicAlertStatusJob,
) -> None:
    """A case with no Recorded Future classic alerts yields no product IDs.

    This is what keeps BaseSyncJob from tracking cases the job does not own.
    """
    job_case = make_job_case(
        [make_alert("a-1", "playbook-1", device_product=PLAYBOOK_ALERT_PRODUCT)],
    )

    assert job._extract_product_ids_from_case(job_case) == []


# ---------------------------------------------------------------------------
# map_product_data_to_case
# ---------------------------------------------------------------------------


def test_map_product_data_attaches_statuses_to_owned_alerts(
    job: SyncClassicAlertStatusJob,
) -> None:
    """Fetched Recorded Future statuses land on the matching alert metadata."""
    owned = make_alert("a-1", "classic-1")
    foreign = make_alert("a-2", "playbook-1", device_product=PLAYBOOK_ALERT_PRODUCT)
    job_case = make_job_case([owned, foreign])
    _statuses(job, {"classic-1": "New", "playbook-1": "Resolved"})

    job.map_product_data_to_case(job_case)

    assert job_case.product_ids_from_secops_alerts == {"classic-1": owned}
    assert job_case.alert_metadata["a-1"].status == "New"
    assert job_case.alert_metadata["a-1"].incident_id == "classic-1"
    assert "a-2" not in job_case.alert_metadata


def test_map_product_data_omits_alerts_with_no_status(
    job: SyncClassicAlertStatusJob,
) -> None:
    """An alert whose status could not be read gets no metadata."""
    job_case = make_job_case([make_alert("a-1", "classic-1")])
    _statuses(job, {})

    job.map_product_data_to_case(job_case)

    assert job_case.alert_metadata == {}


def test_map_product_data_is_a_noop_for_unowned_case(
    job: SyncClassicAlertStatusJob,
) -> None:
    """No Recorded Future call is made for a case with no owned alerts."""
    job_case = make_job_case(
        [make_alert("a-1", "playbook-1", device_product=PLAYBOOK_ALERT_PRODUCT)],
    )

    job.map_product_data_to_case(job_case)

    assert job.api_client.alerts.fetch_bulk.call_count == 0


def test_map_product_data_records_failed_case_on_api_error(
    job: SyncClassicAlertStatusJob,
) -> None:
    """A Recorded Future read failure marks the case rather than raising."""
    job_case = make_job_case([make_alert("a-1", "classic-1")])

    def boom(alert_ids: list[str]) -> dict[str, str]:
        raise RuntimeError("Recorded Future is unreachable")

    job._fetch_product_statuses = boom  # type: ignore[method-assign]

    job.map_product_data_to_case(job_case)

    assert job_case.case_detail.id_ in job.failed_cases


def test_sync_status_skips_failed_cases(job: SyncClassicAlertStatusJob) -> None:
    """A case whose Recorded Future data could not be read is left untouched."""
    alert = make_alert("a-1", "classic-1")
    job_case = make_job_case([alert])
    job.failed_cases.add(job_case.case_detail.id_)

    job.sync_status(job_case)

    assert job.soar_job.close_alert.call_count == 0
    assert job.api_client.update_alert.call_count == 0


# ---------------------------------------------------------------------------
# Inbound: Recorded Future -> Google SecOps
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("terminal_status", ["Resolved", "Dismissed"])
def test_inbound_closes_open_alert_for_terminal_status(
    job: SyncClassicAlertStatusJob,
    terminal_status: str,
) -> None:
    """Both terminal Recorded Future statuses close the Google SecOps alert."""
    alert = make_alert("a-1", "classic-1", status="opened")
    job_case = make_job_case([alert])
    _statuses(job, {"classic-1": terminal_status})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    job.soar_job.close_alert.assert_called_once()
    kwargs = job.soar_job.close_alert.call_args.args
    assert kwargs[0] == SYNC_DEFAULT_CLOSE_ROOT_CAUSE
    assert SYNC_COMMENT_PREFIX in kwargs[1]
    assert terminal_status in kwargs[1]
    assert kwargs[2] == SYNC_DEFAULT_CLOSE_REASON
    assert job.alert_state["a-1"][SYNC_STATE_CLOSED_BY_JOB_KEY] is True
    assert job.alert_state["a-1"][SYNC_STATE_STATUS_KEY] == terminal_status
    assert job.alert_state["a-1"][SYNC_STATE_PRODUCT_ID_KEY] == "classic-1"


def test_inbound_close_uses_configured_reason_and_root_cause() -> None:
    """The closure reason and root cause come from the job parameters."""
    job = build_job(
        SyncClassicAlertStatusJob,
        params=make_params(
            closed_alert_reason="Malicious",
            closed_alert_root_cause="Confirmed threat",
        ),
    )
    job_case = make_job_case([make_alert("a-1", "classic-1")])
    _statuses(job, {"classic-1": "Resolved"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    args = job.soar_job.close_alert.call_args.args
    assert args[0] == "Confirmed threat"
    assert args[2] == "Malicious"


def test_inbound_does_not_reclose_an_already_closed_alert(
    job: SyncClassicAlertStatusJob,
) -> None:
    """A Google SecOps alert that is already closed is left alone."""
    job_case = make_job_case([make_alert("a-1", "classic-1", status="closed")])
    _statuses(job, {"classic-1": "Resolved"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    assert job.soar_job.close_alert.call_count == 0


def test_inbound_leaves_open_alert_open_for_non_terminal_status(
    job: SyncClassicAlertStatusJob,
) -> None:
    """A non-terminal Recorded Future status only records state."""
    job_case = make_job_case([make_alert("a-1", "classic-1", status="opened")])
    _statuses(job, {"classic-1": "Pending"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    assert job.soar_job.close_alert.call_count == 0
    assert job.soar_job.session.post.call_count == 0
    assert job.alert_state["a-1"][SYNC_STATE_STATUS_KEY] == "Pending"


def test_inbound_reopens_alert_the_job_closed(job: SyncClassicAlertStatusJob) -> None:
    """An alert this job closed is reopened when Recorded Future reopens."""
    job.alert_state = {
        "a-1": {
            SYNC_STATE_STATUS_KEY: "Resolved",
            SYNC_STATE_CLOSED_BY_JOB_KEY: True,
            SYNC_STATE_PRODUCT_ID_KEY: "classic-1",
        },
    }
    alert = make_alert("a-1", "classic-1", status="closed")
    job_case = make_job_case([alert])
    _statuses(job, {"classic-1": "New"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    post_urls = [call.args[0] for call in job.soar_job.session.post.call_args_list]
    assert f"{SOAR_API_ROOT}/{SYNC_REOPEN_ALERT_ENDPOINT}" in post_urls
    assert alert.status == "open"
    assert job.alert_state["a-1"][SYNC_STATE_CLOSED_BY_JOB_KEY] is False
    job.soar_job.add_comment.assert_called_once()
    assert "reopened" in job.soar_job.add_comment.call_args.kwargs["comment"]


def test_inbound_does_not_reopen_an_analyst_closed_alert(
    job: SyncClassicAlertStatusJob,
) -> None:
    """An alert closed by an analyst is never reopened by the job."""
    job.alert_state = {
        "a-1": {
            SYNC_STATE_STATUS_KEY: "New",
            SYNC_STATE_CLOSED_BY_JOB_KEY: False,
            SYNC_STATE_PRODUCT_ID_KEY: "classic-1",
        },
    }
    job_case = make_job_case([make_alert("a-1", "classic-1", status="closed")])
    _statuses(job, {"classic-1": "New"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    post_urls = [call.args[0] for call in job.soar_job.session.post.call_args_list]
    assert f"{SOAR_API_ROOT}/{SYNC_REOPEN_ALERT_ENDPOINT}" not in post_urls


def test_inbound_does_not_reopen_without_prior_state(
    job: SyncClassicAlertStatusJob,
) -> None:
    """With no recorded state, a closed alert is not reopened."""
    job_case = make_job_case([make_alert("a-1", "classic-1", status="closed")])
    _statuses(job, {"classic-1": "New"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    assert job.soar_job.session.post.call_count == 0


def test_inbound_reopen_also_reopens_a_closed_case(
    job: SyncClassicAlertStatusJob,
) -> None:
    """Reopening an alert inside a closed case reopens the case too."""
    job.alert_state = {
        "a-1": {
            SYNC_STATE_STATUS_KEY: "Resolved",
            SYNC_STATE_CLOSED_BY_JOB_KEY: True,
            SYNC_STATE_PRODUCT_ID_KEY: "classic-1",
        },
    }
    job_case = make_job_case(
        [make_alert("a-1", "classic-1", status="closed")],
        status=CaseDataStatus.CLOSED,
    )
    _statuses(job, {"classic-1": "New"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    post_urls = [call.args[0] for call in job.soar_job.session.post.call_args_list]
    assert f"{SOAR_API_ROOT}/{SYNC_REOPEN_CASE_ENDPOINT}" in post_urls


# ---------------------------------------------------------------------------
# Outbound: Google SecOps -> Recorded Future
# ---------------------------------------------------------------------------


def test_outbound_resolves_recorded_future_when_analyst_closes_alert(
    job: SyncClassicAlertStatusJob,
) -> None:
    """An analyst-closed alert sets its Recorded Future alert to Resolved."""
    job_case = make_job_case([make_alert("a-1", "classic-1", status="closed")])
    _statuses(job, {"classic-1": "New"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    job.api_client.update_alert.assert_called_once()
    assert job.api_client.update_alert.call_args.kwargs["status"] == (
        SYNC_OUTBOUND_CLOSED_STATUS
    )
    assert job.alert_state["a-1"][SYNC_STATE_STATUS_KEY] == SYNC_OUTBOUND_CLOSED_STATUS


def test_outbound_resolves_recorded_future_when_case_is_closed(
    job: SyncClassicAlertStatusJob,
) -> None:
    """A closed case resolves its Recorded Future alerts even if the alert is open."""
    job_case = make_job_case(
        [make_alert("a-1", "classic-1", status="opened")],
        status=CaseDataStatus.CLOSED,
    )
    _statuses(job, {"classic-1": "New"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    job.api_client.update_alert.assert_called_once()
    assert "case" in job.api_client.update_alert.call_args.kwargs["note"]


def test_outbound_skips_when_recorded_future_is_already_terminal(
    job: SyncClassicAlertStatusJob,
) -> None:
    """No redundant write when Recorded Future already holds a terminal status."""
    job_case = make_job_case([make_alert("a-1", "classic-1", status="closed")])
    _statuses(job, {"classic-1": "Dismissed"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    assert job.api_client.update_alert.call_count == 0


def test_outbound_skips_alerts_this_job_closed(job: SyncClassicAlertStatusJob) -> None:
    """The loop breaker: a job-closed alert is never reported back to Recorded Future."""
    job.alert_state = {
        "a-1": {
            SYNC_STATE_STATUS_KEY: "Resolved",
            SYNC_STATE_CLOSED_BY_JOB_KEY: True,
            SYNC_STATE_PRODUCT_ID_KEY: "classic-1",
        },
    }
    job_case = make_job_case([make_alert("a-1", "classic-1", status="closed")])
    # Recorded Future has since moved off the terminal status, but this alert
    # was closed on Recorded Future's behalf, so there is nothing to report.
    _statuses(job, {"classic-1": "Pending"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    assert job.api_client.update_alert.call_count == 0


def test_inbound_close_does_not_immediately_trigger_outbound(
    job: SyncClassicAlertStatusJob,
) -> None:
    """Closing inbound must not push the same status straight back out."""
    job_case = make_job_case([make_alert("a-1", "classic-1", status="opened")])
    _statuses(job, {"classic-1": "Resolved"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    job.soar_job.close_alert.assert_called_once()
    assert job.api_client.update_alert.call_count == 0


def test_outbound_skips_open_alert_in_open_case(job: SyncClassicAlertStatusJob) -> None:
    """Nothing is pushed while both the alert and its case are open."""
    job_case = make_job_case([make_alert("a-1", "classic-1", status="opened")])
    _statuses(job, {"classic-1": "New"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    assert job.api_client.update_alert.call_count == 0


def test_outbound_failure_does_not_advance_state(
    job: SyncClassicAlertStatusJob,
) -> None:
    """A failed Recorded Future write leaves the state ready to retry."""
    job_case = make_job_case([make_alert("a-1", "classic-1", status="closed")])
    _statuses(job, {"classic-1": "New"})
    job.api_client.update_alert.side_effect = RuntimeError("write rejected")

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    assert job.alert_state["a-1"][SYNC_STATE_STATUS_KEY] == "New"
    assert job.soar_job.add_comment.call_count == 0


# ---------------------------------------------------------------------------
# Case level reconciliation
# ---------------------------------------------------------------------------


def test_case_is_not_closed_when_the_option_is_disabled(
    job: SyncClassicAlertStatusJob,
) -> None:
    """Case closure is opt-in, so it does not happen by default."""
    job_case = make_job_case([make_alert("a-1", "classic-1", status="opened")])
    _statuses(job, {"classic-1": "Resolved"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    assert job.soar_job.close_case.call_count == 0


def test_case_is_closed_when_the_option_is_enabled() -> None:
    """With the option enabled, a fully closed case is closed."""
    job = build_job(
        SyncClassicAlertStatusJob,
        params=make_params(close_case_when_all_alerts_closed=True),
    )
    job_case = make_job_case([make_alert("a-1", "classic-1", status="opened")])
    job._fetch_product_statuses = lambda alert_ids: {"classic-1": "Resolved"}  # type: ignore[method-assign]

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    job.soar_job.close_case.assert_called_once()
    assert job.soar_job.close_case.call_args.kwargs["reason"] == SYNC_CASE_CLOSE_REASON


def test_case_is_not_closed_while_another_alert_is_open() -> None:
    """A case with an unrelated open alert stays open."""
    job = build_job(
        SyncClassicAlertStatusJob,
        params=make_params(close_case_when_all_alerts_closed=True),
    )
    job_case = make_job_case(
        [
            make_alert("a-1", "classic-1", status="opened"),
            make_alert("a-2", None, device_product="Some Other Product", status="opened"),
        ],
    )
    job._fetch_product_statuses = lambda alert_ids: {"classic-1": "Resolved"}  # type: ignore[method-assign]

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    assert job.soar_job.close_case.call_count == 0


# ---------------------------------------------------------------------------
# Sync state persistence
# ---------------------------------------------------------------------------


def test_read_alert_state_returns_empty_when_unset(
    job: SyncClassicAlertStatusJob,
) -> None:
    """A first run starts from an empty state."""
    job.soar_job.get_job_context_property.return_value = None

    assert job._read_alert_state() == {}


def test_read_alert_state_parses_stored_json(job: SyncClassicAlertStatusJob) -> None:
    """Stored state round-trips out of the job context."""
    stored = {"a-1": {SYNC_STATE_STATUS_KEY: "Resolved"}}
    job.soar_job.get_job_context_property.return_value = json.dumps(stored)

    assert job._read_alert_state() == stored


@pytest.mark.parametrize("corrupt", ["not json", "[1, 2, 3]", '"a string"'])
def test_read_alert_state_recovers_from_unusable_context(
    job: SyncClassicAlertStatusJob,
    corrupt: str,
) -> None:
    """Corrupt or wrongly shaped state is discarded rather than raising."""
    job.soar_job.get_job_context_property.return_value = corrupt

    assert job._read_alert_state() == {}


def test_write_alert_state_persists_json(job: SyncClassicAlertStatusJob) -> None:
    """State is written back as JSON under the state context key."""
    job.alert_state = {"a-1": {SYNC_STATE_STATUS_KEY: "New"}}

    job._write_alert_state()

    kwargs = job.soar_job.set_job_context_property.call_args.kwargs
    assert kwargs["property_key"] == job.state_context_identifier
    assert json.loads(kwargs["property_value"]) == job.alert_state


def test_cached_product_statuses_indexes_by_recorded_future_id(
    job: SyncClassicAlertStatusJob,
) -> None:
    """The cache is keyed by Recorded Future alert ID, skipping partial entries."""
    job.alert_state = {
        "a-1": {
            SYNC_STATE_STATUS_KEY: "New",
            SYNC_STATE_PRODUCT_ID_KEY: "classic-1",
        },
        "a-2": {SYNC_STATE_STATUS_KEY: "Resolved"},
        "a-3": {SYNC_STATE_PRODUCT_ID_KEY: "classic-3"},
    }

    assert job.cached_product_statuses() == {"classic-1": "New"}


# ---------------------------------------------------------------------------
# Tracked pair cleanup
# ---------------------------------------------------------------------------


def test_is_alert_and_product_closed_requires_both_sides(
    job: SyncClassicAlertStatusJob,
) -> None:
    """The pair only counts as closed when Recorded Future and SecOps agree."""
    alert = make_alert("a-1", "classic-1", status="closed")
    job_case = make_job_case([alert])
    _statuses(job, {"classic-1": "Resolved"})
    job.map_product_data_to_case(job_case)

    assert job.is_alert_and_product_closed(job_case, "classic-1") is True

    alert.status = "opened"
    assert job.is_alert_and_product_closed(job_case, "classic-1") is False


def test_is_alert_and_product_closed_false_for_unknown_product(
    job: SyncClassicAlertStatusJob,
) -> None:
    """An untracked Recorded Future ID is not considered closed."""
    job_case = make_job_case([make_alert("a-1", "classic-1", status="closed")])

    assert job.is_alert_and_product_closed(job_case, "classic-999") is False


def test_remove_synced_data_forgets_the_alert_state(
    job: SyncClassicAlertStatusJob,
) -> None:
    """Closed pairs are dropped so the state dictionary stays bounded."""
    job_case = make_job_case([make_alert("a-1", "classic-1", status="closed")])
    _statuses(job, {"classic-1": "Resolved"})
    job.map_product_data_to_case(job_case)
    job.alert_state["a-1"] = {SYNC_STATE_STATUS_KEY: "Resolved"}

    job.remove_synced_data_from_db(job_case, "classic-1")

    assert "a-1" not in job.alert_state


# ---------------------------------------------------------------------------
# Deliberate no-ops
# ---------------------------------------------------------------------------


def test_unsynced_fields_are_noops(job: SyncClassicAlertStatusJob) -> None:
    """These jobs sync status only; the other hooks must do nothing."""
    job_case = make_job_case([make_alert("a-1", "classic-1")])

    job.sync_comments(job_case)
    job.sync_tags(job_case)
    job.sync_severity(job_case)
    job.sync_assignee(job_case)

    assert job.soar_job.add_comment.call_count == 0
    assert job.soar_job.assign_case.call_count == 0
    assert job.api_client.update_alert.call_count == 0


def test_device_products_do_not_overlap() -> None:
    """The two jobs must not both claim the same Google SecOps alerts."""
    assert CLASSIC_ALERT_PRODUCT != PLAYBOOK_ALERT_PRODUCT


# ---------------------------------------------------------------------------
# Alert status interpretation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("closed_status", ["close", "closed", "Closed", "CLOSE"])
def test_closed_alert_statuses_are_recognized(closed_status: str) -> None:
    """Both TIPCommon's "close" and the platform's "closed" count as closed."""
    assert is_soar_alert_closed(make_alert("a-1", "classic-1", status=closed_status))


@pytest.mark.parametrize("open_status", ["open", "opened", "New", 0, None, ""])
def test_unrecognized_alert_status_is_treated_as_open(open_status: object) -> None:
    """An absent or unknown status must never be read as closed.

    `AlertCard.from_json` defaults the status to `0`. Reading that as closed
    would make the job push Resolved to Recorded Future for live alerts, so the
    ambiguous case has to fail towards open.
    """
    alert = make_alert("a-1", "classic-1")
    alert.status = open_status

    assert is_soar_alert_closed(alert) is False


def test_unknown_alert_status_does_not_trigger_an_outbound_write(
    job: SyncClassicAlertStatusJob,
) -> None:
    """The fail-safe holds end to end: a status-less alert is left alone."""
    alert = make_alert("a-1", "classic-1")
    alert.status = 0
    job_case = make_job_case([alert])
    _statuses(job, {"classic-1": "New"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    assert job.api_client.update_alert.call_count == 0
