############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for case selection and sync state pruning.

`BaseSyncJob` selects cases by Google SecOps modification time only, and never
calls its own `is_alert_and_product_closed` / `remove_synced_data_from_db`
hooks. Both gaps are closed in `RecordedFutureBaseSyncJob`, so both are
covered here.
"""

from __future__ import annotations

import pytest

from recorded_future_intelligence.core.constants import (
    SYNC_STATE_CLOSED_BY_JOB_KEY,
    SYNC_STATE_PRODUCT_ID_KEY,
    SYNC_STATE_STATUS_KEY,
)
from recorded_future_intelligence.jobs.SyncClassicAlertStatus import (
    SyncClassicAlertStatusJob,
)

from ..common import build_job, make_alert, make_job_case


@pytest.fixture(name="job")
def sync_job() -> SyncClassicAlertStatusJob:
    """Provide a classic alert sync job with the iteration clock primed."""
    job = build_job(SyncClassicAlertStatusJob)
    job._cached_unix_now = 1_700_000_500_000
    return job


def _statuses(job: SyncClassicAlertStatusJob, mapping: dict[str, str]) -> None:
    """Make the job report the given Recorded Future statuses."""
    job._fetch_product_statuses = lambda alert_ids: {  # type: ignore[method-assign]
        alert_id: mapping[alert_id] for alert_id in alert_ids if alert_id in mapping
    }


# ---------------------------------------------------------------------------
# statuses_for caching
# ---------------------------------------------------------------------------


def test_statuses_for_reads_each_alert_once(job: SyncClassicAlertStatusJob) -> None:
    """Case selection and per-case syncing must not double-read the same alert."""
    calls: list[list[str]] = []

    def record(alert_ids: list[str]) -> dict[str, str]:
        calls.append(list(alert_ids))
        return {alert_id: "New" for alert_id in alert_ids}

    job._fetch_product_statuses = record  # type: ignore[method-assign]

    assert job.statuses_for(["classic-1"]) == {"classic-1": "New"}
    assert job.statuses_for(["classic-1", "classic-2"]) == {
        "classic-1": "New",
        "classic-2": "New",
    }
    assert calls == [["classic-1"], ["classic-2"]]


def test_statuses_for_omits_unresolvable_ids(job: SyncClassicAlertStatusJob) -> None:
    """IDs Recorded Future could not resolve are absent rather than None."""
    _statuses(job, {"classic-1": "New"})

    assert job.statuses_for(["classic-1", "classic-2"]) == {"classic-1": "New"}


# ---------------------------------------------------------------------------
# Recorded Future driven case selection
# ---------------------------------------------------------------------------


def test_recorded_future_status_change_selects_the_case(
    job: SyncClassicAlertStatusJob,
) -> None:
    """A status change made only in Recorded Future pulls its case into the run.

    Without this the inbound direction would only work when the Google SecOps
    case happened to be modified in the same window.
    """
    job.alert_state = {
        "a-1": {
            SYNC_STATE_STATUS_KEY: "New",
            SYNC_STATE_PRODUCT_ID_KEY: "classic-1",
        },
    }
    _statuses(job, {"classic-1": "Resolved"})
    job.soar_job.get_cases_by_ticket_id.return_value = [77]

    assert job.modified_synced_case_ids_by_product(["classic-1"], []) == [
        ("77", job._cached_unix_now),
    ]


def test_unchanged_recorded_future_status_selects_nothing(
    job: SyncClassicAlertStatusJob,
) -> None:
    """An unchanged Recorded Future status adds no extra cases."""
    job.alert_state = {
        "a-1": {
            SYNC_STATE_STATUS_KEY: "New",
            SYNC_STATE_PRODUCT_ID_KEY: "classic-1",
        },
    }
    _statuses(job, {"classic-1": "New"})

    assert job.modified_synced_case_ids_by_product(["classic-1"], []) == []
    assert job.soar_job.get_cases_by_ticket_id.call_count == 0


def test_already_selected_cases_are_not_duplicated(
    job: SyncClassicAlertStatusJob,
) -> None:
    """A case already selected by modification time is not added twice."""
    job.alert_state = {
        "a-1": {
            SYNC_STATE_STATUS_KEY: "New",
            SYNC_STATE_PRODUCT_ID_KEY: "classic-1",
        },
    }
    _statuses(job, {"classic-1": "Resolved"})
    job.soar_job.get_cases_by_ticket_id.return_value = [77]

    result = job.modified_synced_case_ids_by_product(
        ["classic-1"],
        [("77", 1_700_000_000_000)],
    )

    assert result == []


def test_no_tracked_alerts_short_circuits(job: SyncClassicAlertStatusJob) -> None:
    """With nothing tracked yet, no Recorded Future call is made."""
    calls: list[list[str]] = []
    job._fetch_product_statuses = lambda ids: calls.append(list(ids)) or {}  # type: ignore[method-assign]

    assert job.modified_synced_case_ids_by_product([], []) == []
    assert calls == []


def test_status_read_failure_degrades_to_secops_selection(
    job: SyncClassicAlertStatusJob,
) -> None:
    """A Recorded Future outage must not abort the whole iteration."""

    def boom(alert_ids: list[str]) -> dict[str, str]:
        raise RuntimeError("Recorded Future is unreachable")

    job._fetch_product_statuses = boom  # type: ignore[method-assign]

    assert job.modified_synced_case_ids_by_product(["classic-1"], []) == []


def test_hook_is_not_native_so_base_sync_job_uses_it() -> None:
    """`BaseSyncJob` only calls this hook when it has been overridden."""
    from TIPCommon.base.utils import is_native

    job = build_job(SyncClassicAlertStatusJob)

    assert is_native(job.modified_synced_case_ids_by_product) is False


# ---------------------------------------------------------------------------
# Ticket ID lookup response shapes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ([77, 78], ["77", "78"]),
        ((77,), ["77"]),
        ({"caseIds": [77]}, ["77"]),
        ({"case_ids": [77]}, ["77"]),
        ({"cases": [77]}, ["77"]),
        ([77, None], ["77"]),
        ([], []),
        ({"unexpected": "shape"}, []),
        (None, []),
    ],
)
def test_case_id_lookup_handles_response_shapes(
    job: SyncClassicAlertStatusJob,
    response: object,
    expected: list[str],
) -> None:
    """The ticket ID search response is normalized to a list of case ID strings."""
    job.soar_job.get_cases_by_ticket_id.return_value = response

    assert job._case_ids_for_product_id("classic-1") == expected


def test_case_id_lookup_survives_an_api_error(job: SyncClassicAlertStatusJob) -> None:
    """A failed lookup skips that alert instead of failing case selection."""
    job.soar_job.get_cases_by_ticket_id.side_effect = RuntimeError("search failed")

    assert job._case_ids_for_product_id("classic-1") == []


# ---------------------------------------------------------------------------
# Sync state pruning
# ---------------------------------------------------------------------------


def test_settled_pair_is_dropped_from_state_and_tracking(
    job: SyncClassicAlertStatusJob,
) -> None:
    """A pair closed on both sides by analysts stops being tracked."""
    job_case = make_job_case([make_alert("a-1", "classic-1", status="closed")])
    job.processed_items = {str(job_case.case_detail.id_): ["classic-1"]}
    _statuses(job, {"classic-1": "Dismissed"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    assert "a-1" not in job.alert_state
    assert str(job_case.case_detail.id_) not in job.processed_items


def test_pair_closed_by_the_job_is_still_tracked(
    job: SyncClassicAlertStatusJob,
) -> None:
    """A job-closed pair is kept, because reopening it depends on that state."""
    job.alert_state = {
        "a-1": {
            SYNC_STATE_STATUS_KEY: "Resolved",
            SYNC_STATE_CLOSED_BY_JOB_KEY: True,
            SYNC_STATE_PRODUCT_ID_KEY: "classic-1",
        },
    }
    job_case = make_job_case([make_alert("a-1", "classic-1", status="closed")])
    job.processed_items = {str(job_case.case_detail.id_): ["classic-1"]}
    _statuses(job, {"classic-1": "Resolved"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    assert job.alert_state["a-1"][SYNC_STATE_CLOSED_BY_JOB_KEY] is True
    assert job.processed_items[str(job_case.case_detail.id_)] == ["classic-1"]


def test_open_pair_is_not_pruned(job: SyncClassicAlertStatusJob) -> None:
    """A pair that is still open on either side keeps being tracked."""
    job_case = make_job_case([make_alert("a-1", "classic-1", status="opened")])
    job.processed_items = {str(job_case.case_detail.id_): ["classic-1"]}
    _statuses(job, {"classic-1": "New"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    assert job.alert_state["a-1"][SYNC_STATE_STATUS_KEY] == "New"
    assert job.processed_items[str(job_case.case_detail.id_)] == ["classic-1"]


def test_pruning_keeps_unsettled_siblings_tracked(
    job: SyncClassicAlertStatusJob,
) -> None:
    """Pruning one settled alert must not untrack the rest of the case."""
    job_case = make_job_case(
        [
            make_alert("a-1", "classic-1", status="closed"),
            make_alert("a-2", "classic-2", status="opened"),
        ],
    )
    job.processed_items = {
        str(job_case.case_detail.id_): ["classic-1", "classic-2"],
    }
    _statuses(job, {"classic-1": "Resolved", "classic-2": "New"})

    job.map_product_data_to_case(job_case)
    job.sync_status(job_case)

    assert job.processed_items[str(job_case.case_detail.id_)] == ["classic-2"]
    assert "a-1" not in job.alert_state
    assert "a-2" in job.alert_state
