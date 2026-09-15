############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the Recorded Future playbook alert status sync job."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from recorded_future_intelligence.core.constants import (
    PLAYBOOK_ALERT_API_LIMIT,
    PLAYBOOK_ALERT_PRODUCT,
    PLAYBOOK_ALERT_SYNC_CONTEXT_KEY,
    PLAYBOOK_ALERT_SYNC_JOB_SCRIPT_NAME,
    SYNC_STATE_PRODUCT_ID_KEY,
    SYNC_STATE_STATUS_KEY,
)
from recorded_future_intelligence.jobs.SyncPlaybookAlertStatus import (
    SyncPlaybookAlertStatusJob,
)

from ..common import build_job

# 1_700_000_000_000 ms is the last run time set by `build_job`.
EXPECTED_UPDATED_FROM_PREFIX = "2023-11-14T22:13:20"


def make_search_response(statuses: dict[str, str]) -> SimpleNamespace:
    """Build a stand-in for a psengine playbook alert `SearchResponse`.

    Args:
        statuses (dict[str, str]): Mapping of playbook alert ID to status.

    Returns:
        SimpleNamespace: The search response double.

    """
    return SimpleNamespace(
        data=[
            SimpleNamespace(playbook_alert_id=alert_id, status=status)
            for alert_id, status in statuses.items()
        ],
    )


def make_playbook_alert(status: str | None) -> SimpleNamespace:
    """Build a stand-in for a fetched playbook alert.

    Args:
        status (str | None): The status panel value, or None for an alert with
            no status panel.

    Returns:
        SimpleNamespace: The playbook alert double.

    """
    panel_status = SimpleNamespace(status=status) if status is not None else None
    return SimpleNamespace(panel_status=panel_status)


@pytest.fixture(name="job")
def playbook_job() -> SyncPlaybookAlertStatusJob:
    """Provide a playbook alert sync job wired to doubles."""
    return build_job(SyncPlaybookAlertStatusJob)


def test_job_identity(job: SyncPlaybookAlertStatusJob) -> None:
    """The job claims the playbook alert device product and its own context key."""
    assert job.DEVICE_PRODUCT == PLAYBOOK_ALERT_PRODUCT
    assert job.name == PLAYBOOK_ALERT_SYNC_JOB_SCRIPT_NAME
    assert job.context_identifier == PLAYBOOK_ALERT_SYNC_CONTEXT_KEY


def test_context_key_differs_from_classic_job(
    job: SyncPlaybookAlertStatusJob,
) -> None:
    """The two jobs must not share sync state."""
    from recorded_future_intelligence.core.constants import (
        CLASSIC_ALERT_SYNC_CONTEXT_KEY,
    )

    assert job.context_identifier != CLASSIC_ALERT_SYNC_CONTEXT_KEY


# ---------------------------------------------------------------------------
# Incremental search
# ---------------------------------------------------------------------------


def test_fetch_product_statuses_prefers_the_updated_search(
    job: SyncPlaybookAlertStatusJob,
) -> None:
    """Alerts reported as updated take their status from the search result."""
    job.api_client.playbook_alerts.search.return_value = make_search_response(
        {"task:1": "Resolved"},
    )

    assert job._fetch_product_statuses(["task:1"]) == {"task:1": "Resolved"}
    assert job.api_client.playbook_alerts.fetch.call_count == 0


def test_updated_search_uses_the_last_run_time(
    job: SyncPlaybookAlertStatusJob,
) -> None:
    """`updated_from` is derived from the job's last run time, in seconds."""
    job.api_client.playbook_alerts.search.return_value = make_search_response({})

    job._fetch_product_statuses(["task:1"])

    kwargs = job.api_client.playbook_alerts.search.call_args.kwargs
    assert kwargs["updated_from"].startswith(EXPECTED_UPDATED_FROM_PREFIX)
    assert kwargs["max_results"] == PLAYBOOK_ALERT_API_LIMIT


def test_updated_search_runs_only_once_per_iteration(
    job: SyncPlaybookAlertStatusJob,
) -> None:
    """The search covers every case, so it must not repeat per case."""
    job.api_client.playbook_alerts.search.return_value = make_search_response(
        {"task:1": "New", "task:2": "Resolved"},
    )

    job._fetch_product_statuses(["task:1"])
    job._fetch_product_statuses(["task:2"])

    assert job.api_client.playbook_alerts.search.call_count == 1


# ---------------------------------------------------------------------------
# Cache fallback
# ---------------------------------------------------------------------------


def test_unchanged_alerts_reuse_the_cached_status() -> None:
    """An alert absent from the updated window keeps its last known status.

    This is what makes the incremental search safe: outbound sync still needs
    the Recorded Future status of alerts that did not change.
    """
    job = build_job(
        SyncPlaybookAlertStatusJob,
        alert_state={
            "a-1": {
                SYNC_STATE_STATUS_KEY: "InProgress",
                SYNC_STATE_PRODUCT_ID_KEY: "task:1",
            },
        },
    )
    job.api_client.playbook_alerts.search.return_value = make_search_response({})

    assert job._fetch_product_statuses(["task:1"]) == {"task:1": "InProgress"}
    assert job.api_client.playbook_alerts.fetch.call_count == 0


def test_updated_search_overrides_the_cached_status() -> None:
    """A fresh status from Recorded Future wins over the cached one."""
    job = build_job(
        SyncPlaybookAlertStatusJob,
        alert_state={
            "a-1": {
                SYNC_STATE_STATUS_KEY: "New",
                SYNC_STATE_PRODUCT_ID_KEY: "task:1",
            },
        },
    )
    job.api_client.playbook_alerts.search.return_value = make_search_response(
        {"task:1": "Dismissed"},
    )

    assert job._fetch_product_statuses(["task:1"]) == {"task:1": "Dismissed"}


# ---------------------------------------------------------------------------
# Individual fetch fallback
# ---------------------------------------------------------------------------


def test_first_sighting_falls_back_to_an_individual_fetch(
    job: SyncPlaybookAlertStatusJob,
) -> None:
    """An alert with neither a fresh nor a cached status is fetched directly."""
    job.api_client.playbook_alerts.search.return_value = make_search_response({})
    job.api_client.playbook_alerts.fetch.return_value = make_playbook_alert("New")

    assert job._fetch_product_statuses(["task:1"]) == {"task:1": "New"}
    job.api_client.playbook_alerts.fetch.assert_called_once_with(alert_id="task:1")


def test_individual_fetch_failure_omits_the_alert(
    job: SyncPlaybookAlertStatusJob,
) -> None:
    """A failed fetch drops that alert instead of failing the whole case."""
    job.api_client.playbook_alerts.search.return_value = make_search_response({})
    job.api_client.playbook_alerts.fetch.side_effect = RuntimeError("not found")

    assert job._fetch_product_statuses(["task:1"]) == {}


def test_alert_with_no_status_panel_is_omitted(
    job: SyncPlaybookAlertStatusJob,
) -> None:
    """An alert with no status panel contributes no status."""
    job.api_client.playbook_alerts.search.return_value = make_search_response({})
    job.api_client.playbook_alerts.fetch.return_value = make_playbook_alert(None)

    assert job._fetch_product_statuses(["task:1"]) == {}


def test_search_failure_falls_through_to_cache_and_fetch() -> None:
    """A broken search degrades to the cache and individual fetches."""
    job = build_job(
        SyncPlaybookAlertStatusJob,
        alert_state={
            "a-1": {
                SYNC_STATE_STATUS_KEY: "InProgress",
                SYNC_STATE_PRODUCT_ID_KEY: "task:1",
            },
        },
    )
    job.api_client.playbook_alerts.search.side_effect = RuntimeError("search down")
    job.api_client.playbook_alerts.fetch.return_value = make_playbook_alert("New")

    assert job._fetch_product_statuses(["task:1", "task:2"]) == {
        "task:1": "InProgress",
        "task:2": "New",
    }


def test_search_failure_is_not_retried_within_an_iteration(
    job: SyncPlaybookAlertStatusJob,
) -> None:
    """A failed search is not re-attempted for every case in the iteration."""
    job.api_client.playbook_alerts.search.side_effect = RuntimeError("search down")
    job.api_client.playbook_alerts.fetch.return_value = make_playbook_alert("New")

    job._fetch_product_statuses(["task:1"])
    job._fetch_product_statuses(["task:2"])

    assert job.api_client.playbook_alerts.search.call_count == 1


# ---------------------------------------------------------------------------
# Outbound write
# ---------------------------------------------------------------------------


def test_push_status_writes_status_and_log_entry(
    job: SyncPlaybookAlertStatusJob,
) -> None:
    """The outbound write goes straight to `PlaybookAlertMgr.update` by ID."""
    job._push_status_to_product("task:1", "Resolved", "audit note")

    job.api_client.playbook_alerts.update.assert_called_once_with(
        alert="task:1",
        status="Resolved",
        log_entry="audit note",
    )


def test_push_status_skips_the_redundant_prefetch(
    job: SyncPlaybookAlertStatusJob,
) -> None:
    """`PlaybookAlertMgr.update` accepts a bare ID, so no fetch is needed."""
    job._push_status_to_product("task:1", "Resolved", "audit note")

    assert job.api_client.playbook_alerts.fetch.call_count == 0
    assert job.api_client.update_playbook_alert.call_count == 0
