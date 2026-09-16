############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the Recorded Future classic alert status sync job."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from recorded_future_intelligence.core.constants import (
    CLASSIC_ALERT_PRODUCT,
    CLASSIC_ALERT_SYNC_CONTEXT_KEY,
    CLASSIC_ALERT_SYNC_JOB_SCRIPT_NAME,
    SYNC_PRODUCT_FETCH_MAX_WORKERS,
)
from recorded_future_intelligence.jobs.SyncClassicAlertStatus import (
    SyncClassicAlertStatusJob,
)

from ..common import build_job


def make_classic_alert(alert_id: str, status_in_portal: str | None) -> SimpleNamespace:
    """Build a stand-in for a psengine `ClassicAlert`.

    Args:
        alert_id (str): The Recorded Future classic alert ID.
        status_in_portal (str | None): The portal status, or None for an alert
            that has never been reviewed.

    Returns:
        SimpleNamespace: The classic alert double.

    """
    review = SimpleNamespace(status_in_portal=status_in_portal) if status_in_portal is not None else None
    return SimpleNamespace(id_=alert_id, review=review)


@pytest.fixture(name="job")
def classic_job() -> SyncClassicAlertStatusJob:
    """Provide a classic alert sync job wired to doubles."""
    return build_job(SyncClassicAlertStatusJob)


def test_job_identity(job: SyncClassicAlertStatusJob) -> None:
    """The job claims the classic alert device product and its own context key."""
    assert job.DEVICE_PRODUCT == CLASSIC_ALERT_PRODUCT
    assert job.name == CLASSIC_ALERT_SYNC_JOB_SCRIPT_NAME
    assert job.context_identifier == CLASSIC_ALERT_SYNC_CONTEXT_KEY


def test_fetch_product_statuses_reads_portal_status(
    job: SyncClassicAlertStatusJob,
) -> None:
    """Statuses come from each alert's `review.status_in_portal`."""
    job.api_client.alerts.fetch_bulk.return_value = [
        make_classic_alert("classic-1", "New"),
        make_classic_alert("classic-2", "Resolved"),
    ]

    statuses = job._fetch_product_statuses(["classic-1", "classic-2"])

    assert statuses == {"classic-1": "New", "classic-2": "Resolved"}


def test_fetch_product_statuses_bulk_fetches_by_id(
    job: SyncClassicAlertStatusJob,
) -> None:
    """The classic alert search has no updated-since filter, so IDs are fetched.

    A regression here would silently turn every sync iteration into a full
    re-scan or drop alerts entirely.
    """
    job.api_client.alerts.fetch_bulk.return_value = []

    job._fetch_product_statuses(["classic-2", "classic-1"])

    kwargs = job.api_client.alerts.fetch_bulk.call_args.kwargs
    assert kwargs["ids"] == {"classic-1", "classic-2"}
    assert kwargs["max_workers"] == SYNC_PRODUCT_FETCH_MAX_WORKERS


def test_fetch_product_statuses_skips_unreviewed_alerts(
    job: SyncClassicAlertStatusJob,
) -> None:
    """An alert with no review block contributes no status."""
    job.api_client.alerts.fetch_bulk.return_value = [
        make_classic_alert("classic-1", None),
        make_classic_alert("classic-2", "Pending"),
    ]

    assert job._fetch_product_statuses(["classic-1", "classic-2"]) == {
        "classic-2": "Pending",
    }


def test_fetch_product_statuses_skips_blank_status(
    job: SyncClassicAlertStatusJob,
) -> None:
    """An empty portal status is treated as unknown rather than synced."""
    job.api_client.alerts.fetch_bulk.return_value = [
        make_classic_alert("classic-1", ""),
    ]

    assert job._fetch_product_statuses(["classic-1"]) == {}


def test_fetch_product_statuses_handles_empty_response(
    job: SyncClassicAlertStatusJob,
) -> None:
    """A Recorded Future response with no alerts yields no statuses."""
    job.api_client.alerts.fetch_bulk.return_value = []

    assert job._fetch_product_statuses(["classic-1"]) == {}


def test_push_status_writes_status_and_note(job: SyncClassicAlertStatusJob) -> None:
    """The outbound write goes through the manager's `update_alert` wrapper."""
    job._push_status_to_product("classic-1", "Resolved", "audit note")

    job.api_client.update_alert.assert_called_once_with(
        alert_id="classic-1",
        status="Resolved",
        assignee=None,
        note="audit note",
    )


def test_push_status_does_not_reassign_the_alert(
    job: SyncClassicAlertStatusJob,
) -> None:
    """Status sync must not disturb the Recorded Future assignee."""
    job._push_status_to_product("classic-1", "Resolved", "audit note")

    assert job.api_client.update_alert.call_args.kwargs["assignee"] is None
