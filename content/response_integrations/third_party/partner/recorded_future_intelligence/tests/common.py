############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Shared fixtures and doubles for the Recorded Future integration tests."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

from TIPCommon.base.job import base_job
from TIPCommon.base.job.job_case import JobCase
from TIPCommon.data_models import CaseDataStatus

from recorded_future_intelligence.core.constants import (
    CLASSIC_ALERT_PRODUCT,
    SYNC_DEFAULT_CLOSE_REASON,
    SYNC_DEFAULT_CLOSE_ROOT_CAUSE,
)

if TYPE_CHECKING:
    from recorded_future_intelligence.core.RecordedFutureSyncCommon import (
        RecordedFutureBaseSyncJob,
    )

SOAR_API_ROOT = "https://secops.example.com/api"
SCRIPT_NAME = "test_script"
UNIQUE_IDENTIFIER = "test_uid"
EXPECTED_NAME_ID = f"{SCRIPT_NAME}_{UNIQUE_IDENTIFIER}"


def make_alert(
    identifier: str,
    ticket_id: str | None,
    device_product: str = CLASSIC_ALERT_PRODUCT,
    status: str = "opened",
) -> SimpleNamespace:
    """Build a stand-in for a Google SecOps alert card.

    Args:
        identifier (str): The Google SecOps alert identifier.
        ticket_id (str | None): The Recorded Future alert ID the connector
            stamped onto the alert.
        device_product (str): The alert's device product.
        status (str): The alert's status.

    Returns:
        SimpleNamespace: The alert double.

    """
    return SimpleNamespace(
        identifier=identifier,
        ticket_id=ticket_id,
        device_product=device_product,
        status=status,
        name=f"Alert {identifier}",
        closure_details={},
    )


def make_job_case(
    alerts: list[SimpleNamespace] | None = None,
    case_id: int = 42,
    status: CaseDataStatus = CaseDataStatus.OPENED,
    modification_time: int = 1_700_000_000_000,
) -> JobCase:
    """Build a real `JobCase` around lightweight case and alert doubles.

    Args:
        alerts (list[SimpleNamespace] | None): The case's alerts.
        case_id (int): The case ID.
        status (CaseDataStatus): The case status.
        modification_time (int): The case modification time, in milliseconds.

    Returns:
        JobCase: The job case.

    """
    case_detail = SimpleNamespace(
        id_=case_id,
        alerts=list(alerts or []),
        status=status,
        tags=[],
        comments=[],
        assigned_user=None,
    )
    return JobCase(case_detail=case_detail, modification_time=modification_time)


def make_params(**overrides: Any) -> SimpleNamespace:
    """Build a job parameter container with the sync job defaults.

    Args:
        **overrides (Any): Parameter values to override.

    Returns:
        SimpleNamespace: The parameter container.

    """
    params = SimpleNamespace(
        environment_name="Default Environment",
        max_hours_backwards=24,
        closed_alert_reason=SYNC_DEFAULT_CLOSE_REASON,
        closed_alert_root_cause=SYNC_DEFAULT_CLOSE_ROOT_CAUSE,
        close_case_when_all_alerts_closed=False,
    )
    for name, value in overrides.items():
        setattr(params, name, value)

    return params


def build_job(
    job_class: type[RecordedFutureBaseSyncJob],
    params: SimpleNamespace | None = None,
    alert_state: dict[str, dict] | None = None,
) -> RecordedFutureBaseSyncJob:
    """Instantiate a sync job with its SOAR dependencies replaced by doubles.

    The job's real `__init__` runs, so context identifiers and the rest of the
    `BaseSyncJob` setup are exercised rather than faked.

    Args:
        job_class (type[RecordedFutureBaseSyncJob]): The job class to build.
        params (SimpleNamespace | None): Job parameters; defaults are used if
            omitted.
        alert_state (dict[str, dict] | None): Pre-existing per-alert sync state.

    Returns:
        RecordedFutureBaseSyncJob: The job, ready to exercise.

    """
    soar_job = MagicMock()
    soar_job.script_name = SCRIPT_NAME
    soar_job.unique_identifier = UNIQUE_IDENTIFIER
    soar_job.API_ROOT = SOAR_API_ROOT
    soar_job.get_job_context_property.return_value = None

    with (
        patch.object(base_job, "create_soar_job", return_value=soar_job),
        patch.object(base_job, "create_params_container", return_value=make_params()),
        patch.object(base_job, "create_logger", return_value=MagicMock()),
    ):
        job = job_class()

    job._params = params if params is not None else make_params()
    job._api_client = MagicMock()
    job.alert_state = dict(alert_state or {})
    job.last_run_time = 1_700_000_000_000

    return job
