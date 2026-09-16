############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Shared machinery for the Recorded Future alert status sync jobs.

Both the classic alert and the playbook alert sync jobs keep a Google SecOps
alert and its originating Recorded Future alert in the same state. They differ
only in how a Recorded Future status is read and written, so everything else
lives here.
"""

from __future__ import annotations

import abc
import json
from typing import TYPE_CHECKING, ClassVar

from TIPCommon.base.job.base_sync_job import BaseSyncJob
from TIPCommon.base.job.job_case import SyncMetadata
from TIPCommon.data_models import CaseDataStatus
from TIPCommon.extraction import extract_job_param
from TIPCommon.validation import ParameterValidator

from .constants import (
    SOAR_CLOSED_ALERT_STATUSES,
    SYNC_CASE_CLOSE_REASON,
    SYNC_COMMENT_PREFIX,
    SYNC_DEFAULT_CLOSE_REASON,
    SYNC_DEFAULT_CLOSE_ROOT_CAUSE,
    SYNC_DEFAULT_MAX_HOURS_BACKWARDS,
    SYNC_MAX_HOURS_BACKWARDS,
    SYNC_MIN_HOURS_BACKWARDS,
    SYNC_OUTBOUND_CLOSED_STATUS,
    SYNC_REOPEN_ALERT_ENDPOINT,
    SYNC_REOPEN_CASE_ENDPOINT,
    SYNC_STATE_CLOSED_BY_JOB_KEY,
    SYNC_STATE_CONTEXT_SUFFIX,
    SYNC_STATE_PRODUCT_ID_KEY,
    SYNC_STATE_STATUS_KEY,
    SYNC_TERMINAL_STATUSES,
)
from .RecordedFutureManager import RecordedFutureManager

if TYPE_CHECKING:
    from TIPCommon.base.job.job_case import JobCase
    from TIPCommon.data_models import AlertCard


def is_soar_alert_closed(alert: AlertCard) -> bool:
    """Check whether a Google SecOps alert is closed.

    `AlertCard.from_json` falls back to `0` when the platform omits the status
    field, so anything that is not recognizably a closed status is reported as
    open. That is the fail-safe direction: an ambiguous status never causes an
    alert to be treated as closed, and so never triggers an automatic write.

    Args:
        alert (AlertCard): The Google SecOps alert to check.

    Returns:
        bool: True if the alert is closed, False otherwise.

    """
    status = getattr(alert, "status", None)
    return str(status).lower() in SOAR_CLOSED_ALERT_STATUSES


class RecordedFutureBaseSyncJob(BaseSyncJob[RecordedFutureManager], abc.ABC):
    """Base class for the Recorded Future alert status sync jobs.

    Subclasses declare which Google SecOps ``device_product`` they own and
    implement the two Recorded Future status operations, ``_fetch_product_statuses``
    and ``_push_status_to_product``.
    """

    #: The ``device_product`` stamped on Google SecOps alerts by the connector
    #: that ingests this alert family.
    DEVICE_PRODUCT: ClassVar[str] = ""

    #: Human readable name of the alert family, used in case comments.
    PRODUCT_LABEL: ClassVar[str] = "Recorded Future alert"

    def __init__(self, job_name: str, context_identifier: str) -> None:
        # The Recorded Future connectors do not tag the cases they create, so
        # there is no tag to pre-filter on. Case selection is instead narrowed
        # by `_extract_product_ids_from_case`, which drops any case with no
        # alert belonging to this job's alert family. An empty list is only
        # safe because `sync_tags` is a no-op here; `get_tags_to_sync` would
        # index `tags_identifiers[0]`.
        super().__init__(
            job_name=job_name,
            context_identifier=context_identifier,
            tags_identifiers=[],
        )
        self.state_context_identifier: str = f"{context_identifier}{SYNC_STATE_CONTEXT_SUFFIX}"
        self.alert_state: dict[str, dict] = {}
        self.failed_cases: set[int] = set()
        # Recorded Future statuses read during this iteration, keyed by alert
        # ID. Case selection and per-case syncing both need them, so they are
        # read once and reused.
        self.status_cache: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Job setup
    # ------------------------------------------------------------------

    def _validate_params(self) -> None:
        """Validate and normalize the job parameters.

        `Job._extract_job_params` already populated `self.params` from the job
        definition, snake-casing each parameter name. Optional parameters that
        the operator cleared arrive as empty strings, so closure behaviour is
        normalized back to its documented default here.
        """
        validator = ParameterValidator(self.soar_job)
        self.params.max_hours_backwards = validator.validate_range(
            param_name="Max Hours Backwards",
            value=self.params.max_hours_backwards or SYNC_DEFAULT_MAX_HOURS_BACKWARDS,
            min_limit=SYNC_MIN_HOURS_BACKWARDS,
            max_limit=SYNC_MAX_HOURS_BACKWARDS,
            default_value=SYNC_DEFAULT_MAX_HOURS_BACKWARDS,
        )
        self.params.closed_alert_reason = getattr(self.params, "closed_alert_reason", None) or SYNC_DEFAULT_CLOSE_REASON
        self.params.closed_alert_root_cause = (
            getattr(self.params, "closed_alert_root_cause", None) or SYNC_DEFAULT_CLOSE_ROOT_CAUSE
        )
        self.params.close_case_when_all_alerts_closed = bool(
            getattr(self.params, "close_case_when_all_alerts_closed", False),
        )

    def _init_api_clients(self) -> RecordedFutureManager:
        """Build the Recorded Future manager from the job's own parameters.

        Jobs cannot read integration instance configuration, so the API
        credentials are declared as job parameters.

        Returns:
            RecordedFutureManager: The configured manager.

        """
        api_url = extract_job_param(
            siemplify=self.soar_job,
            param_name="API URL",
            is_mandatory=True,
            print_value=True,
        )
        api_key = extract_job_param(
            siemplify=self.soar_job,
            param_name="API Key",
            is_mandatory=True,
            remove_whitespaces=False,
        )
        verify_ssl = extract_job_param(
            siemplify=self.soar_job,
            param_name="Verify SSL",
            input_type=bool,
            is_mandatory=False,
            default_value=False,
            print_value=True,
        )

        return RecordedFutureManager(
            api_url,
            api_key,
            verify_ssl,
            siemplify=self.soar_job,
        )

    # ------------------------------------------------------------------
    # Per-family operations
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def _fetch_product_statuses(self, alert_ids: list[str]) -> dict[str, str]:
        """Read the current Recorded Future status of the given alerts.

        Args:
            alert_ids (list[str]): Recorded Future alert IDs to look up.

        Returns:
            dict[str, str]: Mapping of Recorded Future alert ID to its current
            status. IDs that could not be read are omitted.

        """
        raise NotImplementedError

    @abc.abstractmethod
    def _push_status_to_product(self, alert_id: str, status: str, note: str) -> None:
        """Write a status back to a Recorded Future alert.

        Args:
            alert_id (str): The Recorded Future alert ID to update.
            status (str): The new Recorded Future status.
            note (str): Audit text to attach to the update.

        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Sync state persistence
    # ------------------------------------------------------------------

    def _read_alert_state(self) -> dict[str, dict]:
        """Read the per-alert sync state from the job context.

        Returns:
            dict[str, dict]: Mapping of Google SecOps alert identifier to its
            stored sync state.

        """
        raw_state = self.soar_job.get_job_context_property(
            self.name_id,
            self.state_context_identifier,
        )
        if not raw_state:
            return {}

        try:
            state = json.loads(raw_state)
        except (TypeError, ValueError):
            self.logger.warn("Could not parse stored sync state. Starting from an empty state.")
            return {}

        return state if isinstance(state, dict) else {}

    def _write_alert_state(self) -> None:
        """Persist the per-alert sync state to the job context."""
        self.soar_job.set_job_context_property(
            identifier=self.name_id,
            property_key=self.state_context_identifier,
            property_value=json.dumps(self.alert_state),
        )

    def _get_alert_state(self, alert_identifier: str) -> dict:
        """Fetch the stored sync state for a single Google SecOps alert.

        Args:
            alert_identifier (str): The Google SecOps alert identifier.

        Returns:
            dict: The stored state, or an empty default.

        """
        return self.alert_state.get(alert_identifier, {})

    def _set_alert_state(
        self,
        alert_identifier: str,
        recorded_future_status: str | None = None,
        closed_by_job: bool | None = None,
        product_id: str | None = None,
    ) -> None:
        """Update the stored sync state for a single Google SecOps alert.

        Args:
            alert_identifier (str): The Google SecOps alert identifier.
            recorded_future_status (str | None): Last observed Recorded Future
                status, if it should be updated.
            closed_by_job (bool | None): Whether this job closed the Google
                SecOps alert, if it should be updated.
            product_id (str | None): The Recorded Future alert ID this Google
                SecOps alert came from, if it should be updated.

        """
        state = self.alert_state.setdefault(alert_identifier, {})
        if recorded_future_status is not None:
            state[SYNC_STATE_STATUS_KEY] = recorded_future_status
        if closed_by_job is not None:
            state[SYNC_STATE_CLOSED_BY_JOB_KEY] = closed_by_job
        if product_id is not None:
            state[SYNC_STATE_PRODUCT_ID_KEY] = product_id

    def cached_product_statuses(self) -> dict[str, str]:
        """Index the last observed Recorded Future status by alert ID.

        A Recorded Future alert that has not been modified since the previous
        iteration still holds the status this job last recorded for it, so
        subclasses whose API supports an incremental "updated since" query can
        use this instead of re-reading every tracked alert.

        Returns:
            dict[str, str]: Mapping of Recorded Future alert ID to its last
            observed status.

        """
        return {
            state[SYNC_STATE_PRODUCT_ID_KEY]: state[SYNC_STATE_STATUS_KEY]
            for state in self.alert_state.values()
            if state.get(SYNC_STATE_PRODUCT_ID_KEY) and state.get(SYNC_STATE_STATUS_KEY)
        }

    # ------------------------------------------------------------------
    # BaseSyncJob hooks
    # ------------------------------------------------------------------

    def _perform_job(self) -> None:
        """Load the sync state, run the sync cycle, then persist the state."""
        self.alert_state = self._read_alert_state()
        try:
            super()._perform_job()
        finally:
            self._write_alert_state()

    def statuses_for(self, alert_ids: list[str]) -> dict[str, str]:
        """Read Recorded Future statuses, reusing anything already read.

        Args:
            alert_ids (list[str]): Recorded Future alert IDs to resolve.

        Returns:
            dict[str, str]: Mapping of alert ID to current status, for the IDs
            that could be resolved.

        """
        missing = [alert_id for alert_id in alert_ids if alert_id not in self.status_cache]
        if missing:
            self.status_cache.update(self._fetch_product_statuses(missing))

        return {alert_id: self.status_cache[alert_id] for alert_id in alert_ids if alert_id in self.status_cache}

    def modified_synced_case_ids_by_product(
        self,
        product_ids: list[str],
        case_ids: list[tuple[str, int]],
    ) -> list[tuple[str, int]]:
        """Add cases whose Recorded Future alert changed but whose case did not.

        `BaseSyncJob` selects cases by Google SecOps modification time, so a
        status change made only in Recorded Future would never be picked up.
        Overriding this hook is what makes the inbound direction work.

        Args:
            product_ids (list[str]): Recorded Future alert IDs already tracked
                by this job.
            case_ids (list[tuple[str, int]]): Cases already selected this
                iteration, as (case ID, modification time) pairs.

        Returns:
            list[tuple[str, int]]: Additional (case ID, timestamp) pairs for
            cases whose Recorded Future alert changed status.

        """
        tracked_ids = list(product_ids)
        if not tracked_ids:
            return []

        try:
            statuses = self.statuses_for(tracked_ids)
        except Exception:
            self.logger.exception(
                "Failed to read Recorded Future statuses while selecting cases. "
                "This iteration only covers cases modified in Google SecOps.",
            )
            return []

        last_seen = self.cached_product_statuses()
        changed_ids = [alert_id for alert_id, status in statuses.items() if last_seen.get(alert_id) != status]
        if not changed_ids:
            return []

        already_selected = {case_id for case_id, _ in case_ids}
        additional: dict[str, int] = {}
        for alert_id in changed_ids:
            for case_id in self._case_ids_for_product_id(alert_id):
                if case_id not in already_selected:
                    additional[case_id] = self._cached_unix_now

        if additional:
            self.logger.info(
                f"Selected {len(additional)} additional case(s) because their "
                f"Recorded Future alert status changed: {sorted(additional)}",
            )

        return list(additional.items())

    def _case_ids_for_product_id(self, product_id: str) -> list[str]:
        """Find the Google SecOps cases carrying a Recorded Future alert ID.

        The connectors store the Recorded Future alert ID as the Google SecOps
        alert's ticket ID, so the platform's ticket ID search resolves it.

        Args:
            product_id (str): The Recorded Future alert ID.

        Returns:
            list[str]: The matching case IDs.

        """
        try:
            response = self.soar_job.get_cases_by_ticket_id(ticket_id=product_id)
        except Exception:
            self.logger.exception(
                f"Failed to look up Google SecOps cases for Recorded Future alert {product_id}.",
            )
            return []

        if isinstance(response, dict):
            for key in ("caseIds", "case_ids", "cases"):
                if isinstance(response.get(key), (list, tuple)):
                    response = response[key]
                    break

        if not isinstance(response, (list, tuple)):
            self.logger.warn(
                f"Unexpected response shape when searching cases by ticket ID {product_id}: {type(response).__name__}.",
            )
            return []

        return [str(case_id) for case_id in response if case_id is not None]

    def _extract_product_ids_from_case(self, case_details: JobCase) -> list[str]:
        """Collect the Recorded Future alert IDs owned by this job from a case.

        Args:
            case_details (JobCase): The case to inspect.

        Returns:
            list[str]: The distinct Recorded Future alert IDs found on the
            case's alerts, sorted for stable ordering.

        """
        return sorted(
            {alert.ticket_id for alert in self._owned_alerts(case_details) if alert.ticket_id},
        )

    def _owned_alerts(self, job_case: JobCase) -> list[AlertCard]:
        """Filter a case's alerts down to the ones this job owns.

        Args:
            job_case (JobCase): The case to inspect.

        Returns:
            list[AlertCard]: Alerts whose ``device_product`` matches this job's.

        """
        return [alert for alert in job_case.case_detail.alerts if alert.device_product == self.DEVICE_PRODUCT]

    def map_product_data_to_case(self, job_case: JobCase) -> None:
        """Attach the current Recorded Future status to each owned alert.

        Args:
            job_case (JobCase): The case to enrich.

        """
        owned_alerts = self._owned_alerts(job_case)
        job_case.product_ids_from_secops_alerts = {alert.ticket_id: alert for alert in owned_alerts if alert.ticket_id}

        alert_ids = sorted(job_case.product_ids_from_secops_alerts)
        if not alert_ids:
            return

        try:
            statuses = self.statuses_for(alert_ids)
        except Exception:
            self.logger.exception(
                f"Failed to read Recorded Future statuses for case {job_case.case_detail.id_}.",
            )
            self.failed_cases.add(job_case.case_detail.id_)
            return

        for alert in owned_alerts:
            status = statuses.get(alert.ticket_id)
            if status:
                job_case.alert_metadata[alert.identifier] = SyncMetadata(
                    status=status,
                    incident_id=alert.ticket_id,
                )

    def sync_status(self, job_case: JobCase) -> None:
        """Synchronize status in both directions for a single case.

        Args:
            job_case (JobCase): The case to synchronize.

        """
        if job_case.case_detail.id_ in self.failed_cases:
            self.logger.info(
                f"Skipping status sync for case {job_case.case_detail.id_} "
                "because its Recorded Future data could not be read.",
            )
            return

        try:
            reopened_any = False
            for alert in self._owned_alerts(job_case):
                reopened_any |= self._sync_alert_inbound(job_case, alert)
                self._sync_alert_outbound(job_case, alert)

            self._reconcile_case_status(job_case, reopened_any=reopened_any)
            self._prune_settled_pairs(job_case)
        except Exception:
            self.logger.exception(
                f"Failed to sync status for case {job_case.case_detail.id_}.",
            )

    def _prune_settled_pairs(self, job_case: JobCase) -> None:
        """Stop tracking pairs that are closed on both sides and need no reopen.

        `BaseSyncJob` declares `is_alert_and_product_closed` and
        `remove_synced_data_from_db` but never calls them, so without this both
        the tracked-ID map and the sync state would grow without bound.

        A pair this job closed itself is deliberately kept, because reopening it
        later depends on that recorded state.

        Args:
            job_case (JobCase): The case to prune.

        """
        settled: list[tuple[str, str]] = []
        for alert in self._owned_alerts(job_case):
            if not alert.ticket_id:
                continue
            if self._get_alert_state(alert.identifier).get(SYNC_STATE_CLOSED_BY_JOB_KEY):
                continue
            if self.is_alert_and_product_closed(job_case, alert.ticket_id):
                settled.append((str(job_case.case_detail.id_), alert.ticket_id))

        for case_id, product_id in settled:
            self.remove_synced_data_from_db(job_case, product_id)
            self.logger.info(
                f"Recorded Future alert {product_id} and its Google SecOps alert in case "
                f"{case_id} are both closed. Dropping them from the sync state.",
            )

        if settled:
            self._remove_synced_entries(settled)

    def is_alert_and_product_closed(self, job_case: JobCase, product: object) -> bool:
        """Check whether both sides of a synced pair are closed.

        Args:
            job_case (JobCase): The case the alert belongs to.
            product (object): The Recorded Future alert ID being checked.

        Returns:
            bool: True if the Google SecOps alert and the Recorded Future alert
            are both closed, False otherwise.

        """
        alert = job_case.product_ids_from_secops_alerts.get(str(product))
        if alert is None:
            return False

        metadata = job_case.alert_metadata.get(alert.identifier)
        product_closed = bool(metadata and metadata.status in SYNC_TERMINAL_STATUSES)

        return is_soar_alert_closed(alert) and product_closed

    def remove_synced_data_from_db(self, job_case: JobCase, product_details: object) -> None:
        """Drop sync state for a pair that is closed on both sides.

        Args:
            job_case (JobCase): The case the alert belongs to.
            product_details (object): The Recorded Future alert ID to forget.

        """
        alert = job_case.product_ids_from_secops_alerts.get(str(product_details))
        if alert is not None:
            self.alert_state.pop(alert.identifier, None)

    # The Recorded Future status sync jobs deliberately synchronize status only.
    # These hooks are required by BaseSyncJob's contract and are intentional
    # no-ops.

    def sync_comments(self, job_case: JobCase) -> None:
        """Not synchronized by this job.

        Args:
            job_case (JobCase): Unused.

        """

    def sync_tags(self, job_case: JobCase) -> None:
        """Not synchronized by this job.

        Args:
            job_case (JobCase): Unused.

        """

    def sync_severity(self, job_case: JobCase) -> None:
        """Not synchronized by this job.

        Args:
            job_case (JobCase): Unused.

        """

    def sync_assignee(self, job_case: JobCase) -> None:
        """Not synchronized by this job.

        Args:
            job_case (JobCase): Unused.

        """

    # ------------------------------------------------------------------
    # Inbound: Recorded Future -> Google SecOps
    # ------------------------------------------------------------------

    def _sync_alert_inbound(self, job_case: JobCase, alert: AlertCard) -> bool:
        """Apply a Recorded Future status change to a Google SecOps alert.

        Args:
            job_case (JobCase): The case the alert belongs to.
            alert (AlertCard): The Google SecOps alert to update.

        Returns:
            bool: True if the alert was reopened, False otherwise.

        """
        metadata = job_case.alert_metadata.get(alert.identifier)
        if not metadata or not metadata.status:
            return False

        recorded_future_status = metadata.status
        state = self._get_alert_state(alert.identifier)
        is_terminal = recorded_future_status in SYNC_TERMINAL_STATUSES
        alert_closed = is_soar_alert_closed(alert)

        if is_terminal and not alert_closed:
            self._close_alert_in_secops(job_case, alert, recorded_future_status)
            self._set_alert_state(
                alert.identifier,
                recorded_future_status=recorded_future_status,
                closed_by_job=True,
                product_id=alert.ticket_id,
            )
            return False

        if not is_terminal and alert_closed and state.get(SYNC_STATE_CLOSED_BY_JOB_KEY):
            self._reopen_alert_in_secops(job_case, alert, recorded_future_status)
            self._set_alert_state(
                alert.identifier,
                recorded_future_status=recorded_future_status,
                closed_by_job=False,
                product_id=alert.ticket_id,
            )
            return True

        self._set_alert_state(
            alert.identifier,
            recorded_future_status=recorded_future_status,
            product_id=alert.ticket_id,
        )
        return False

    def _close_alert_in_secops(
        self,
        job_case: JobCase,
        alert: AlertCard,
        recorded_future_status: str,
    ) -> None:
        """Close a Google SecOps alert because its Recorded Future alert closed.

        Args:
            job_case (JobCase): The case the alert belongs to.
            alert (AlertCard): The Google SecOps alert to close.
            recorded_future_status (str): The terminal Recorded Future status.

        """
        comment = (
            f"{SYNC_COMMENT_PREFIX} {alert.ticket_id}: alert closed because the "
            f"corresponding {self.PRODUCT_LABEL} was set to "
            f"{recorded_future_status} in Recorded Future."
        )
        self.sync_product_status_to_case(
            case_id=str(job_case.case_detail.id_),
            alert_id=alert.identifier,
            reason=self.params.closed_alert_reason,
            root_cause=self.params.closed_alert_root_cause,
            comment=comment,
        )
        # Reflect the close locally so the outbound pass and the case level
        # reconciliation in this same iteration see the new state. "close" is
        # the vocabulary TIPCommon's own alert helpers compare against.
        alert.status = "close"

    def _reopen_alert_in_secops(
        self,
        job_case: JobCase,
        alert: AlertCard,
        recorded_future_status: str,
    ) -> None:
        """Reopen a Google SecOps alert this job previously closed.

        Args:
            job_case (JobCase): The case the alert belongs to.
            alert (AlertCard): The Google SecOps alert to reopen.
            recorded_future_status (str): The new Recorded Future status.

        """
        case_id = job_case.case_detail.id_
        if job_case.case_detail.status == CaseDataStatus.CLOSED:
            self._reopen_case(case_id)

        self._post_to_soar(
            SYNC_REOPEN_ALERT_ENDPOINT,
            {"caseId": int(case_id), "alertIdentifier": alert.identifier},
        )
        alert.status = "open"

        self.soar_job.add_comment(
            comment=(
                f"{SYNC_COMMENT_PREFIX} {alert.ticket_id}: alert reopened because the "
                f"corresponding {self.PRODUCT_LABEL} was set to "
                f"{recorded_future_status} in Recorded Future."
            ),
            case_id=case_id,
            alert_identifier=alert.identifier,
        )
        self.logger.info(f"Reopened alert {alert.identifier} in case {case_id}.")

    def _reopen_case(self, case_id: int) -> None:
        """Reopen a closed Google SecOps case.

        Args:
            case_id (int): The case to reopen.

        """
        self._post_to_soar(SYNC_REOPEN_CASE_ENDPOINT, [int(case_id)])
        self.logger.info(f"Reopened case {case_id}.")

    def _post_to_soar(self, endpoint: str, payload: object) -> None:
        """POST to a Google SecOps API endpoint that the SDK does not expose.

        Args:
            endpoint (str): The endpoint path, relative to the API root.
            payload (object): The JSON body to send.

        """
        url = f"{self.soar_job.API_ROOT}/{endpoint}"
        response = self.soar_job.session.post(url, json=payload)
        response.raise_for_status()

    # ------------------------------------------------------------------
    # Outbound: Google SecOps -> Recorded Future
    # ------------------------------------------------------------------

    def _sync_alert_outbound(self, job_case: JobCase, alert: AlertCard) -> None:
        """Push a Google SecOps closure back to Recorded Future.

        Args:
            job_case (JobCase): The case the alert belongs to.
            alert (AlertCard): The Google SecOps alert to read.

        """
        metadata = job_case.alert_metadata.get(alert.identifier)
        if not metadata or not metadata.status:
            return

        if metadata.status in SYNC_TERMINAL_STATUSES:
            return

        state = self._get_alert_state(alert.identifier)
        if state.get(SYNC_STATE_CLOSED_BY_JOB_KEY):
            # This job closed the Google SecOps alert on Recorded Future's
            # behalf, so there is nothing to report back.
            return

        is_case_closed = job_case.case_detail.status == CaseDataStatus.CLOSED
        if not is_case_closed and not is_soar_alert_closed(alert):
            return

        origin = "case" if is_case_closed else "alert"
        note = (
            f"{SYNC_COMMENT_PREFIX} Status set to {SYNC_OUTBOUND_CLOSED_STATUS} because "
            f"Google SecOps {origin} {job_case.case_detail.id_} was closed."
        )

        try:
            self._push_status_to_product(
                alert.ticket_id,
                SYNC_OUTBOUND_CLOSED_STATUS,
                note,
            )
        except Exception:
            self.logger.exception(
                f"Failed to set Recorded Future alert {alert.ticket_id} to {SYNC_OUTBOUND_CLOSED_STATUS}.",
            )
            return

        self._set_alert_state(
            alert.identifier,
            recorded_future_status=SYNC_OUTBOUND_CLOSED_STATUS,
            product_id=alert.ticket_id,
        )
        self.soar_job.add_comment(
            comment=(
                f"{SYNC_COMMENT_PREFIX} {alert.ticket_id}: {self.PRODUCT_LABEL} set to "
                f"{SYNC_OUTBOUND_CLOSED_STATUS} in Recorded Future because the Google "
                f"SecOps {origin} was closed."
            ),
            case_id=job_case.case_detail.id_,
            alert_identifier=alert.identifier,
        )
        self.logger.info(
            f"Set Recorded Future alert {alert.ticket_id} to {SYNC_OUTBOUND_CLOSED_STATUS}.",
        )

    # ------------------------------------------------------------------
    # Case level reconciliation
    # ------------------------------------------------------------------

    def _reconcile_case_status(self, job_case: JobCase, reopened_any: bool) -> None:
        """Align the case status with its alerts after per-alert syncing.

        Reopening a case is unconditional, because an alert reopened inside a
        closed case is otherwise invisible. Closing a case is opt-in via the
        'Close Case When All Alerts Closed' parameter.

        Args:
            job_case (JobCase): The case to reconcile.
            reopened_any (bool): Whether any alert on the case was reopened.

        """
        case = job_case.case_detail
        if reopened_any and case.status == CaseDataStatus.CLOSED:
            self._reopen_case(case.id_)
            return

        if not self.params.close_case_when_all_alerts_closed:
            return

        if case.status == CaseDataStatus.CLOSED or not case.alerts:
            return

        if not all(is_soar_alert_closed(alert) for alert in case.alerts):
            return

        self.soar_job.close_case(
            root_cause=self.params.closed_alert_root_cause,
            case_id=case.id_,
            reason=SYNC_CASE_CLOSE_REASON,
            comment=(f"{SYNC_COMMENT_PREFIX} All alerts on this case are closed. Closing the case."),
            alert_identifier=None,
        )
        self.logger.info(f"Closed case {case.id_} because all of its alerts are closed.")
