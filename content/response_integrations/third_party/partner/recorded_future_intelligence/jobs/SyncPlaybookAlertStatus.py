############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Keeps Recorded Future playbook alert status and Google SecOps alert status in sync."""

from __future__ import annotations

from datetime import datetime, timezone

from ..core.constants import (
    DATETIME_ISO_FORMAT,
    PLAYBOOK_ALERT_API_LIMIT,
    PLAYBOOK_ALERT_PRODUCT,
    PLAYBOOK_ALERT_SYNC_CONTEXT_KEY,
    PLAYBOOK_ALERT_SYNC_JOB_SCRIPT_NAME,
)
from ..core.RecordedFutureSyncCommon import RecordedFutureBaseSyncJob


class SyncPlaybookAlertStatusJob(RecordedFutureBaseSyncJob):
    """Bi-directional status sync for Recorded Future playbook alerts.

    The playbook alert search endpoint supports an `updated_from` filter and
    returns each alert's status inline, so one search per iteration covers
    every alert that changed in Recorded Future. Tracked alerts absent from
    that window are unchanged, and reuse the status recorded on the previous
    iteration.
    """

    DEVICE_PRODUCT = PLAYBOOK_ALERT_PRODUCT
    PRODUCT_LABEL = "playbook alert"

    def __init__(self) -> None:
        super().__init__(
            job_name=PLAYBOOK_ALERT_SYNC_JOB_SCRIPT_NAME,
            context_identifier=PLAYBOOK_ALERT_SYNC_CONTEXT_KEY,
        )
        self._updated_statuses: dict[str, str] | None = None

    def _fetch_product_statuses(self, alert_ids: list[str]) -> dict[str, str]:
        """Read the current status of the given playbook alerts.

        Args:
            alert_ids (list[str]): Recorded Future playbook alert IDs.

        Returns:
            dict[str, str]: Mapping of alert ID to its current status. IDs that
            could neither be found in the updated window, in the cached state,
            nor fetched individually are omitted.

        """
        updated_statuses = self._get_updated_statuses()
        cached_statuses = self.cached_product_statuses()

        statuses: dict[str, str] = {}
        for alert_id in alert_ids:
            status = updated_statuses.get(alert_id) or cached_statuses.get(alert_id)
            if status is None:
                status = self._fetch_single_status(alert_id)
            if status:
                statuses[alert_id] = status

        return statuses

    def _get_updated_statuses(self) -> dict[str, str]:
        """Search once per iteration for playbook alerts updated since last run.

        Returns:
            dict[str, str]: Mapping of playbook alert ID to status for every
            alert updated since the job's last successful run.

        """
        if self._updated_statuses is not None:
            return self._updated_statuses

        updated_from = datetime.fromtimestamp(
            self.last_run_time / 1000,
            tz=timezone.utc,
        ).strftime(DATETIME_ISO_FORMAT)

        try:
            response = self.api_client.playbook_alerts.search(
                updated_from=updated_from,
                max_results=PLAYBOOK_ALERT_API_LIMIT,
            )
            self._updated_statuses = {entry.playbook_alert_id: entry.status for entry in response.data}
            self.logger.info(
                f"Found {len(self._updated_statuses)} playbook alerts updated since {updated_from}.",
            )
        except Exception:
            self.logger.exception(
                "Failed to search for updated playbook alerts. Falling back to the cached "
                "statuses and individual fetches for this iteration.",
            )
            self._updated_statuses = {}

        return self._updated_statuses

    def _fetch_single_status(self, alert_id: str) -> str | None:
        """Fetch one playbook alert's status directly.

        Used the first time an alert is seen, when there is no cached status
        and Recorded Future did not report it as recently updated.

        Args:
            alert_id (str): The Recorded Future playbook alert ID.

        Returns:
            str | None: The alert's status, or None if it could not be read.

        """
        try:
            alert = self.api_client.playbook_alerts.fetch(alert_id=alert_id)
        except Exception:
            self.logger.exception(
                f"Failed to fetch Recorded Future playbook alert {alert_id}.",
            )
            return None

        panel_status = getattr(alert, "panel_status", None)
        status = getattr(panel_status, "status", None) if panel_status else None
        if not status:
            self.logger.info(
                f"Recorded Future playbook alert {alert_id} has no status panel. Skipping.",
            )

        return status

    def _push_status_to_product(self, alert_id: str, status: str, note: str) -> None:
        """Set the status of a playbook alert.

        `PlaybookAlertMgr.update` accepts a bare alert ID, so this avoids the
        redundant pre-fetch that `RecordedFutureManager.update_playbook_alert`
        performs.

        Args:
            alert_id (str): The Recorded Future playbook alert ID.
            status (str): The new status.
            note (str): Audit text stored as the alert log entry.

        """
        self.api_client.playbook_alerts.update(
            alert=alert_id,
            status=status,
            log_entry=note,
        )


def main() -> None:
    """Run the playbook alert status sync job."""
    SyncPlaybookAlertStatusJob().start()


if __name__ == "__main__":
    main()
