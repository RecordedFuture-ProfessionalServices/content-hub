############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Keeps Recorded Future classic alert status and Google SecOps alert status in sync."""

from __future__ import annotations

from ..core.constants import (
    CLASSIC_ALERT_PRODUCT,
    CLASSIC_ALERT_SYNC_CONTEXT_KEY,
    CLASSIC_ALERT_SYNC_JOB_SCRIPT_NAME,
    SYNC_PRODUCT_FETCH_MAX_WORKERS,
)
from ..core.RecordedFutureSyncCommon import RecordedFutureBaseSyncJob


class SyncClassicAlertStatusJob(RecordedFutureBaseSyncJob):
    """Bi-directional status sync for Recorded Future classic alerts.

    The classic alert search endpoint can only filter on trigger time, not on
    last-modified time, so the current status of every tracked alert is read
    with a bulk fetch by ID rather than an incremental search.
    """

    DEVICE_PRODUCT = CLASSIC_ALERT_PRODUCT
    PRODUCT_LABEL = "classic alert"

    def __init__(self) -> None:
        super().__init__(
            job_name=CLASSIC_ALERT_SYNC_JOB_SCRIPT_NAME,
            context_identifier=CLASSIC_ALERT_SYNC_CONTEXT_KEY,
        )

    def _fetch_product_statuses(self, alert_ids: list[str]) -> dict[str, str]:
        """Read the portal status of the given classic alerts.

        Args:
            alert_ids (list[str]): Recorded Future classic alert IDs.

        Returns:
            dict[str, str]: Mapping of alert ID to its `statusInPortal` value.
            Alerts with no review data are omitted.

        """
        alerts = self.api_client.alerts.fetch_bulk(
            ids=set(alert_ids),
            max_workers=SYNC_PRODUCT_FETCH_MAX_WORKERS,
        )

        statuses: dict[str, str] = {}
        for alert in alerts:
            review = getattr(alert, "review", None)
            status = getattr(review, "status_in_portal", None) if review else None
            if status:
                statuses[alert.id_] = status
            else:
                self.logger.info(
                    f"Recorded Future classic alert {alert.id_} has no portal status. Skipping.",
                )

        return statuses

    def _push_status_to_product(self, alert_id: str, status: str, note: str) -> None:
        """Set the portal status of a classic alert.

        Args:
            alert_id (str): The Recorded Future classic alert ID.
            status (str): The new status.
            note (str): Audit text stored as the alert note.

        """
        self.api_client.update_alert(
            alert_id=alert_id,
            status=status,
            assignee=None,
            note=note,
        )


def main() -> None:
    """Run the classic alert status sync job."""
    SyncClassicAlertStatusJob().start()


if __name__ == "__main__":
    main()
