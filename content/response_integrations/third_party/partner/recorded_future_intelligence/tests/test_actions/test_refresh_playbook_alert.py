############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the Refresh Playbook Alert action.

This is the one action that drives the Google SecOps platform as well as the
Recorded Future API: it reads the alert card it was run from and writes
entities back to the case. `soar_case` stands in for that side - see its
docstring - so these tests cover what the action itself decides: the two
guards it applies before doing any work, whether it asks for screenshots, and
what it puts in the case. How the manager turns an alert into entities is
covered in `test_manager`.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from soar_sdk.SiemplifyAction import SiemplifyAction
from TIPCommon.base.action import ExecutionState

from recorded_future_intelligence.actions import RefreshPlaybookAlert
from recorded_future_intelligence.core.constants import (
    DEFAULT_DEVICE_VENDOR,
    PLAYBOOK_ALERT_PRODUCT,
)
from recorded_future_intelligence.core.exceptions import RecordedFutureInvalidCaseTypeError
from recorded_future_intelligence.tests.common import (
    CONFIG_PATH,
    make_playbook_alert,
    make_screenshot,
)
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.core.session import RecordedFutureSession

if TYPE_CHECKING:
    from TIPCommon.types import SingleJson

SCREENSHOT_BYTES = b"\x89PNG\r\n\x1a\nrefreshed"

DOMAIN_ABUSE_PARAMETERS = {
    "Playbook Alert ID": "task:pa-1",
    "Category": "domain_abuse",
}


class SoarCase:
    """The Google SecOps side of a refresh, recording what was written to it.

    Args:
        reporting_vendor: The vendor on the alert card the action was run from.
        reporting_product: The product on that alert card.
        linked_cases: The cases already linked to the Recorded Future alert.

    """

    def __init__(
        self,
        reporting_vendor: str = DEFAULT_DEVICE_VENDOR,
        reporting_product: str = PLAYBOOK_ALERT_PRODUCT,
        linked_cases: list[int] | None = None,
    ) -> None:
        self.current_alert = SimpleNamespace(
            reporting_vendor=reporting_vendor,
            reporting_product=reporting_product,
            rule_generator="Domain Abuse",
        )
        self.linked_cases = linked_cases or []
        self.added_entities: list[SingleJson] = []

    @property
    def added_identifiers(self) -> list[str]:
        """Return the identifier of every entity the action added to the case."""
        return [entity["entity_identifier"] for entity in self.added_entities]


@pytest.fixture
def soar_case(monkeypatch: pytest.MonkeyPatch) -> SoarCase:
    """Stand in for the Google SecOps platform the action reads and writes.

    The in-memory product doubles the Recorded Future API, not Google SecOps,
    so a real `SiemplifyAction` would send these three calls to the mock
    session and get a `ValueError` for an unrouted path - which
    `_load_alert` swallows, leaving `current_alert` as None and the action
    failing on an `AttributeError` before it reaches anything worth testing.
    Replacing the three members it uses keeps the platform out of the way
    while still recording what the action asked the platform to do.
    """
    case = SoarCase()

    def add_entity_to_case(_self: object, **kwargs: object) -> None:
        case.added_entities.append(kwargs)

    monkeypatch.setattr(
        SiemplifyAction,
        "current_alert",
        property(lambda _: case.current_alert),
    )
    monkeypatch.setattr(
        SiemplifyAction,
        "get_cases_by_ticket_id",
        lambda *_, **__: case.linked_cases,
    )
    monkeypatch.setattr(SiemplifyAction, "add_entity_to_case", add_entity_to_case)

    return case


class TestRefreshPlaybookAlert:
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters=DOMAIN_ABUSE_PARAMETERS,
    )
    def test_refreshes_the_alert_and_adds_its_entity_to_the_case(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
        soar_case: SoarCase,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert(
                "task:pa-1",
                entity_id="idn:bad-example.com",
                entity_name="bad-example.com",
            ),
        )

        RefreshPlaybookAlert.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True
        assert soar_case.added_identifiers == ["bad-example.com"]

        event = action_output.results.json_output.json_result
        assert event["playbook_alert_id"] == "task:pa-1"
        assert event["category"] == "domain_abuse"

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters=DOMAIN_ABUSE_PARAMETERS,
    )
    def test_reports_the_cases_already_linked_to_the_alert(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
        soar_case: SoarCase,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1"),
        )
        soar_case.linked_cases = [11, 12]

        RefreshPlaybookAlert.main()

        assert action_output.results.json_output.json_result["linked_cases"] == [11, 12]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={**DOMAIN_ABUSE_PARAMETERS, "Fetch Screenshots": True},
    )
    def test_fetches_screenshots_when_asked(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
        soar_case: SoarCase,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert(
                "task:pa-1",
                screenshots=[make_screenshot("img-1")],
            ),
        )
        recorded_future.set_screenshot("img-1", SCREENSHOT_BYTES)

        RefreshPlaybookAlert.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        requested = [
            record.request.url.path for record in script_session.request_history if "/image/" in record.request.url.path
        ]
        assert requested == ["/playbook-alert/domain_abuse/task:pa-1/image/img-1"]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters=DOMAIN_ABUSE_PARAMETERS,
    )
    def test_leaves_screenshots_alone_by_default(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
        soar_case: SoarCase,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert(
                "task:pa-1",
                screenshots=[make_screenshot("img-1")],
            ),
        )
        recorded_future.set_screenshot("img-1", SCREENSHOT_BYTES)

        RefreshPlaybookAlert.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert not [record for record in script_session.request_history if "/image/" in record.request.url.path]

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters=DOMAIN_ABUSE_PARAMETERS,
    )
    def test_refuses_a_case_that_is_not_a_playbook_alert(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
        soar_case: SoarCase,
    ) -> None:
        """The guard runs outside the try, so its error leaves the action.

        Google SecOps records that as a failed run, but the analyst gets a
        traceback rather than the message the guard was given.
        """
        soar_case.current_alert.reporting_product = "Some Other Product"

        with pytest.raises(RecordedFutureInvalidCaseTypeError):
            RefreshPlaybookAlert.main()

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters={"Playbook Alert ID": "task:pa-1", "Category": ""},
    )
    def test_refuses_an_alert_label_it_cannot_map_to_a_category(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
        soar_case: SoarCase,
    ) -> None:
        """An unmappable label reaches the action as an empty Category.

        The playbook derives the parameter from `LABEL_MAP`, so a label that is
        not in it arrives blank rather than absent. `Category` is extracted as
        mandatory, though, so the blank value is rejected during parameter
        extraction and the action's own `LABEL_MAP` guard never runs - the
        analyst sees "Missing mandatory parameter" rather than the list of
        accepted labels the guard was written to give them.
        """
        with pytest.raises(Exception, match="Missing mandatory parameter Category"):
            RefreshPlaybookAlert.main()

    @pytest.mark.xfail(
        strict=True,
        reason="Bug: `RecordedFutureManager.add_lightweight_entity` warns "
        "through `self.siemplify.warn` (core/RecordedFutureManager.py:483), "
        "which exists on the logger, not on `SiemplifyAction`. The resulting "
        "AttributeError escapes into the action's catch-all, so one entity "
        "the API reported without a type prefix fails the whole refresh "
        "instead of being skipped. Remove this marker once fixed.",
    )
    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters=DOMAIN_ABUSE_PARAMETERS,
    )
    def test_skips_an_entity_that_carries_no_type_prefix(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
        soar_case: SoarCase,
    ) -> None:
        recorded_future.set_playbook_alert(
            "domain_abuse",
            "task:pa-1",
            make_playbook_alert("task:pa-1", entity_id="bad-example.com"),
        )

        RefreshPlaybookAlert.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert soar_case.added_entities == []

    @set_metadata(
        integration_config_file_path=CONFIG_PATH,
        parameters=DOMAIN_ABUSE_PARAMETERS,
    )
    def test_reports_an_alert_the_api_does_not_hold(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
        soar_case: SoarCase,
    ) -> None:
        RefreshPlaybookAlert.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False
        assert soar_case.added_entities == []
