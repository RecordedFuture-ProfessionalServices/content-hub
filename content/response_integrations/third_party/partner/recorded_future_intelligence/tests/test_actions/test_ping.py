############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the Ping action.

Ping proves connectivity by enriching a known-good IP, so a 401 from the API
has to surface as a failed action rather than an empty success.
"""

from __future__ import annotations

import pytest
from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from TIPCommon.base.action import ExecutionState

from recorded_future_intelligence.actions import Ping
from recorded_future_intelligence.core.constants import PING_IP
from recorded_future_intelligence.tests.common import CONFIG_PATH, make_enrichment_record
from recorded_future_intelligence.tests.core.product import RecordedFuture
from recorded_future_intelligence.tests.core.session import RecordedFutureSession


class TestPing:
    @set_metadata(integration_config_file_path=CONFIG_PATH)
    def test_connectivity_succeeds(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.set_enrichment("ip", PING_IP, make_enrichment_record(PING_IP, "ip"))

        Ping.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True
        assert "Successfully connected" in action_output.results.output_message

    @pytest.mark.xfail(
        strict=True,
        reason="Bug: Ping discards the return value of "
        "RecordedFutureManager.test_connectivity (actions/Ping.py:70), which "
        "returns False rather than raising when psengine swallows the 401. A "
        "rejected token therefore reports COMPLETED / 'Successfully "
        "connected'. Remove this marker once fixed.",
    )
    @set_metadata(integration_config_file_path=CONFIG_PATH)
    def test_connectivity_fails_on_rejected_token(
        self,
        script_session: RecordedFutureSession,
        action_output: MockActionOutput,
        recorded_future: RecordedFuture,
    ) -> None:
        recorded_future.authorized = False

        Ping.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False
        assert "Failed to connect" in action_output.results.output_message
