############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Pytest configuration for the Recorded Future integration test suite.

The modules inside `soar_sdk` import each other as top level modules, so that
directory has to be importable in its own right. `mp test` adds it to
PYTHONPATH before invoking pytest; `_ensure_soar_sdk_importable` does the same
when pytest is run directly, so the suite behaves identically either way. It
runs before the imports below because `integration_testing` itself imports
`OverflowManager` from the SDK at module level.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _ensure_soar_sdk_importable() -> None:
    """Add the bundled SOAR SDK directory to `sys.path` if it is not already."""
    try:
        import SiemplifyUtils  # noqa: F401, PLC0415
    except ModuleNotFoundError:
        for sdk_path in Path(sys.prefix).glob("lib/*/site-packages/soar_sdk"):
            sys.path.insert(0, str(sdk_path))
            return


_ensure_soar_sdk_importable()

from collections.abc import Iterator  # noqa: E402

import pytest  # noqa: E402
import SiemplifyBase as top_level_siemplify_base  # noqa: E402
import SiemplifyUtils  # noqa: E402
import soar_sdk.SiemplifyUtils  # noqa: E402
from integration_testing.common import use_live_api  # noqa: E402
from integration_testing.platform.script_output import (  # noqa: E402
    MockActionOutput,
    MockConnectorOutput,
)
from psengine import base_http_client  # noqa: E402
from psengine.config import Config  # noqa: E402
from soar_sdk.SiemplifyBase import SiemplifyBase  # noqa: E402
from soar_sdk.SiemplifyConnectors import SiemplifyConnectorExecution  # noqa: E402
from TIPCommon import DataStream  # noqa: E402

from recorded_future_intelligence.tests.core.product import RecordedFuture  # noqa: E402
from recorded_future_intelligence.tests.core.session import RecordedFutureSession  # noqa: E402

pytest_plugins = ("integration_testing.conftest",)


@pytest.fixture
def action_output(monkeypatch: pytest.MonkeyPatch) -> Iterator[MockActionOutput]:
    """Capture an action's result object.

    Overrides `integration_testing`'s own fixture, which redirects only the top
    level `SiemplifyUtils`. The SDK is importable under two names and these
    actions import `soar_sdk.SiemplifyUtils`, so an action that writes its
    output itself would otherwise bypass the capture entirely.
    """
    with MockActionOutput() as output:
        monkeypatch.setattr(SiemplifyUtils, "real_stdout", output.get_out_io())
        monkeypatch.setattr(soar_sdk.SiemplifyUtils, "real_stdout", output.get_out_io())
        monkeypatch.setattr(sys, "stderr", output.get_err_io())
        yield output


@pytest.fixture
def connector_output(monkeypatch: pytest.MonkeyPatch) -> Iterator[MockConnectorOutput]:
    """Capture a connector's returned package.

    Overrides `integration_testing`'s own fixture for the same reason
    `action_output` does: it redirects only the top level `SiemplifyUtils`, and
    these connectors are driven through `soar_sdk`.
    """
    with MockConnectorOutput() as output:
        monkeypatch.setattr(SiemplifyUtils, "real_stdout", output.get_out_io())
        monkeypatch.setattr(soar_sdk.SiemplifyUtils, "real_stdout", output.get_out_io())
        monkeypatch.setattr(sys, "stderr", output.get_err_io())
        yield output


@pytest.fixture(autouse=True)
def _unify_connector_class_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make `DataStreamFactory` recognise a connector built from `soar_sdk`.

    The SDK's files are reachable under two module names, so
    `SiemplifyConnectors.SiemplifyConnectorExecution` and
    `soar_sdk.SiemplifyConnectors.SiemplifyConnectorExecution` are two
    different classes from the same source. `TIPCommon` imports the first,
    these connectors instantiate the second, and
    `DataStreamFactory.get_stream_object` decides what to hand back with an
    `isinstance` check - which fails, returns None, and makes `read_ids` raise
    `AttributeError: 'NoneType' object has no attribute 'read_content'`.
    Pointing the check at the class the connectors actually use settles it.
    """
    monkeypatch.setattr(
        DataStream,
        "SiemplifyConnectorExecution",
        SiemplifyConnectorExecution,
    )


@pytest.fixture(autouse=True)
def _bridge_context_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Send context writes from the `soar_sdk` base class to the mock context.

    `set_metadata` patches the context getter on both copies of
    `SiemplifyBase` but the setter only on the top level one - its
    `_get_set_context_path_and_fn_2` names the same path as its non-`_2`
    counterpart. A connector's writes would therefore go to the real setter
    while its reads came from the mock store, so nothing it saved could be
    read back.

    The replacement forwards to whatever the top level setter is at call time,
    which is the mock store once `set_metadata` has patched it. Resolving it
    lazily matters: `set_metadata` patches inside the test call, after fixtures
    have already run.
    """

    def set_context_property_in_server(_self: object, *args: object) -> object:
        return top_level_siemplify_base.SiemplifyBase.set_context_property_in_server(*args)

    monkeypatch.setattr(
        SiemplifyBase,
        "set_context_property_in_server",
        set_context_property_in_server,
    )


@pytest.fixture(autouse=True)
def run_folder(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Point a connector's working directory at a per-test temporary one.

    `integration_testing` has a fixture of the same name, but it patches the
    `SiemplifyConnectorExecution` reachable as a top level module, and these
    connectors import `soar_sdk.SiemplifyConnectors` - a separate module
    object with its own class. Without this, `run_folder` runs for real and
    tries to `mkdir /opt/siemplify`. It must be a `property`, not a plain
    lambda, because the SDK reads it as one.
    """
    monkeypatch.setattr(
        SiemplifyConnectorExecution,
        "run_folder",
        property(lambda _: str(tmp_path)),
    )


@pytest.fixture(autouse=True)
def mock_sys_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace `sys.exit` with a no-op that accepts a bare call.

    Overrides `integration_testing`'s own fixture, whose `lambda _: ...` is
    stricter than the real `sys.exit` and rejects the no-argument form that
    actions with a custom `end_script` use.
    """
    monkeypatch.setattr(sys, "exit", lambda *_: ...)


@pytest.fixture(autouse=True)
def _isolate_from_local_tls_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hide a developer's `REQUESTS_CA_BUNDLE` from the SDK bootstrap.

    `SiemplifyBase` warns about that variable through the mock logger, which
    has no `warning` method, so a machine behind a TLS proxy would fail every
    action test for a reason that has nothing to do with the integration.
    """
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)


@pytest.fixture
def recorded_future() -> RecordedFuture:
    """Provide the in-memory Recorded Future API for a test to seed."""
    return RecordedFuture()


@pytest.fixture(autouse=True)
def script_session(
    monkeypatch: pytest.MonkeyPatch,
    recorded_future: RecordedFuture,
) -> RecordedFutureSession:
    """Mock the session psengine creates, and expose request history.

    psengine does `from requests import Session` in `base_http_client`, so the
    name has to be replaced there - patching `requests.Session` is too late.
    """
    session = RecordedFutureSession(recorded_future)
    if not use_live_api():
        monkeypatch.setattr(base_http_client, "Session", lambda: session)

    return session


@pytest.fixture(autouse=True)
def sdk_session(
    monkeypatch: pytest.MonkeyPatch,
    recorded_future: RecordedFuture,
) -> RecordedFutureSession:
    """Mock the SDK's own session (entity updates, insights)."""
    session = RecordedFutureSession(recorded_future)
    if not use_live_api():
        monkeypatch.setattr(SiemplifyBase, "create_session", lambda *_: session)

    return session


@pytest.fixture(autouse=True)
def _reset_psengine_config() -> Iterator[None]:
    """Clear psengine's process wide config so tests cannot leak settings.

    `Config.init` replaces a class level singleton; without this a token or SSL
    setting from one action test silently applies to the next.
    """
    Config.reset_instance()
    yield
    Config.reset_instance()
