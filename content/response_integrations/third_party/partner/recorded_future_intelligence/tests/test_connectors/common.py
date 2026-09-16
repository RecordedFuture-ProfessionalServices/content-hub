############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Shared helpers for the connector tests.

Connector parameters arrive as the strings the platform stores, not as typed
values: `extract_connector_param` treats a falsy value as absent and rejects it
when the parameter is mandatory, so a real `False` for `Verify SSL` reads as
"missing mandatory parameter". Every boolean here is therefore `"true"` or
`"false"`, exactly as the platform would supply it.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from SiemplifyConnectorsDataModel import ConnectorContext

if TYPE_CHECKING:
    from TIPCommon.types import SingleJson

API_URL = "https://api.recordedfuture.com"
API_KEY = "0123456789abcdef0123456789abcdef"

TRACKING_CONNECTOR_PARAMS: SingleJson = {
    "DeviceProductField": "device_product",
    "EventClassId": "category",
    "Environment Regex Pattern": ".*",
    "PythonProcessTimeout": 180,
    "API URL": API_URL,
    "API Key": API_KEY,
    "Search Max Hours Backwards": 24,
    "Playbook Alert Categories": "domain_abuse",
    "Playbook Alert Reopened": "false",
    "Priority Increased": "false",
    "New Assessment Added": "false",
    "Entity Added": "false",
    "Max Alerts To Fetch": 100,
    "Severity": "Medium",
    "Enable Overflow": "false",
    "Verify SSL": "false",
}


PLAYBOOK_CONNECTOR_PARAMS: SingleJson = {
    "DeviceProductField": "device_product",
    "EventClassId": "category",
    "Environment Regex Pattern": ".*",
    "PythonProcessTimeout": 180,
    "API URL": API_URL,
    "API Key": API_KEY,
    "Fetch Max Hours Backwards": 24,
    "Playbook Alert Categories": "domain_abuse",
    "Max Alerts To Fetch": 100,
    "Severity": "Medium",
    "Enable Overflow": "false",
    "Verify SSL": "false",
}

CLASSIC_CONNECTOR_PARAMS: SingleJson = {
    "DeviceProductField": "device_product",
    "EventClassId": "category",
    "Environment Regex Pattern": ".*",
    "PythonProcessTimeout": 180,
    "API URL": API_URL,
    "API Key": API_KEY,
    "Fetch Max Hours Backwards": 24,
    "Alert Statuses": "New",
    "Max Alerts To Fetch": 100,
    "Severity": "Medium",
    "Use whitelist as a blacklist": "false",
    "Enable Overflow": "false",
    "Extract all Entities": "false",
    "Verify SSL": "false",
}


def connector_params(**overrides: object) -> SingleJson:
    """Return the tracking connector's parameters with `overrides` applied.

    Args:
        **overrides: Parameter values to replace.

    Returns:
        The parameter dictionary.

    """
    return {**TRACKING_CONNECTOR_PARAMS, **overrides}


def playbook_params(**overrides: object) -> SingleJson:
    """Return the Playbook Alerts connector's parameters with `overrides` applied.

    Args:
        **overrides: Parameter values to replace.

    Returns:
        The parameter dictionary.

    """
    return {**PLAYBOOK_CONNECTOR_PARAMS, **overrides}


def classic_params(**overrides: object) -> SingleJson:
    """Return the Classic Alerts connector's parameters with `overrides` applied.

    Args:
        **overrides: Parameter values to replace.

    Returns:
        The parameter dictionary.

    """
    return {**CLASSIC_CONNECTOR_PARAMS, **overrides}


def allowlist_context(allowlist: list[str]) -> SingleJson:
    """Return an `input_context` carrying a connector allowlist.

    `set_metadata` copies its `parameters` into the context's connector info
    when that info has no parameters of its own, so leaving `params` empty here
    keeps the parameter plumbing working. `connector_context` has to be a real
    `ConnectorContext`, not a plain dict: `_fill_missing_context` reaches
    straight through it for `connector_info`.

    Args:
        allowlist: The rule names to put on the connector's allowlist.

    Returns:
        The input context.

    """
    return {"connector_context": ConnectorContext({"params": [], "allow_list": allowlist})}


def minutes_ago(minutes: int) -> str:
    """Return a log timestamp `minutes` in the past, in the API's format.

    Built relative to now rather than hard coded because the connector derives
    its update window from the last success time, which is itself relative to
    now - a fixed date would fall outside the window and the alert would be
    skipped for the wrong reason. Local time, matching the naive
    `datetime.now()` the connector compares against.

    Args:
        minutes: How far in the past the timestamp should be.

    Returns:
        The timestamp, with milliseconds and a trailing `Z`.

    """
    moment = datetime.now() - timedelta(minutes=minutes)  # noqa: DTZ005
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
