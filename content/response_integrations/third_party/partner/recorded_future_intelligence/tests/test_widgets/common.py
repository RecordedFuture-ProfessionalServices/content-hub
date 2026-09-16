############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Shared discovery helpers for the predefined widget tests."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

INTEGRATION_ROOT = Path(__file__).resolve().parents[2]
WIDGETS_DIR = INTEGRATION_ROOT / "widgets"
ACTIONS_DIR = INTEGRATION_ROOT / "actions"

# The placeholder Google SecOps substitutes with the bound action's JSON result
# before serving the widget.
JSON_RESULT_PLACEHOLDER = "[{stepInstanceName}.JsonResult]"

# `const allowlistedFields = ["entity", "location"];`
ALLOWLIST_PATTERN = re.compile(
    r"const\s+allowlistedFields\s*=\s*\[(?P<body>[^\]]*)\]\s*;",
)

# The Recorded Future payload shapes the widgets render. Each is a different
# endpoint with a different contract, so each gets its own data-contract test
# module and none of them inherits assertions that do not apply to it.
DATA_MODELS = (
    "enrichment",
    "bulk-enrichment",
    "sandbox-detonation",
    "sandbox-hash-report",
)

# Which payload shape each widget renders, and so which data-contract module
# tests it.
#
# This lives here rather than in the widgets because the shipped HTML is
# generated with its comments stripped, leaving nowhere in the file to declare
# it, and `mp` validates the metadata key set strictly so an extra YAML key
# would be rejected at build time. The table is therefore the test suite's own
# record, and `test_widget_routing_matches_its_script_constants` in
# test_widget_metadata pins every entry to a constant the widget's script
# actually declares, so a widget cannot be re-pointed at a different payload
# without this table failing.
WIDGET_DATA_MODELS = {
    "DetonateFile": "sandbox-detonation",
    "DetonateURL": "sandbox-detonation",
    "EnrichCVE": "enrichment",
    "EnrichHash": "enrichment",
    "EnrichHost": "enrichment",
    "EnrichIOC": "enrichment",
    "EnrichIOCsBulk": "bulk-enrichment",
    "EnrichIP": "enrichment",
    "EnrichURL": "enrichment",
    "SearchHashMalwareIntelligence": "sandbox-hash-report",
}

# The script constant that distinguishes each payload shape, used to verify
# WIDGET_DATA_MODELS against the widgets themselves. `SANDBOX_BANDS` marks the
# sandbox family and `CRITICALITY_BANDS` the enrichment family; within each,
# the second constant separates the two members.
DATA_MODEL_FINGERPRINTS = {
    "enrichment": ("CRITICALITY_BANDS",),
    "bulk-enrichment": ("CRITICALITY_BANDS", "INTEL_CARD_PREFIX"),
    "sandbox-detonation": ("SANDBOX_BANDS", "IOC_TYPE_LABELS"),
    "sandbox-hash-report": ("SANDBOX_BANDS",),
}

# `const SANDBOX_REPORT_PREFIX = "https://sandbox.recordedfuture.com/";`
STRING_CONSTANT_TEMPLATE = r'const\s+{name}\s*=\s*"(?P<value>[^"]*)"\s*;'

# `const IOC_TYPE_LABELS = {urls: "URL", domains: "Domain"};`
OBJECT_CONSTANT_TEMPLATE = r"const\s+{name}\s*=\s*\{{(?P<body>[^}}]*)\}}\s*;"

WIDGET_NAMES = sorted(path.stem for path in WIDGETS_DIR.glob("*.yaml"))


def widget_yaml(name: str) -> dict[str, Any]:
    """Return the parsed metadata for a widget."""
    return yaml.safe_load((WIDGETS_DIR / f"{name}.yaml").read_text(encoding="utf-8"))


def widget_html(name: str) -> str:
    """Return the raw HTML body for a widget."""
    return (WIDGETS_DIR / f"{name}.html").read_text(encoding="utf-8")


def widget_allowlist(name: str) -> list[str]:
    """Extract the `allowlistedFields` array declared in a widget's script.

    Returns:
        The field names the widget keeps for its generic detail list.

    Raises:
        AssertionError: If the declaration is missing or not a single array.

    """
    matches = ALLOWLIST_PATTERN.findall(widget_html(name))
    assert len(matches) == 1, f"{name}.html must declare `allowlistedFields` exactly once, found {len(matches)}"
    return [field.strip().strip("\"'") for field in matches[0].split(",") if field.strip()]


def widget_data_model(name: str) -> str:
    """Return the Recorded Future payload shape a widget renders.

    Returns an empty string for an unrouted widget rather than raising, because
    the data-contract modules call this at import time to route their
    parameters: raising here would turn one missing table entry into a
    collection error across three modules instead of a single clear failure
    from `test_widget_is_routed_to_a_known_data_model`.

    Returns:
        The widget's data model name, or "" if the table does not route it.

    """
    return WIDGET_DATA_MODELS.get(name, "")


def widgets_for_model(model: str) -> list[str]:
    """List the widgets declaring a given data model.

    A widget whose HTML sibling is missing is skipped, so that the parity test in
    test_widget_metadata reports that rather than every data-contract module
    failing to import.

    Returns:
        The widget names rendering `model`, sorted.

    """
    return sorted(
        name for name in WIDGET_NAMES if (WIDGETS_DIR / f"{name}.html").is_file() and widget_data_model(name) == model
    )


def widget_string_constant(name: str, constant: str) -> str:
    """Return the value of a `const <constant> = "...";` in a widget's script.

    Returns:
        The string literal assigned to the constant.

    Raises:
        AssertionError: If the declaration is missing or duplicated.

    """
    pattern = re.compile(STRING_CONSTANT_TEMPLATE.format(name=re.escape(constant)))
    matches = pattern.findall(widget_html(name))
    assert len(matches) == 1, (
        f"{name}.html must declare `{constant}` exactly once as a string literal, found {len(matches)}"
    )
    return matches[0]


def widget_object_constant_keys(name: str, constant: str) -> list[str]:
    """Return the keys of a `const <constant> = {a: "...", b: "..."};` declaration.

    Returns:
        The declared keys, in source order.

    Raises:
        AssertionError: If the declaration is missing or duplicated.

    """
    pattern = re.compile(OBJECT_CONSTANT_TEMPLATE.format(name=re.escape(constant)))
    matches = pattern.findall(widget_html(name))
    assert len(matches) == 1, (
        f"{name}.html must declare `{constant}` exactly once as an object literal, found {len(matches)}"
    )
    return [entry.split(":", 1)[0].strip() for entry in matches[0].split(",") if entry.strip()]


def action_metadata() -> dict[str, dict[str, Any]]:
    """Map every action's display name to its parsed metadata.

    Returns:
        A mapping of action display name to action metadata.

    """
    actions: dict[str, dict[str, Any]] = {}
    for path in sorted(ACTIONS_DIR.glob("*.yaml")):
        meta = yaml.safe_load(path.read_text(encoding="utf-8"))
        actions[meta["name"]] = meta
    return actions


def json_result_example(action_meta: dict[str, Any]) -> Any:
    """Load the committed JSON result example for an action.

    Returns:
        The decoded example payload, or None when the action declares none.

    """
    for result in action_meta.get("dynamic_results_metadata") or []:
        if result.get("result_name") == "JsonResult":
            path = INTEGRATION_ROOT / result["result_example_path"]
            return json.loads(path.read_text(encoding="utf-8"))
    return None
