############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the helpers in `UtilsManager`.

The `is_*` predicates decide whether the tracking connector raises a new case
for a playbook alert update, so a wrong answer either floods the SOC or drops
a real change silently. They run against captured `panel_log_v2` payloads.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from soar_sdk.SiemplifyDataModel import EntityTypes

from recorded_future_intelligence.core.UtilsManager import (
    detect_image_mime_type,
    format_timestamp,
    get_entity_original_identifier,
    get_recorded_future_document_id,
    get_recorded_future_id,
    is_create_new_case,
    is_entity_added,
    is_new_assessment,
    is_priority_increase,
    is_reopened,
    map_secops_entities_to_rf,
)

LOGS_DIR = Path(__file__).resolve().parents[1] / "statics" / "playbook_alert_tracking_connector"


def logs(file: str) -> list:
    """Load the `panel_log_v2` entries from a captured playbook alert."""
    data = json.loads((LOGS_DIR / file).read_text(encoding="utf-8"))
    return data["data"]["panel_log_v2"]


def make_entity(identifier: str, entity_type: str, **properties: str) -> SimpleNamespace:
    """Build a stand-in for a Google SecOps entity."""
    return SimpleNamespace(
        identifier=identifier,
        entity_type=entity_type,
        additional_properties=dict(properties),
    )


# ---------------------------------------------------------------------------
# Playbook alert update predicates
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("file", "expected"),
    [
        ("is_reopened.json", True),
        ("not_reopened.json", False),
        ("entity_added.json", False),
        ("empty_logs.json", False),
    ],
)
def test_is_reopened(file: str, expected: bool) -> None:
    """Only a Resolved/Dismissed to New/InProgress transition counts as reopened."""
    assert is_reopened(playbook_alert_logs=logs(file)) is expected


@pytest.mark.parametrize(
    ("file", "expected"),
    [
        ("priority_increase_info_moderate.json", True),
        ("priority_increase_moderate_high.json", True),
        ("priority_decrease_high_info.json", False),
        ("entity_added.json", False),
        ("empty_logs.json", False),
    ],
)
def test_is_priority_increase(file: str, expected: bool) -> None:
    """A priority change only counts when the new severity outranks the old."""
    assert is_priority_increase(playbook_alert_logs=logs(file)) is expected


@pytest.mark.parametrize(
    ("file", "expected"),
    [
        ("assessment_added.json", True),
        ("assessment_removed.json", False),
        ("is_reopened.json", False),
        ("empty_logs.json", False),
    ],
)
def test_is_new_assessment(file: str, expected: bool) -> None:
    """A removed assessment must not be mistaken for a new one."""
    assert is_new_assessment(playbook_alert_logs=logs(file)) is expected


@pytest.mark.parametrize(
    ("file", "expected"),
    [
        ("entity_added.json", True),
        ("priority_increase_info_moderate.json", True),
        ("entity_removed.json", False),
        ("is_reopened.json", False),
        ("empty_logs.json", False),
    ],
)
def test_is_entity_added(file: str, expected: bool) -> None:
    """Any of the entity change types with an `added` list counts, including DNS changes."""
    assert is_entity_added(playbook_alert_logs=logs(file)) is expected


# ---------------------------------------------------------------------------
# Connector case creation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("file", "filters", "expected"),
    [
        ("entity_added.json", {"entity_added": True}, True),
        ("entity_removed.json", {"entity_added": True}, False),
        ("priority_increase_info_moderate.json", {"entity_added": True}, True),
        ("priority_increase_info_moderate.json", {"entity_added": False}, False),
        ("is_reopened.json", {"reopened": True}, True),
        ("not_reopened.json", {"reopened": True}, False),
        ("assessment_added.json", {"new_assessment": True}, True),
        ("assessment_removed.json", {"new_assessment": True}, False),
        ("priority_increase_moderate_high.json", {"priority_increase": True}, True),
        ("priority_decrease_high_info.json", {"priority_increase": True}, False),
        ("empty_logs.json", {"entity_added": True}, False),
    ],
)
def test_is_create_new_case(file: str, filters: dict, expected: bool) -> None:
    """A case is raised when any enabled filter matches the alert's logs."""
    assert is_create_new_case(playbook_alert_logs=logs(file), active_filters=filters) is expected


def test_is_create_new_case_ignores_unknown_filters() -> None:
    """An unrecognised connector parameter must not raise a case on its own."""
    assert (
        is_create_new_case(
            playbook_alert_logs=logs("entity_added.json"),
            active_filters={"bad_key": True, "bad_key2": False},
        )
        is False
    )


def test_is_create_new_case_needs_a_matching_filter() -> None:
    """An update the connector is not watching for does not raise a case."""
    assert (
        is_create_new_case(
            playbook_alert_logs=logs("entity_added.json"),
            active_filters={"reopened": True},
        )
        is False
    )


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        ("2026-09-01T13:45:30.123Z", "09/01/2026 13:45:30"),
        ("2026-09-01T13:45:30Z", "09/01/2026 13:45:30"),
        ("", ""),
        (None, ""),
    ],
)
def test_format_timestamp(timestamp: str | None, expected: str) -> None:
    """Both the millisecond and second precision API formats are accepted."""
    assert format_timestamp(timestamp) == expected


@pytest.mark.parametrize(
    ("image_bytes", "expected"),
    [
        (b"\x89PNG\r\n\x1a\n rest", "image/png"),
        (b"\xff\xd8\xff rest", "image/jpeg"),
        (b"GIF87a rest", "image/gif"),
        (b"GIF89a rest", "image/gif"),
        (b"RIFF\x00\x00\x00\x00WEBP rest", "image/webp"),
        (b"not an image", "image/png"),
    ],
)
def test_detect_image_mime_type(image_bytes: bytes, expected: str) -> None:
    """Screenshot bytes are typed from their magic number, defaulting to PNG."""
    assert detect_image_mime_type(image_bytes) == expected


def test_detect_image_mime_type_rejects_riff_that_is_not_webp() -> None:
    """A RIFF container that is not WebP must not be typed as one."""
    assert detect_image_mime_type(b"RIFF\x00\x00\x00\x00WAVE rest") == "image/png"


# ---------------------------------------------------------------------------
# Entity helpers
# ---------------------------------------------------------------------------


def test_get_entity_original_identifier_prefers_the_original() -> None:
    """SecOps uppercases identifiers, so the original casing has to be recovered."""
    entity = make_entity("EXAMPLE.COM", EntityTypes.DOMAIN, OriginalIdentifier="example.com")

    assert get_entity_original_identifier(entity) == "example.com"


def test_get_entity_original_identifier_falls_back_to_the_identifier() -> None:
    """An entity SecOps never rewrote has no `OriginalIdentifier`."""
    assert get_entity_original_identifier(make_entity("1.1.1.1", EntityTypes.ADDRESS)) == "1.1.1.1"


def test_recorded_future_ids_default_to_empty() -> None:
    """An entity the integration has not enriched carries no Recorded Future IDs."""
    entity = make_entity("1.1.1.1", EntityTypes.ADDRESS)

    assert get_recorded_future_id(entity) == ""
    assert get_recorded_future_document_id(entity) == ""


def test_recorded_future_ids_are_read_from_enrichment() -> None:
    """Enrichment stamps the IDs later actions look up."""
    entity = make_entity("1.1.1.1", EntityTypes.ADDRESS, RF_id="ip:1.1.1.1", RF_doc_id="doc-1")

    assert get_recorded_future_id(entity) == "ip:1.1.1.1"
    assert get_recorded_future_document_id(entity) == "doc-1"


def test_map_secops_entities_to_rf_prefixes_each_type() -> None:
    """List actions address entities by their Recorded Future prefixed ID."""
    entities = [
        make_entity("1.1.1.1", EntityTypes.ADDRESS),
        make_entity("example.com", EntityTypes.DOMAIN),
        make_entity("host.example.com", EntityTypes.HOSTNAME),
        make_entity("https://example.com", EntityTypes.URL),
    ]

    assert map_secops_entities_to_rf(entities) == [
        "ip:1.1.1.1",
        "idn:example.com",
        "idn:host.example.com",
        "url:https://example.com",
    ]


def test_map_secops_entities_to_rf_drops_unmapped_types() -> None:
    """An unmapped type is skipped rather than sent as a malformed ID."""
    entities = [
        make_entity("1.1.1.1", EntityTypes.ADDRESS),
        make_entity("some-user", EntityTypes.USER),
    ]

    assert map_secops_entities_to_rf(entities) == ["ip:1.1.1.1"]
