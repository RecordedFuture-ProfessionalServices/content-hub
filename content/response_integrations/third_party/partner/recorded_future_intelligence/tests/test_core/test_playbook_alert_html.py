############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the HTML chunks the playbook alert widgets render.

`create_events_with_html` is the only producer of these keys and the widgets
are the only consumers, so a category that stops emitting its chunk shows up
as a blank panel in the case rather than an error anywhere.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from recorded_future_intelligence.core.datamodels import PlaybookAlert

START = datetime(2026, 9, 1, 3, 4, 5, tzinfo=timezone.utc)
END = datetime(2026, 9, 2, 3, 4, 5, tzinfo=timezone.utc)

# Each category renders a different set of panels.
CATEGORY_CHUNKS = {
    "domain_abuse": {"targets_html", "assessment_html", "dns_html", "screenshots_html"},
    "code_repo_leakage": {"targets_html", "assessment_html"},
    "cyber_vulnerability": {"targets_html", "insikt_html", "affected_products_html"},
    "identity_novel_exposures": {"targets_html", "hashes_html", "secrets_html", "av_html"},
    "third_party_risk": {"targets_html", "assessment_html"},
    "malware_report": {"matched_hashes_html"},
}


def make_alert(category: str, raw_data: dict | None = None, **overrides: object) -> PlaybookAlert:
    """Build a playbook alert of the given category."""
    fields = {
        "raw_data": raw_data if raw_data is not None else {},
        "id_": "task:abc-123",
        "alert_url": "https://app.recordedfuture.com/playbook-alerts/task:abc-123",
        "category": category,
        "label": category.replace("_", " ").title(),
        "start": START,
        "end": END,
        "title": "An alert",
        "priority": "High",
    }
    fields.update(overrides)
    return PlaybookAlert(**fields)


@pytest.mark.parametrize(("category", "expected"), CATEGORY_CHUNKS.items())
def test_category_emits_its_html_chunks(category: str, expected: set[str]) -> None:
    """Every panel the category's widget reads is present, even with no data."""
    event = make_alert(category).create_events_with_html()

    assert expected <= set(event)


def test_unknown_category_emits_no_html() -> None:
    """A category Recorded Future adds later must not break the connector."""
    event = make_alert("brand_new_category").create_events_with_html()

    assert not [key for key in event if key.endswith("_html")]
    assert event["category"] == "brand_new_category"


def test_domain_abuse_lists_its_targets() -> None:
    """Domain abuse targets are plain strings rather than objects."""
    event = make_alert(
        "domain_abuse",
        {"panel_status": {"targets": ["evil-example.com", "evil-exarnple.com"]}},
    ).create_events_with_html()

    assert event["targets_html"] == "<li>evil-example.com</li> <li>evil-exarnple.com</li>"


def test_other_categories_read_the_target_name() -> None:
    """Every other category carries targets as objects with a `name`."""
    event = make_alert(
        "third_party_risk",
        {"panel_status": {"targets": [{"name": "Acme Corp"}]}},
    ).create_events_with_html()

    assert event["targets_html"] == "<li>Acme Corp</li>"


def test_targets_without_a_name_are_skipped() -> None:
    """One malformed target must not drop the whole panel."""
    event = make_alert(
        "third_party_risk",
        {"panel_status": {"targets": [{"name": "Acme Corp"}, {"no_name": "?"}]}},
    ).create_events_with_html()

    assert event["targets_html"] == "<li>Acme Corp</li>"


def test_domain_abuse_lists_its_assessments() -> None:
    """The assessment panel explains why the domain was flagged."""
    event = make_alert(
        "domain_abuse",
        {"panel_status": {"context_list": [{"context": "phishing"}, {"context": "malware"}]}},
    ).create_events_with_html()

    assert event["assessment_html"] == "<li>phishing</li> <li>malware</li>"


def test_domain_abuse_renders_screenshots_inline() -> None:
    """Screenshots ride along as data URIs so the widget needs no credentials."""
    event = make_alert(
        "domain_abuse",
        screenshots={
            "img:1": {
                "description": "Landing page",
                "mime_type": "image/png",
                "image_b64": "aGVsbG8=",
                "created": "09/01/2026 03:04:05",
            },
        },
    ).create_events_with_html()

    assert "data:image/png;base64,aGVsbG8=" in event["screenshots_html"]
    assert "Landing page" in event["screenshots_html"]


def test_screenshot_descriptions_are_escaped() -> None:
    """A description is attacker controlled, so it must not inject markup."""
    event = make_alert(
        "domain_abuse",
        screenshots={
            "img:1": {
                "description": "<script>alert(1)</script>",
                "mime_type": "image/png",
                "image_b64": "aGVsbG8=",
                "created": "09/01/2026 03:04:05",
            },
        },
    ).create_events_with_html()

    assert "<script>" not in event["screenshots_html"]
    assert "&lt;script&gt;" in event["screenshots_html"]


def test_incomplete_screenshots_are_skipped() -> None:
    """A screenshot whose bytes failed to download must not drop the others."""
    event = make_alert(
        "domain_abuse",
        screenshots={
            "img:1": {"description": "No bytes"},
            "img:2": {
                "description": "Landing page",
                "mime_type": "image/png",
                "image_b64": "aGVsbG8=",
                "created": "09/01/2026 03:04:05",
            },
        },
    ).create_events_with_html()

    assert event["screenshots_html"].count("data:image") == 1


def test_html_generation_does_not_mutate_the_raw_alert() -> None:
    """The raw payload is also written to the case wall, so it must stay clean."""
    raw = {"panel_status": {"targets": ["evil-example.com"]}}
    alert = make_alert("domain_abuse", raw)

    alert.create_events_with_html()

    assert raw == {"panel_status": {"targets": ["evil-example.com"]}}
