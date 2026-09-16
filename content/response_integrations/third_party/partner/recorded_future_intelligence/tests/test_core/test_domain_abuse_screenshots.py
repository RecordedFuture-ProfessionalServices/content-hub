############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for Domain Abuse screenshot retrieval and rendering.

The image bytes take an unusual route to the case view: psengine keeps them on
a private attribute that `dump_model` does not emit, so they are fetched
separately, base64 encoded, and rendered into a `screenshots_html` chunk that
the Domain Abuse widget injects. These tests cover the two places that path can
break silently - a screenshot that never reaches the HTML, and a payload large
enough to fail the whole action on the platform's JSON result size cap.
"""

from __future__ import annotations

import base64
from datetime import datetime
from types import SimpleNamespace

import pytest
from psengine.playbook_alerts import PBA_DomainAbuse, PlaybookAlertRetrieveImageError
from psengine.playbook_alerts.models.pba_domain_abuse import Screenshot

from recorded_future_intelligence.core import RecordedFutureManager as manager_module
from recorded_future_intelligence.core.datamodels import PlaybookAlert
from recorded_future_intelligence.core.RecordedFutureDataModelTransformationLayer import (
    build_playbook_alert,
)
from recorded_future_intelligence.core.RecordedFutureManager import RecordedFutureManager
from recorded_future_intelligence.core.UtilsManager import detect_image_mime_type

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"padding"
JPEG_BYTES = b"\xff\xd8\xff" + b"padding"
ALERT_ID = "task:d6e5c2a1-0000-0000-0000-000000000001"


def make_screenshot(image_id: str, description: str = "A screenshot") -> Screenshot:
    """Builds a real psengine screenshot metadata model."""
    return Screenshot(
        description=description,
        image_id=image_id,
        created=datetime(2026, 9, 15, 9, 14, 22),  # noqa: DTZ001
    )


def make_alert(screenshots: list[Screenshot]) -> SimpleNamespace:
    """Builds the subset of a Domain Abuse alert that `fetch_screenshots` reads."""
    return SimpleNamespace(
        playbook_alert_id=ALERT_ID,
        category="domain_abuse",
        panel_evidence_summary=SimpleNamespace(screenshots=screenshots),
    )


def make_manager(fetch_one_image) -> RecordedFutureManager:
    """Builds a manager with no config or network, wired to a fake image fetch.

    `__init__` calls `Config.init` and constructs the psengine managers, none of
    which the screenshot path needs.
    """
    rf_manager = object.__new__(RecordedFutureManager)
    rf_manager.siemplify = SimpleNamespace(
        LOGGER=SimpleNamespace(info=lambda *a, **kw: None, error=lambda *a, **kw: None),
    )
    rf_manager.playbook_alerts = SimpleNamespace(fetch_one_image=fetch_one_image)
    return rf_manager


def make_playbook_alert(screenshots: dict | None = None) -> PlaybookAlert:
    """Builds a Domain Abuse `PlaybookAlert` data model."""
    return PlaybookAlert(
        raw_data={"playbook_alert_id": ALERT_ID},
        id_=ALERT_ID,
        alert_url=f"https://app.recordedfuture.com/portal/playbook-alerts/{ALERT_ID}",
        category="domain_abuse",
        label="Domain Abuse",
        start=datetime(2026, 9, 15, 9, 0, 0),  # noqa: DTZ001
        end=datetime(2026, 9, 15, 9, 30, 0),  # noqa: DTZ001
        title="Domain Abuse - evil-example.com",
        priority="High",
        screenshots=screenshots,
    )


@pytest.mark.parametrize(
    ("image_bytes", "expected"),
    [
        (PNG_BYTES, "image/png"),
        (JPEG_BYTES, "image/jpeg"),
        (b"GIF87a" + b"padding", "image/gif"),
        (b"GIF89a" + b"padding", "image/gif"),
        (b"RIFF" + b"\x00\x00\x00\x00" + b"WEBP" + b"padding", "image/webp"),
        # The endpoint discards its Content-Type, so an unrecognised payload has
        # to fall back to something a browser will attempt to decode.
        (b"not an image at all", "image/png"),
        (b"", "image/png"),
    ],
)
def test_detect_image_mime_type(image_bytes: bytes, expected: str) -> None:
    assert detect_image_mime_type(image_bytes) == expected


def test_fetch_screenshots_encodes_metadata_and_bytes() -> None:
    screenshot = make_screenshot("img:0001", description="Spoofed login page")
    rf_manager = make_manager(lambda **kwargs: PNG_BYTES)

    result = rf_manager.fetch_screenshots(make_alert([screenshot]))

    assert result == {
        "img:0001": {
            "description": "Spoofed login page",
            "created": "09/15/2026 09:14:22",
            "mime_type": "image/png",
            "image_b64": base64.b64encode(PNG_BYTES).decode(),
        },
    }


def test_fetch_screenshots_requests_each_image_for_its_alert() -> None:
    calls = []

    def fetch_one_image(**kwargs):
        calls.append(kwargs)
        return PNG_BYTES

    rf_manager = make_manager(fetch_one_image)
    rf_manager.fetch_screenshots(make_alert([make_screenshot("img:0001")]))

    assert calls == [
        {
            "alert_id": ALERT_ID,
            "image_id": "img:0001",
            "alert_category": "domain_abuse",
        },
    ]


def test_fetch_screenshots_survives_a_failed_image() -> None:
    """One unavailable image must not cost the other images or the refresh.

    psengine's own `fetch_images` wraps the whole loop in a single error
    handler, so this is the behaviour that motivates fetching one at a time.
    """

    def fetch_one_image(*, image_id, **kwargs):
        if image_id == "img:0001":
            raise PlaybookAlertRetrieveImageError("boom")
        return PNG_BYTES

    rf_manager = make_manager(fetch_one_image)
    alert = make_alert([make_screenshot("img:0001"), make_screenshot("img:0002")])

    result = rf_manager.fetch_screenshots(alert)

    assert list(result) == ["img:0002"]


def test_fetch_screenshots_enforces_the_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """An oversized image is dropped, and a later one that fits still lands.

    Exceeding the platform's `max_json_result_size` fails the action outright
    and the case keeps stale data, so the budget skips rather than breaks.
    """
    small = PNG_BYTES
    large = PNG_BYTES + b"x" * 512
    budget = len(base64.b64encode(small).decode())
    monkeypatch.setattr(manager_module, "SCREENSHOT_B64_BUDGET", budget)

    def fetch_one_image(*, image_id, **kwargs):
        return large if image_id == "img:0001" else small

    rf_manager = make_manager(fetch_one_image)
    alert = make_alert([make_screenshot("img:0001"), make_screenshot("img:0002")])

    result = rf_manager.fetch_screenshots(alert)

    assert list(result) == ["img:0002"]


def test_fetch_screenshots_with_no_screenshots() -> None:
    rf_manager = make_manager(lambda **kwargs: PNG_BYTES)

    assert rf_manager.fetch_screenshots(make_alert([])) == {}
    assert rf_manager.fetch_screenshots(make_alert(None)) == {}


def test_screenshots_html_renders_an_inline_data_uri() -> None:
    image_b64 = base64.b64encode(PNG_BYTES).decode()
    alert = make_playbook_alert(
        {
            "img:0001": {
                "description": "Spoofed login page",
                "created": "09/15/2026 09:14:22",
                "mime_type": "image/png",
                "image_b64": image_b64,
            },
        },
    )

    event = alert.create_events_with_html()

    assert f'src="data:image/png;base64,{image_b64}"' in event["screenshots_html"]
    assert 'data-image-id="img:0001"' in event["screenshots_html"]
    assert "Spoofed login page" in event["screenshots_html"]
    assert "09/15/2026 09:14:22" in event["screenshots_html"]


def test_screenshots_html_escapes_the_description() -> None:
    """Descriptions are attacker-influenced text landing in an unsafe-rendered widget."""
    alert = make_playbook_alert(
        {
            "img:0001": {
                "description": '<script>alert("xss")</script>',
                "created": "09/15/2026 09:14:22",
                "mime_type": "image/png",
                "image_b64": base64.b64encode(PNG_BYTES).decode(),
            },
        },
    )

    screenshots_html = alert.create_events_with_html()["screenshots_html"]

    assert "<script>" not in screenshots_html
    assert "&lt;script&gt;" in screenshots_html


def test_screenshots_html_skips_incomplete_entries() -> None:
    alert = make_playbook_alert({"img:0001": {"description": "No bytes"}})

    assert alert.create_events_with_html()["screenshots_html"] == ""


def test_screenshots_html_is_empty_when_disabled() -> None:
    """With the parameter off the chunk is present but empty, so the panel hides."""
    event = make_playbook_alert().create_events_with_html()

    assert event["screenshots_html"] == ""


def test_other_categories_have_no_screenshots_chunk() -> None:
    alert = make_playbook_alert()
    alert.category = "cyber_vulnerability"

    assert "screenshots_html" not in alert.create_events_with_html()


def make_psengine_alert() -> PBA_DomainAbuse:
    """Builds a real psengine Domain Abuse alert with one screenshot."""
    return PBA_DomainAbuse.model_validate(
        {
            "playbook_alert_id": ALERT_ID,
            "panel_status": {
                "status": "New",
                "priority": "High",
                "created": "2026-09-15T09:00:00.000Z",
                "updated": "2026-09-15T09:30:00.000Z",
                "case_rule_id": "rule:0001",
                "case_rule_label": "Domain Abuse",
                "alert_rule": {"id": "rule:0001", "label": "Domain Abuse"},
                "entity_id": "idn:evil-example.com",
                "entity_name": "evil-example.com",
                "actions_taken": [],
                "targets": ["idn:example.com"],
            },
            "panel_evidence_summary": {
                "screenshots": [
                    {
                        "description": "Spoofed login page",
                        "image_id": "img:0001",
                        "created": "2026-09-15T09:14:22.000Z",
                    },
                ],
            },
        },
    )


def test_build_playbook_alert_carries_screenshots_past_dump_model() -> None:
    """The bytes have to be threaded in separately or they vanish here.

    `dump_model` calls `model_dump`, which never emits psengine's private
    `_images` attribute. This is the step where enabling the psengine
    `fetch_images` flag on its own silently produces nothing.
    """
    image_b64 = base64.b64encode(PNG_BYTES).decode()
    screenshots = {
        "img:0001": {
            "description": "Spoofed login page",
            "created": "09/15/2026 09:14:22",
            "mime_type": "image/png",
            "image_b64": image_b64,
        },
    }

    alert = build_playbook_alert(make_psengine_alert(), screenshots=screenshots)
    event = alert.create_events_with_html()

    # Metadata survives the dump; the bytes only arrive via the separate path.
    assert event["panel_evidence_summary"]["screenshots"][0]["image_id"] == "img:0001"
    assert "images" not in event
    assert f'src="data:image/png;base64,{image_b64}"' in event["screenshots_html"]


def test_build_playbook_alert_without_screenshots() -> None:
    event = build_playbook_alert(make_psengine_alert()).create_events_with_html()

    assert event["screenshots_html"] == ""
