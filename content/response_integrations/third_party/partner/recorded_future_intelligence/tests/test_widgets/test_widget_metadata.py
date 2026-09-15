############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Validates the metadata of every predefined widget.

A widget binds to an action by its display name, and nothing at runtime reports
a binding that failed: a typo in `action_identifier` simply means the widget
never appears in the case or alert view. These tests catch that, and the schema
mistakes that would otherwise only surface when `mp build` runs in CI.
"""

from __future__ import annotations

import pytest
from tests.test_widgets.common import (
    DATA_MODELS,
    JSON_RESULT_PLACEHOLDER,
    WIDGET_NAMES,
    WIDGETS_DIR,
    action_metadata,
    widget_data_model,
    widget_html,
    widget_yaml,
)

# Mirrors mp.core.data_models.common.widget.data and .../integrations/action_widget.
VALID_TYPES = {"html"}
VALID_SCOPES = {"alert", "case"}
VALID_DEFINITION_SCOPES = {"alert", "case", "both"}
VALID_SIZES = {"half_width", "full_width", "third_width", "two_thirds_width"}
VALID_MATCH_TYPES = {
    "equal",
    "contains",
    "starts_with",
    "greater_than",
    "less_than",
    "not_equal",
    "not_contains",
    "is_empty",
    "is_not_empty",
}

REQUIRED_KEYS = {
    "title",
    "type",
    "scope",
    "action_identifier",
    "description",
    "data_definition",
    "condition_group",
    "default_size",
}

# mp.core.constants.DISPLAY_NAME_MAX_LENGTH / LONG_DESCRIPTION_MAX_LENGTH.
DISPLAY_NAME_MAX_LENGTH = 150
LONG_DESCRIPTION_MAX_LENGTH = 2050

TITLE_PREFIX = "Recorded Future - "


def test_widgets_are_discovered() -> None:
    """Guard against the glob silently matching nothing."""
    assert WIDGET_NAMES


@pytest.mark.parametrize("name", WIDGET_NAMES)
def test_widget_has_matching_html(name: str) -> None:
    """Each widget has an HTML sibling.

    `mp` rejects an unpaired file at build time; failing here surfaces it
    locally instead.
    """
    assert (WIDGETS_DIR / f"{name}.html").is_file()


@pytest.mark.parametrize("path", sorted(WIDGETS_DIR.glob("*.html")), ids=lambda p: p.stem)
def test_widget_html_has_matching_yaml(path) -> None:  # noqa: ANN001
    """Each widget HTML file has a metadata sibling."""
    assert path.with_suffix(".yaml").is_file()


@pytest.mark.parametrize("name", WIDGET_NAMES)
def test_widget_metadata_keys(name: str) -> None:
    """Metadata carries exactly the keys the build expects."""
    assert set(widget_yaml(name)) == REQUIRED_KEYS


@pytest.mark.parametrize("name", WIDGET_NAMES)
def test_widget_enum_values_are_buildable(name: str) -> None:
    """Every enum-backed field uses a value `mp` can map to its built form."""
    meta = widget_yaml(name)
    data_definition = meta["data_definition"]

    assert meta["type"] in VALID_TYPES
    assert meta["scope"] in VALID_SCOPES
    assert meta["default_size"] in VALID_SIZES
    assert data_definition["type"] in VALID_TYPES
    assert data_definition["widget_definition_scope"] in VALID_DEFINITION_SCOPES
    assert isinstance(data_definition["html_height"], int)
    assert isinstance(data_definition["safe_rendering"], bool)


@pytest.mark.parametrize("name", WIDGET_NAMES)
def test_widget_is_available_on_case_and_alert_views(name: str) -> None:
    """Widgets are placeable on both view types.

    `widget_definition_scope: both` is what lets a team build either a case or
    an alert view from this data, which is the point of shipping them.
    """
    assert widget_yaml(name)["data_definition"]["widget_definition_scope"] == "both"


@pytest.mark.parametrize("name", WIDGET_NAMES)
def test_widget_condition_group(name: str) -> None:
    """The render conditions are well formed."""
    condition_group = widget_yaml(name)["condition_group"]
    assert condition_group["logical_operator"] in {"and", "or"}

    conditions = condition_group["conditions"]
    assert conditions, "a widget with no conditions renders unconditionally"
    for condition in conditions:
        assert set(condition) == {
            "field_name",
            "value",
            "match_type",
            "custom_operator_name",
        }
        assert condition["match_type"] in VALID_MATCH_TYPES
        assert condition["field_name"].startswith("[{stepInstanceName}.JsonResult")


@pytest.mark.parametrize("name", WIDGET_NAMES)
def test_widget_binds_to_an_existing_action(name: str) -> None:
    """`action_identifier` matches an action's display name.

    This is the failure that is invisible at runtime: an identifier that matches
    nothing yields a widget that never renders, with no error logged anywhere.
    """
    identifier = widget_yaml(name)["action_identifier"]
    known_actions = action_metadata()
    assert identifier in known_actions, (
        f"{name}.yaml binds to unknown action {identifier!r}; "
        f"known actions: {sorted(known_actions)}"
    )


@pytest.mark.parametrize("name", WIDGET_NAMES)
def test_widget_title_and_description(name: str) -> None:
    """Titles are branded consistently and stay inside the length limits."""
    meta = widget_yaml(name)
    title = meta["title"]

    assert title.startswith(TITLE_PREFIX), f"{name}.yaml title must start with {TITLE_PREFIX!r}"
    assert title == f"{TITLE_PREFIX}{meta['action_identifier']}"
    assert len(title) <= DISPLAY_NAME_MAX_LENGTH
    assert len(meta["description"]) <= LONG_DESCRIPTION_MAX_LENGTH
    assert len(meta["action_identifier"]) <= DISPLAY_NAME_MAX_LENGTH


@pytest.mark.parametrize("name", WIDGET_NAMES)
def test_widget_html_declares_the_json_placeholder_once(name: str) -> None:
    """The payload placeholder appears exactly once.

    Google SecOps substitutes it with the action's JSON result. Zero occurrences
    means the widget renders no data; more than one means the payload is
    inlined repeatedly, which bloats the view and breaks the script.
    """
    assert widget_html(name).count(JSON_RESULT_PLACEHOLDER) == 1


@pytest.mark.parametrize("name", WIDGET_NAMES)
def test_widget_html_structure(name: str) -> None:
    """The HTML is a complete document built from the tracked template."""
    html = widget_html(name)

    assert "<!DOCTYPE html>" in html
    assert html.rstrip().endswith("</html>")
    assert "Apache License" in html, "missing licence header"
    # Records which template revision this widget was based on, so a future
    # re-base can tell what it is upgrading from.
    assert "Widget created by Enrichment Template" in html


@pytest.mark.parametrize("name", WIDGET_NAMES)
def test_widget_declares_a_known_data_model(name: str) -> None:
    """Each widget declares which Recorded Future payload shape it renders.

    The declaration is what routes a widget to its data-contract test module. A
    widget that declares nothing, or declares a model no module tests, would be
    built and shipped with its payload assumptions unchecked.
    """
    model = widget_data_model(name)
    assert model, (
        f"{name}.html declares no data model, or declares one more than once. "
        f"Add a single `<!-- Recorded Future data model: ... -->` comment; "
        f"without it, nothing checks the payload assumptions the script makes."
    )
    assert model in DATA_MODELS, (
        f"{name}.html declares unknown data model {model!r}; "
        f"known models: {list(DATA_MODELS)}. Add a data-contract test module "
        f"for a new model rather than widening this list alone."
    )


def test_every_data_model_has_a_widget() -> None:
    """No data model is left declared but unused.

    A model in `DATA_MODELS` that no widget declares means its test module
    silently tests nothing, which reads as coverage it does not have.
    """
    declared = {widget_data_model(name) for name in WIDGET_NAMES if (WIDGETS_DIR / f"{name}.html").is_file()}
    unused = sorted(set(DATA_MODELS) - declared)
    assert not unused, f"data models with no widget: {unused}"
