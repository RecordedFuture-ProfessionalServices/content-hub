############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Pins the JSON contract the bulk enrichment widget renders.

`Enrich IOCs Bulk` reads Recorded Future's SOAR enrichment endpoint, whose risk
block is shaped differently to the one the single-entity enrichment actions
return: `risk.level` in place of `risk.criticality`, no `criticalityLabel` or
`riskSummary`, and the triggered rules keyed by rule id rather than listed. The
widget reshapes all of that, and none of the reshaping errors when the payload
drifts -- it renders an empty panel instead. These tests assert the shape against
the committed example so the drift fails in CI.
"""

from __future__ import annotations

import pytest
from tests.test_widgets.common import (
    action_metadata,
    json_result_example,
    widget_allowlist,
    widget_html,
    widget_string_constant,
    widget_yaml,
    widgets_for_model,
)

BULK_WIDGETS = widgets_for_model("bulk-enrichment")
ENRICHMENT_WIDGETS = widgets_for_model("enrichment")

# `risk` feeds the summary block and the two tables lifted out of it, so it is
# intentionally absent from `allowlistedFields`.
SUMMARY_FIELDS = ("risk",)

MAX_RISK_SCORE = 99

# The fields `buildDisplayModel` maps into each row of the Risk Rules table.
EVIDENCE_FIELDS = ("rule", "level", "description", "mitigation", "timestamp")

# Recorded Future's inline entity markup, as in
# `<e id=source:VKz42X>Insikt Group</e>`.
ENTITY_MARKUP = "<e id="


def _report(name: str) -> dict:
    """Return the first entity's report from the bound action's example payload.

    Returns:
        The decoded report object, unwrapped from its one-element list.

    """
    identifier = widget_yaml(name)["action_identifier"]
    example = json_result_example(action_metadata()[identifier])
    assert example is not None, f"action {identifier!r} declares no JsonResult example"
    return example[0]["EntityResult"][0]


def test_bulk_widgets_are_discovered() -> None:
    """Guard against the data-model routing matching nothing."""
    assert BULK_WIDGETS


@pytest.mark.parametrize("name", BULK_WIDGETS)
def test_payload_is_a_list_of_entity_results(name: str) -> None:
    """The payload is the per-entity list the widget iterates.

    Bulk enrichment is the one action where the sidebar earns its place, so the
    list shape matters more here than anywhere else.
    """
    identifier = widget_yaml(name)["action_identifier"]
    example = json_result_example(action_metadata()[identifier])

    assert isinstance(example, list), "the widget calls .filter/.map on the payload"
    assert example, "an empty example cannot demonstrate the contract"
    for item in example:
        assert isinstance(item, dict)
        assert isinstance(item.get("Entity"), str)
        assert item["Entity"].strip(), "the widget skips entries with a blank Entity"
        entity_result = item["EntityResult"]
        assert isinstance(entity_result, list), (
            "expected the one-tuple wrapper from RFIndicator.to_json(); "
            f"if the action now returns a bare object the unwrap in {name}.html "
            "is no longer load-bearing and this test should say so"
        )
        assert len(entity_result) == 1
        assert isinstance(entity_result[0], dict)


@pytest.mark.parametrize("name", BULK_WIDGETS)
def test_allowlisted_fields_match_the_payload(name: str) -> None:
    """Every allowlisted field exists in the payload.

    Unlike `Enrich IOC`, this action returns one shape for every entity type, so
    every allowlisted name has to be present -- there is no per-type field to
    excuse a miss, and `filterKeys` drops an unknown name silently.
    """
    allowlist = widget_allowlist(name)
    assert allowlist, "an empty allowlist renders every key, including noisy ones"

    report = _report(name)
    missing = [field for field in allowlist if field not in report]
    assert not missing, (
        f"{name}.html allowlists {missing}, absent from the payload "
        f"(keys: {sorted(report)}); those rows would render empty"
    )


@pytest.mark.parametrize("name", BULK_WIDGETS)
def test_allowlist_excludes_summary_fields(name: str) -> None:
    """`risk` stays out of the allowlist.

    It is rendered by the summary block and the two lifted tables. Allowlisting
    it too would show the same values twice and dump the whole nested block into
    a 400px-high panel.
    """
    overlap = [field for field in widget_allowlist(name) if field in SUMMARY_FIELDS]
    assert not overlap, f"{name}.html allowlists summary-rendered fields {overlap}"


@pytest.mark.parametrize("name", BULK_WIDGETS)
def test_risk_block_drives_the_summary_badge(name: str) -> None:
    """`risk.score` is present and in range, and `risk.rule` carries the counts."""
    risk = _report(name)["risk"]

    assert isinstance(risk["score"], int)
    assert 0 <= risk["score"] <= MAX_RISK_SCORE

    rule = risk["rule"]
    assert isinstance(rule, dict)
    # Assembled into "17 of 25 Risk Rules currently observed." by the widget,
    # because this payload carries no `riskSummary` sentence of its own.
    assert isinstance(rule["count"], int)
    assert isinstance(rule["maxCount"], int)
    assert isinstance(rule["mostCritical"], str)
    assert rule["mostCritical"]


@pytest.mark.parametrize("name", BULK_WIDGETS)
def test_risk_block_carries_no_criticality_label(name: str) -> None:
    """The payload states no criticality label.

    This is why the widget always derives the band from the score, where the
    single-entity enrichment widgets prefer the API's own `criticalityLabel`. If
    the endpoint starts returning one, the widget should prefer it too, and this
    test is the prompt to make that change.
    """
    risk = _report(name)["risk"]
    assert "criticalityLabel" not in risk, (
        "the SOAR payload now carries a criticality label; prefer it over the "
        "derived band in the widget, as the enrichment widgets do"
    )


@pytest.mark.parametrize("name", BULK_WIDGETS)
def test_evidence_is_keyed_by_rule_id(name: str) -> None:
    """`risk.rule.evidence` is a mapping, not the enrichment actions' array.

    The widget converts it with `Object.values`. Were it already an array, that
    call would still work, but the reshaping would be pointless -- and if it
    became an array of a different shape, the rules table would fill with "N/A".
    """
    evidence = _report(name)["risk"]["rule"]["evidence"]

    assert isinstance(evidence, dict), (
        "expected rules keyed by rule id; an array here means this payload now "
        "matches the enrichment actions' `risk.evidenceDetails` and the two "
        "widgets could share one display model"
    )
    assert evidence, "no triggered rules means the Risk Rules table never renders"
    for key, entry in evidence.items():
        assert isinstance(key, str)
        assert isinstance(entry, dict)
        missing = [field for field in EVIDENCE_FIELDS if field not in entry]
        assert not missing, f"rule {key!r} is missing {missing}, mapped by the rules table"


@pytest.mark.parametrize("name", BULK_WIDGETS)
def test_risk_context_is_keyed_by_source(name: str) -> None:
    """`risk.context` breaks the score down by contributing source.

    Lifted into its own table, with the category name as a column, so a shape
    change here drops that table silently.
    """
    context = _report(name)["risk"]["context"]

    assert isinstance(context, dict)
    assert context
    for category, entry in context.items():
        assert isinstance(category, str)
        assert isinstance(entry, dict)
        assert isinstance(entry["score"], int)
        assert isinstance(entry["rule"], dict)


@pytest.mark.parametrize("name", BULK_WIDGETS)
def test_evidence_descriptions_carry_entity_markup(name: str) -> None:
    """The rule descriptions contain the markup `stripEntityMarkup` removes.

    Every value in the widget reaches the DOM through `textContent`, so left in
    place the tags would be shown literally. If the API stops emitting them this
    test fails, which is the signal that the strip has become dead code rather
    than a silent no-op nobody can account for.
    """
    evidence = _report(name)["risk"]["rule"]["evidence"]
    descriptions = [
        entry["description"] for entry in evidence.values() if isinstance(entry.get("description"), str)
    ]

    assert any(ENTITY_MARKUP in description for description in descriptions), (
        f"no rule description contains {ENTITY_MARKUP!r}; `stripEntityMarkup` in "
        f"{name}.html may no longer be needed"
    )
    assert "stripEntityMarkup" in widget_html(name), (
        f"{name}.html renders descriptions containing {ENTITY_MARKUP!r} without "
        "stripping the markup"
    )


@pytest.mark.parametrize("name", BULK_WIDGETS)
def test_entity_id_is_present_for_the_intel_card_link(name: str) -> None:
    """`entity.id` is what the Intelligence Card link is derived from.

    Without it the widget renders no link at all, which is the one pivot a bulk
    result most needs.
    """
    entity = _report(name)["entity"]

    assert isinstance(entity, dict)
    assert isinstance(entity["id"], str)
    assert entity["id"].strip()


@pytest.mark.parametrize("name", BULK_WIDGETS)
def test_derived_intel_card_url_matches_the_api_form(name: str) -> None:
    """The derived Intelligence Card URL matches the one the API itself returns.

    This payload carries no `intelCard`, so the widget builds the URL from
    `entity.id`. The form is not invented: it is taken from the single-entity
    enrichment actions, which do return one. Asserting their `intelCard` still
    starts with the prefix this widget prepends is what stops the derivation
    going stale unnoticed if Recorded Future ever changes the portal URL.
    """
    prefix = widget_string_constant(name, "INTEL_CARD_PREFIX")
    assert ENRICHMENT_WIDGETS, "nothing to compare the derived URL against"

    for widget in ENRICHMENT_WIDGETS:
        intel_card = _report(widget)["intelCard"]
        assert intel_card.startswith(prefix), (
            f"{widget} returns {intel_card!r}, which does not start with the "
            f"prefix {prefix!r} that {name}.html prepends to `entity.id`"
        )
