############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Pins the JSON contract the enrichment widgets render.

The widget scripts read specific paths out of an action's JSON result. Nothing
connects the two at build time, so if an action's payload shape drifts the
widget does not error -- it renders an empty panel, and the first person to
notice is an analyst looking at a blank case view. These tests assert the shape
the scripts depend on against the committed `resources/*_JsonResult_example.json`
files, so the drift fails in CI instead.
"""

from __future__ import annotations

import pytest
from tests.test_widgets.common import (
    action_metadata,
    json_result_example,
    widget_allowlist,
    widget_yaml,
    widgets_for_model,
)

# Keys `buildDisplayModel` promotes into the summary block rather than the
# generic detail list, so they are intentionally absent from `allowlistedFields`.
SUMMARY_FIELDS = ("risk", "timestamps", "intelCard")

# Recorded Future's shared 0-4 criticality scale, which indexes CRITICALITY_BANDS
# in the widget script.
MAX_CRITICALITY = 4
MAX_RISK_SCORE = 99

# Widgets rendering the single-entity enrichment payload, taken from the data
# model each one declares. Routed by declaration rather than detected from the
# script, so that a widget for a differently shaped action -- a sandbox report,
# say -- cannot silently inherit assertions that do not apply to it.
ENRICHMENT_WIDGETS = widgets_for_model("enrichment")


def _entity_results(name: str) -> list:
    """Return the example payload for the action a widget is bound to.

    Returns:
        The decoded top-level list from the action's JSON result example.

    """
    identifier = widget_yaml(name)["action_identifier"]
    example = json_result_example(action_metadata()[identifier])
    assert example is not None, f"action {identifier!r} declares no JsonResult example"
    return example


def test_enrichment_widgets_are_discovered() -> None:
    """Guard against the data-model routing matching nothing."""
    assert ENRICHMENT_WIDGETS


@pytest.mark.parametrize("name", ENRICHMENT_WIDGETS)
def test_payload_is_a_list_of_entity_results(name: str) -> None:
    """The payload is the per-entity list the widget iterates."""
    example = _entity_results(name)

    assert isinstance(example, list), "the widget calls .filter/.map on the payload"
    assert example, "an empty example cannot demonstrate the contract"
    for item in example:
        assert isinstance(item, dict)
        assert isinstance(item.get("Entity"), str)
        assert item["Entity"].strip(), "the widget skips entries with a blank Entity"
        assert "EntityResult" in item


@pytest.mark.parametrize("name", ENRICHMENT_WIDGETS)
def test_entity_result_is_a_single_element_list(name: str) -> None:
    """`EntityResult` wraps the report in a one-element list.

    `RFIndicator.to_json()` returns `(raw_data,)`, so the report arrives wrapped.
    `normalizeEntityResult` unwraps it; left wrapped, every field would render
    prefixed with its array index ("0 Risk Score") and the field allowlist would
    match nothing, producing an empty widget.

    `normalizeEntityResult` also accepts a bare object, so changing this contract
    would not break the widgets -- but it would mean this assertion is stale, and
    the reader should know the unwrap is then dead code rather than load-bearing.
    """
    for item in _entity_results(name):
        entity_result = item["EntityResult"]
        assert isinstance(entity_result, list), (
            "expected the one-tuple wrapper from RFIndicator.to_json(); "
            "if the action now returns a bare object, the unwrap in "
            f"{name}.html is no longer load-bearing and this test should say so"
        )
        assert len(entity_result) == 1
        assert isinstance(entity_result[0], dict)


@pytest.mark.parametrize("name", ENRICHMENT_WIDGETS)
def test_allowlisted_fields_match_the_payload(name: str) -> None:
    """At least one allowlisted field is present in the bound action's payload.

    `filterKeys` silently drops a name that is not in the payload, so an
    allowlist of nothing but typos yields a widget with an empty detail list and
    no error anywhere.
    """
    allowlist = widget_allowlist(name)
    assert allowlist, "an empty allowlist renders every key, including noisy ones"

    report = _entity_results(name)[0]["EntityResult"][0]
    matched = [field for field in allowlist if field in report]
    assert matched, (
        f"none of {allowlist} exist in the {name} payload (keys: {sorted(report)}); the detail list would render empty"
    )


@pytest.mark.parametrize("name", ENRICHMENT_WIDGETS)
def test_allowlisted_fields_are_known_recorded_future_fields(name: str) -> None:
    """Every allowlisted field is a real field on some enrichment payload.

    Checked against the union across all enrichment examples rather than the
    widget's own, because `Enrich IOC` accepts five entity types and so has to
    allowlist fields that only appear for some of them (`location` for an IP,
    `hashAlgorithm` for a file hash). A genuine typo appears in no payload at
    all and still fails here.
    """
    known_fields: set[str] = set()
    for widget in ENRICHMENT_WIDGETS:
        known_fields.update(_entity_results(widget)[0]["EntityResult"][0])

    unknown = [field for field in widget_allowlist(name) if field not in known_fields]
    assert not unknown, (
        f"{name}.html allowlists {unknown}, which appear in no enrichment payload; known fields: {sorted(known_fields)}"
    )


@pytest.mark.parametrize("name", ENRICHMENT_WIDGETS)
def test_allowlist_excludes_summary_fields(name: str) -> None:
    """Summary fields stay out of the allowlist.

    `risk`, `timestamps` and `intelCard` are rendered by the summary block.
    Allowlisting them too would show the same values twice, which matters in a
    400px-high widget where vertical space is the binding constraint.
    """
    overlap = [field for field in widget_allowlist(name) if field in SUMMARY_FIELDS]
    assert not overlap, f"{name}.html allowlists summary-rendered fields {overlap}"


@pytest.mark.parametrize("name", ENRICHMENT_WIDGETS)
def test_summary_fields_are_present(name: str) -> None:
    """The payload carries what the summary block renders."""
    report = _entity_results(name)[0]["EntityResult"][0]

    for field in SUMMARY_FIELDS:
        assert field in report, f"summary block reads {field!r}, absent from the {name} payload"

    assert isinstance(report["intelCard"], str)
    assert report["intelCard"].startswith("https://"), "safeHttpUrl() only emits an href for an http(s) URL"
    assert set(report["timestamps"]) >= {"firstSeen", "lastSeen"}


@pytest.mark.parametrize("name", ENRICHMENT_WIDGETS)
def test_risk_block_drives_the_summary_badge(name: str) -> None:
    """`risk` carries the score, criticality and rule evidence the badge needs."""
    risk = _entity_results(name)[0]["EntityResult"][0]["risk"]

    assert isinstance(risk["score"], int)
    assert 0 <= risk["score"] <= MAX_RISK_SCORE

    # Indexes CRITICALITY_BANDS in the widget script; out of range would leave
    # the badge uncoloured.
    assert isinstance(risk["criticality"], int)
    assert 0 <= risk["criticality"] <= MAX_CRITICALITY

    # Preferred over the widget's fallback labels, because the vocabulary is
    # entity-type specific: vulnerabilities report High where IOCs report
    # Very Malicious over the same numeric scale.
    assert isinstance(risk["criticalityLabel"], str)
    assert risk["criticalityLabel"]

    assert isinstance(risk.get("riskSummary", ""), str)
    assert isinstance(risk["riskString"], str)


@pytest.mark.parametrize("name", ENRICHMENT_WIDGETS)
def test_risk_rules_table_columns(name: str) -> None:
    """`risk.evidenceDetails` carries the fields the Risk Rules table maps.

    A renamed key here would not break the render, it would quietly produce a
    table column full of "N/A".
    """
    evidence = _entity_results(name)[0]["EntityResult"][0]["risk"]["evidenceDetails"]

    assert isinstance(evidence, list)
    assert evidence, "no triggered rules means the Risk Rules table never renders"
    for rule in evidence:
        assert set(rule) >= {
            "rule",
            "criticalityLabel",
            "evidenceString",
            "mitigationString",
            "timestamp",
        }


@pytest.mark.parametrize("name", ENRICHMENT_WIDGETS)
def test_links_are_categorised_arrays(name: str) -> None:
    """`links` maps a category name to a list of related entities.

    `buildDisplayModel` lifts each category to its own table, so a shape change
    here (a list instead of a mapping, say) would drop the tables silently.
    Populated only when the action runs with "Include Links" enabled, so an
    empty mapping is valid.
    """
    links = _entity_results(name)[0]["EntityResult"][0].get("links", {})

    assert isinstance(links, dict)
    for category, entries in links.items():
        assert isinstance(category, str)
        assert isinstance(entries, list)
        for entry in entries:
            assert isinstance(entry, dict)
            assert set(entry) >= {"id", "name", "type"}
