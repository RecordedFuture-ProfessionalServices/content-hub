############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Pins the JSON contract the two kinds of sandbox widget render.

`Detonate File` and `Detonate URL` return a Recorded Future Sandbox detonation
report; `Search Hash Malware Intelligence` returns a sandbox report for a hash
already analysed. Both score 0-10 rather than 0-99 and state no verdict label,
and the detonation payload is a single object where every other action in this
integration returns a list. None of that errors when it drifts -- the widget
renders an empty panel -- so it is asserted here against the committed examples.
"""

from __future__ import annotations

import pytest
from tests.test_widgets.common import (
    INTEGRATION_ROOT,
    action_metadata,
    json_result_example,
    widget_allowlist,
    widget_object_constant_keys,
    widget_string_constant,
    widget_yaml,
    widgets_for_model,
)

DETONATION_WIDGETS = widgets_for_model("sandbox-detonation")
HASH_REPORT_WIDGETS = widgets_for_model("sandbox-hash-report")
SANDBOX_WIDGETS = DETONATION_WIDGETS + HASH_REPORT_WIDGETS

# The sandbox scores 0-10, which `bandFromSandboxScore` maps onto the five band
# colours. A score outside the range would leave the badge uncoloured.
MAX_SANDBOX_SCORE = 10

# Where the integration already writes a sandbox report link for the case wall.
# The widgets derive the same URL, and should not disagree with it.
CASE_WALL_SOURCE = INTEGRATION_ROOT / "core" / "RecordedFutureCommon.py"


def _example(name: str):  # noqa: ANN202
    """Return the decoded example payload for the action a widget is bound to.

    Returns:
        The decoded JSON result example, whatever its top-level shape.

    """
    identifier = widget_yaml(name)["action_identifier"]
    example = json_result_example(action_metadata()[identifier])
    assert example is not None, f"action {identifier!r} declares no JsonResult example"
    return example


def _detonation_report(name: str) -> dict:
    """Return the report from a detonation payload.

    Returns:
        The decoded sandbox detonation report.

    """
    return _example(name)["EntityResult"]


def _hash_report(name: str) -> dict:
    """Return the first report from a hash search payload.

    Returns:
        The decoded sandbox report, unwrapped from its one-element list.

    """
    return _example(name)[0]["EntityResult"][0]


def test_sandbox_widgets_are_discovered() -> None:
    """Guard against the data-model routing matching nothing."""
    assert DETONATION_WIDGETS
    assert HASH_REPORT_WIDGETS


@pytest.mark.parametrize("name", DETONATION_WIDGETS)
def test_detonation_payload_is_a_single_object(name: str) -> None:
    """A detonation returns one object, not the per-entity list.

    This is why the widget wraps the payload before the template's render path:
    the template calls `.filter()` on it, which would throw on a bare object.
    Were this ever changed to a list, the wrap becomes a pass-through and this
    test is what says so.
    """
    example = _example(name)

    assert isinstance(example, dict), (
        "expected a single detonation object; a list here means the wrap in "
        f"{name}.html is now a pass-through and this test should say so"
    )
    assert isinstance(example.get("Entity"), str)
    assert example["Entity"].strip(), "the widget skips entries with a blank Entity"
    assert isinstance(example["EntityResult"], dict), (
        "a detonation report is not wrapped in the one-tuple the enrichment "
        "actions use; `normalizeEntityResult` accepts both"
    )


@pytest.mark.parametrize("name", HASH_REPORT_WIDGETS)
def test_hash_payload_is_a_list_of_entity_results(name: str) -> None:
    """A hash search returns the per-entity list, one report per hash."""
    example = _example(name)

    assert isinstance(example, list), "the widget calls .filter/.map on the payload"
    assert example, "an empty example cannot demonstrate the contract"
    for item in example:
        assert isinstance(item, dict)
        assert isinstance(item.get("Entity"), str)
        assert item["Entity"].strip()
        entity_result = item["EntityResult"]
        assert isinstance(entity_result, list), (
            "expected the one-tuple wrapper from `to_json()`; if the action now "
            f"returns a bare object the unwrap in {name}.html is no longer "
            "load-bearing and this test should say so"
        )
        assert len(entity_result) == 1
        assert isinstance(entity_result[0], dict)


@pytest.mark.parametrize("name", DETONATION_WIDGETS)
def test_detonation_allowlist_matches_the_payload(name: str) -> None:
    """The allowlisted fields exist, so the sandbox build rows are not blank."""
    allowlist = widget_allowlist(name)
    assert allowlist, "an empty allowlist makes `filterKeys` return every key"

    report = _detonation_report(name)
    missing = [field for field in allowlist if field not in report]
    assert not missing, f"{name}.html allowlists {missing}, absent from the payload"


@pytest.mark.parametrize("name", HASH_REPORT_WIDGETS)
def test_hash_allowlist_matches_the_payload(name: str) -> None:
    """The allowlisted fields exist, so the detail list is not empty."""
    allowlist = widget_allowlist(name)
    assert allowlist, "an empty allowlist makes `filterKeys` return every key"

    report = _hash_report(name)
    missing = [field for field in allowlist if field not in report]
    assert not missing, (
        f"{name}.html allowlists {missing}, absent from the payload "
        f"(keys: {sorted(report)}); those sections would render empty"
    )


@pytest.mark.parametrize("name", HASH_REPORT_WIDGETS)
def test_hash_allowlist_excludes_projected_fields(name: str) -> None:
    """`sample` and `dynamic` stay out of the allowlist.

    `sample` feeds the summary block. `dynamic` is projected into tables because
    its `network.http` entries carry full headers and multi-kilobyte URLs;
    allowlisting it would flatten all of that into the panel.
    """
    overlap = [field for field in widget_allowlist(name) if field in {"sample", "dynamic"}]
    assert not overlap, f"{name}.html allowlists projected fields {overlap}"


@pytest.mark.parametrize("name", DETONATION_WIDGETS)
def test_detonation_score_drives_the_summary_badge(name: str) -> None:
    """`analysis.score` is the verdict, and `sample` carries the analysis window."""
    report = _detonation_report(name)

    analysis = report["analysis"]
    assert isinstance(analysis["score"], int)
    assert 0 <= analysis["score"] <= MAX_SANDBOX_SCORE
    assert isinstance(analysis.get("tags", []), list)

    sample = report["sample"]
    # `sample.id` is what the report link is derived from; without it the widget
    # renders no link.
    assert isinstance(sample["id"], str)
    assert sample["id"].strip()
    assert isinstance(sample["target"], str)
    for field in ("created", "completed"):
        assert isinstance(sample[field], str)
        assert sample[field], f"summary renders `sample.{field}`"


@pytest.mark.parametrize("name", HASH_REPORT_WIDGETS)
def test_hash_score_drives_the_summary_badge(name: str) -> None:
    """`sample.score` is the verdict for a hash report."""
    sample = _hash_report(name)["sample"]

    assert isinstance(sample["score"], int)
    assert 0 <= sample["score"] <= MAX_SANDBOX_SCORE
    assert isinstance(sample["id"], str)
    assert sample["id"].strip()
    assert isinstance(sample["completed"], str)
    assert isinstance(sample.get("tags", []), list)


@pytest.mark.parametrize("name", SANDBOX_WIDGETS)
def test_sandbox_payload_states_no_verdict_label(name: str) -> None:
    """The payload scores but does not name a verdict.

    This is why `SANDBOX_BANDS` and its thresholds are the widget's own reading
    of the score rather than an API value, as the comment on them says. If the
    sandbox starts returning a verdict, prefer it, and this test is the prompt.
    """
    report = _detonation_report(name) if name in DETONATION_WIDGETS else _hash_report(name)
    containers = [report, report.get("sample") or {}, report.get("analysis") or {}]

    for container in containers:
        for field in ("verdict", "criticalityLabel", "scoreLabel"):
            assert field not in container, (
                f"the sandbox payload now names a verdict ({field!r}); prefer it "
                f"over the derived band in {name}.html"
            )


@pytest.mark.parametrize("name", DETONATION_WIDGETS)
def test_detonation_tasks_and_signatures(name: str) -> None:
    """The tasks and signatures tables have the fields they map.

    A renamed key here would not break the render: it would quietly produce a
    table column full of "N/A".
    """
    report = _detonation_report(name)

    tasks = report["tasks"]
    assert isinstance(tasks, list)
    assert tasks, "no tasks means the Tasks table never renders"
    for task in tasks:
        assert set(task) >= {"name", "kind", "status"}

    signatures = report["signatures"]
    assert isinstance(signatures, list)
    assert signatures, "no signatures means the Signatures table never renders"
    # `score` and `desc` are optional per signature -- the example carries
    # signatures without either -- so the widget sorts on a default. At least one
    # has to carry a score for the sort to mean anything.
    assert all("name" in signature for signature in signatures)
    assert any(isinstance(signature.get("score"), int) for signature in signatures)


@pytest.mark.parametrize("name", DETONATION_WIDGETS)
def test_detonation_iocs_are_lists_of_strings_per_kind(name: str) -> None:
    """`targets[].iocs` maps a kind to a list of bare strings.

    A list of strings gives the table renderer no columns, which is why the
    widget pivots them into typed rows. A mapping of objects here would mean that
    pivot drops them.
    """
    targets = _detonation_report(name)["targets"]

    assert isinstance(targets, list)
    assert targets, "no targets means the Indicators table never renders"
    for target in targets:
        assert set(target) >= {"target", "score"}
        iocs = target.get("iocs", {})
        assert isinstance(iocs, dict)
        for kind, values in iocs.items():
            assert isinstance(kind, str)
            assert isinstance(values, list)
            for value in values:
                assert isinstance(value, str), f"`iocs.{kind}` holds a non-string"


@pytest.mark.parametrize("name", DETONATION_WIDGETS)
def test_every_ioc_kind_has_a_display_label(name: str) -> None:
    """Every `iocs` kind in the payload is named in `IOC_TYPE_LABELS`.

    The fallback is the template's title casing, which renders `ips` as "Ips".
    That is legible but sloppy, and this is the test that notices a newly
    returned kind before an analyst does.
    """
    labelled = set(widget_object_constant_keys(name, "IOC_TYPE_LABELS"))

    kinds = set()
    for target in _detonation_report(name)["targets"]:
        kinds.update(target.get("iocs", {}))

    unlabelled = sorted(kinds - labelled)
    assert not unlabelled, (
        f"{name}.html has no display label for IOC kinds {unlabelled}; "
        f"they would render through the generic title casing"
    )


@pytest.mark.parametrize("name", HASH_REPORT_WIDGETS)
def test_hash_report_malware_config(name: str) -> None:
    """`dynamic.extracted[].config` names the family the summary headlines."""
    extracted = _hash_report(name)["dynamic"]["extracted"]

    assert isinstance(extracted, list)
    assert extracted, "no extracted config means the summary names no family"
    for entry in extracted:
        config = entry["config"]
        assert isinstance(config, dict)
        assert isinstance(config["family"], str)
        assert config["family"]
        assert isinstance(config["rule"], str)
        assert isinstance(config["c2"], list)


@pytest.mark.parametrize("name", HASH_REPORT_WIDGETS)
def test_hash_report_network_observations(name: str) -> None:
    """The network tables have the fields they map out of `dynamic.network`."""
    network = _hash_report(name)["dynamic"]["network"]

    assert isinstance(network, dict)

    for entry in network["dns"]:
        assert set(entry) >= {"request_domain", "request_type", "response_value"}
    for entry in network["ips"]:
        assert set(entry) >= {"ip", "asn", "cc"}
    for entry in network["flows"]:
        assert set(entry) >= {"proto", "dst_ip", "dst_port"}

    # `network.http` is projected down to the request line, so only `url` and
    # `method` are load-bearing; the rest of the exchange is deliberately dropped.
    for exchange in network.get("http", []):
        for step in exchange["sequence"]:
            assert isinstance(step["request"]["url"], str)


@pytest.mark.parametrize("name", HASH_REPORT_WIDGETS)
def test_counts_disagree_with_the_arrays_they_count(name: str) -> None:
    """The payload's own `*_count` fields do not match the arrays beside them.

    The widget counts the rows it renders instead. This test records why: in the
    committed example `dns_count` is lower than the number of DNS entries and
    `ips_count` is higher than the number of addresses, so a headline built from
    them would contradict the table directly below it. If the counts ever become
    reliable this test fails, and the widget could use them to report totals
    beyond what the payload carries.
    """
    dynamic = _hash_report(name)["dynamic"]
    network = dynamic["network"]

    pairs = [
        ("network.dns_count", network.get("dns_count"), len(network.get("dns", []))),
        ("network.ips_count", network.get("ips_count"), len(network.get("ips", []))),
        (
            "dynamic.signatures_count",
            dynamic.get("signatures_count"),
            len(dynamic.get("signatures", [])),
        ),
    ]
    mismatched = [name_ for name_, count, length in pairs if count != length]
    assert mismatched, (
        "every `*_count` now matches the array beside it; the summary could "
        "report the sandbox's totals rather than only the rows it renders"
    )


@pytest.mark.parametrize("name", SANDBOX_WIDGETS)
def test_report_link_agrees_with_the_case_wall(name: str) -> None:
    """The widget's sandbox report URL matches the one written to the case wall.

    The integration already writes `https://sandbox.recordedfuture.com/<id>` into
    the case wall for these actions. A widget that links somewhere else while
    sitting next to that text is worse than one that does not link at all.
    """
    prefix = widget_string_constant(name, "SANDBOX_REPORT_PREFIX")
    case_wall = CASE_WALL_SOURCE.read_text(encoding="utf-8")

    assert prefix in case_wall, (
        f"{name}.html links to {prefix!r}, which {CASE_WALL_SOURCE.name} does not "
        f"use; the widget and the case wall would disagree"
    )
