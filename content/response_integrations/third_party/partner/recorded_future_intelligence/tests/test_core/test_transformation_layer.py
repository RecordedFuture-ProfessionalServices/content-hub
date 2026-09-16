############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the layer that turns psengine models into Google SecOps objects.

This is the seam between the two data shapes, so a field renamed on either
side surfaces here first - as a missing enrichment field on an entity rather
than as an error.
"""

from __future__ import annotations

import pytest
from psengine.enrich import EnrichmentData, SOAREnrichedEntity, SOAREnrichOut
from psengine.enrich.constants import IOC_TO_MODEL

from recorded_future_intelligence.core.constants import CLASSIC_ALERT_ENTITY_MAPPING
from recorded_future_intelligence.core.datamodels import CVE, HASH, HOST, IP, URL
from recorded_future_intelligence.core.RecordedFutureDataModelTransformationLayer import (
    _extract_triggered_by,
    build_links,
    build_siemplify_object,
    build_siemplify_soar_object,
    dump_model,
    format_triggered_by,
)
from recorded_future_intelligence.tests.common import make_enrichment_record, make_evidence

LOCATION = {
    "organization": "Google LLC",
    "cidr": {"id": "ip:8.8.8.0/24", "name": "8.8.8.0/24", "type": "IpAddress"},
    "location": {"continent": "North America", "country": "United States", "city": "Mountain View"},
    "asn": "AS15169",
}


def enriched(entity: str, entity_type: str, **kwargs: object) -> EnrichmentData:
    """Build the psengine model the lookup manager returns.

    The content model has to be chosen explicitly; handing `EnrichmentData` a
    plain dict lets it coerce the record into the wrong entity model.
    """
    record = make_enrichment_record(entity, entity_type, **kwargs)
    return EnrichmentData(
        entity=entity,
        entity_type=entity_type,
        is_enriched=True,
        content=IOC_TO_MODEL[entity_type].model_validate(record),
    )


def soar_enriched(entity: str, entity_type: str, evidence: dict | None = None) -> SOAREnrichOut:
    """Build the psengine result the bulk SOAR endpoint returns."""
    rule = {"count": 2, "maxCount": 70, "mostCritical": "C&C Server", "summary": []}
    if evidence is not None:
        rule["evidence"] = evidence

    content = SOAREnrichedEntity.model_validate(
        {
            "entity": {"id": f"{entity_type}:{entity}", "name": entity, "type": entity_type},
            "risk": {"score": 85, "level": 4, "context": {}, "rule": rule},
        },
    )
    return SOAREnrichOut(entity=entity, is_enriched=True, content=content)


# ---------------------------------------------------------------------------
# dump_model
# ---------------------------------------------------------------------------


def test_dump_model_uses_the_api_field_names() -> None:
    """The raw data written to the case wall has to match the Recorded Future API."""
    dumped = dump_model(enriched("1.1.1.1", "ip").content)

    assert "intelCard" in dumped
    assert "intel_card" not in dumped


def test_dump_model_omits_fields_the_api_did_not_return() -> None:
    """An unset field would otherwise render as an empty row in the case wall."""
    assert "links" not in dump_model(enriched("1.1.1.1", "ip").content)


# ---------------------------------------------------------------------------
# build_links
# ---------------------------------------------------------------------------


def test_build_links_without_links() -> None:
    """Links are only requested when the action asks for them."""
    assert build_links(None) == {}


def make_section(name: str, entities: list[str]) -> dict:
    """Build one links section holding the given entity names."""
    return {
        "section_id": {"id": f"section:{name}", "name": name, "type": "Section"},
        "total_count": len(entities),
        "lists": [
            {
                "type": {"id": "type:1", "name": "Related", "type": "Type"},
                "total_count": len(entities),
                "entities": [{"id": f"entity:{e}", "name": e, "type": "Malware"} for e in entities],
            },
        ],
    }


def make_links(*sections: dict) -> dict:
    """Build the links payload the enrichment endpoint returns."""
    return {
        "hits": [
            {
                "sections": list(sections),
                "start_date": "2026-01-01T00:00:00.000Z",
                "stop_date": "2026-09-01T00:00:00.000Z",
                "total_count": 1,
                "sample_reference_ids": ["ref-1"],
                "counts": [],
                "event_count": 1,
            },
        ],
        "method_aggregates": [],
        "counts": [],
    }


def test_build_links_groups_entities_by_section() -> None:
    """The links table is keyed by section name across every list."""
    content = enriched(
        "1.1.1.1",
        "ip",
        links=make_links(make_section("Malware", ["Emotet"]), make_section("Attacker", ["APT28"])),
    ).content

    links = build_links(content.links)

    assert [entity.name for entity in links["Malware"]] == ["Emotet"]
    assert [entity.name for entity in links["Attacker"]] == ["APT28"]


@pytest.mark.xfail(
    strict=True,
    reason="Bug: build_links iterates section.lists without a None guard "
    "(core/RecordedFutureDataModelTransformationLayer.py:82), so a section "
    "the API returns with a null 'lists' raises TypeError instead of "
    "contributing no rows. Remove this marker once fixed.",
)
def test_build_links_skips_sections_with_no_lists() -> None:
    """A section the API returned empty contributes no rows."""
    section = make_section("Malware", [])
    section["lists"] = None
    content = enriched("1.1.1.1", "ip", links=make_links(section)).content

    assert build_links(content.links) == {}


# ---------------------------------------------------------------------------
# build_siemplify_object
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entity", "entity_type", "expected"),
    [
        ("1.1.1.1", "ip", IP),
        ("example.com", "domain", HOST),
        ("https://example.com", "url", URL),
        ("a" * 64, "hash", HASH),
        ("CVE-2026-0001", "vulnerability", CVE),
    ],
)
def test_build_siemplify_object_picks_the_datamodel_for_the_type(
    entity: str,
    entity_type: str,
    expected: type,
) -> None:
    """Each Recorded Future type has one Google SecOps datamodel."""
    assert isinstance(build_siemplify_object(enriched(entity, entity_type)), expected)


def test_build_siemplify_object_carries_the_risk_fields() -> None:
    """Score, rules, and evidence are what the enrichment and widgets render."""
    indicator = build_siemplify_object(
        enriched("1.1.1.1", "ip", score=85, evidence=[make_evidence("Current C&C Server")]),
    )

    assert indicator.score == 85
    assert indicator.rule_names == ["Current C&C Server"]


@pytest.mark.xfail(
    strict=True,
    reason="Bug: RFIndicator.__init__ stores self.entity_id = (entity_id,) "
    "(core/datamodels.py:66), so every datamodel carries a stray 1-tuple "
    "where the callers expect the bare 'type:value' string. Split out from "
    "test_build_siemplify_object_carries_the_risk_fields so the score and "
    "rule assertions keep running. Remove this marker once fixed.",
)
def test_build_siemplify_object_carries_the_entity_id() -> None:
    """The entity id is the 'type:value' string the enrichment keys on."""
    indicator = build_siemplify_object(enriched("1.1.1.1", "ip", score=85))

    assert indicator.entity_id == "ip:1.1.1.1"


def test_build_siemplify_object_adds_ip_geolocation() -> None:
    """An IP's location is only present on the IP datamodel."""
    indicator = build_siemplify_object(enriched("8.8.8.8", "ip", location=LOCATION))

    assert indicator.city == "Mountain View"
    assert indicator.country == "United States"
    assert indicator.asn == "AS15169"
    assert indicator.organization == "Google LLC"


def test_build_siemplify_object_tolerates_an_ip_without_a_location() -> None:
    """The API omits location for some IPs, which must not fail the enrichment."""
    indicator = build_siemplify_object(enriched("1.1.1.1", "ip"))

    assert indicator.city is None
    assert indicator.score == 0


def test_build_siemplify_object_adds_the_hash_algorithm() -> None:
    """The algorithm is requested as an extra field for hashes only."""
    indicator = build_siemplify_object(enriched("a" * 64, "hash", hashAlgorithm="SHA256"))

    assert indicator.hashAlgorithm == "SHA256"


# ---------------------------------------------------------------------------
# build_siemplify_soar_object
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entity_type", "expected"),
    [
        ("IpAddress", IP),
        ("InternetDomainName", HOST),
        ("Hash", HASH),
        ("URL", URL),
        ("CyberVulnerability", CVE),
    ],
)
def test_build_soar_object_maps_every_bulk_entity_type(entity_type: str, expected: type) -> None:
    """The bulk endpoint reports types by their Recorded Future name."""
    assert isinstance(build_siemplify_soar_object(soar_enriched("value", entity_type)), expected)


def test_build_soar_object_carries_evidence_when_present() -> None:
    """Bulk enrichment returns evidence keyed by rule rather than as a list."""
    indicator = build_siemplify_soar_object(
        soar_enriched(
            "1.1.1.1",
            "IpAddress",
            evidence={
                "recentValidatedCnc": {
                    "count": 1,
                    "timestamp": "2026-09-01T07:18:35.000Z",
                    "description": "Validated C&C server.",
                    "rule": "Validated C&C Server",
                    "sightings": 41,
                    "mitigation": "",
                    "level": 4,
                },
            },
        ),
    )

    assert indicator.rule_names == ["Validated C&C Server"]
    assert indicator.score == 85


def test_build_soar_object_without_evidence() -> None:
    """A low risk entity comes back with a score and no triggered rules."""
    indicator = build_siemplify_soar_object(soar_enriched("1.1.1.1", "IpAddress"))

    assert indicator.evidence_details == []
    assert indicator.score == 85


# ---------------------------------------------------------------------------
# format_triggered_by
# ---------------------------------------------------------------------------


def test_format_triggered_by_without_data() -> None:
    """Most alert rules have no triggered-by paths."""
    assert format_triggered_by([]) == {}
    assert format_triggered_by(None) == {}


def test_format_triggered_by_flattens_the_first_path() -> None:
    """Each reference keeps one path, with the relationship folded into the entity."""
    result = format_triggered_by(
        [
            {
                "reference_id": "ref-1",
                "entity_paths": [
                    [
                        {"entity": {"id": "ip:1.1.1.1", "name": "1.1.1.1"}, "attribute": {"id": "attacker"}},
                        {"entity": {"id": "malware:emotet", "name": "Emotet"}, "attribute": {"id": "malware"}},
                    ],
                ],
            },
        ],
    )

    assert [entity["name"] for entity in result["ref-1"]] == ["1.1.1.1", "Emotet"]
    assert result["ref-1"][0]["relationship"] == "attacker"


def test_format_triggered_by_skips_references_without_paths() -> None:
    """A malformed reference must not drop the rest of the alert's references."""
    result = format_triggered_by(
        [
            {"reference_id": "ref-1"},
            {
                "reference_id": "ref-2",
                "entity_paths": [[{"entity": {"id": "ip:1.1.1.1", "name": "1.1.1.1"}, "attribute": {}}]],
            },
        ],
    )

    assert list(result) == ["ref-2"]


def test_format_triggered_by_skips_steps_without_an_entity() -> None:
    """A path step with no entity carries nothing an analyst can pivot on."""
    result = format_triggered_by(
        [
            {
                "reference_id": "ref-1",
                "entity_paths": [
                    [
                        {"attribute": {"id": "attacker"}},
                        {"entity": {"id": "ip:1.1.1.1", "name": "1.1.1.1"}, "attribute": {"id": "attacker"}},
                    ],
                ],
            },
        ],
    )

    assert len(result["ref-1"]) == 1


# ---------------------------------------------------------------------------
# _extract_triggered_by
# ---------------------------------------------------------------------------


def test_extract_triggered_by_parses_name_and_type() -> None:
    """The API reports the trigger as a single `name(Type)` string."""
    assert _extract_triggered_by(["1.1.1.1(IpAddress)"]) == [{"name": "1.1.1.1", "type": "IpAddress"}]


def test_extract_triggered_by_keeps_only_the_first_hop() -> None:
    """Everything after the arrow is the path, not the entity that triggered."""
    assert _extract_triggered_by(["Emotet(Malware)->1.1.1.1(IpAddress)"]) == [
        {"name": "Emotet", "type": "Malware"},
    ]


def test_extract_triggered_by_deduplicates() -> None:
    """The same entity triggering several references is still one entity."""
    assert _extract_triggered_by(["1.1.1.1(IpAddress)", "1.1.1.1(IpAddress)"]) == [
        {"name": "1.1.1.1", "type": "IpAddress"},
    ]


def test_extract_triggered_by_handles_names_with_spaces() -> None:
    """Threat actor and malware names routinely contain spaces."""
    assert _extract_triggered_by(["APT 28(ThreatActor)"]) == [{"name": "APT 28", "type": "ThreatActor"}]


def test_extract_triggered_by_without_data() -> None:
    """An alert with no triggers yields no entities."""
    assert _extract_triggered_by([]) == []


# ---------------------------------------------------------------------------
# Entity mapping
# ---------------------------------------------------------------------------


def test_classic_alert_entity_mapping_covers_every_enrichable_type() -> None:
    """A type missing here is silently dropped from the alert's events."""
    assert set(CLASSIC_ALERT_ENTITY_MAPPING.values()) == {
        "IpAddress",
        "InternetDomainName",
        "EmailAddress",
        "Hash",
        "URL",
        "CyberVulnerability",
    }
