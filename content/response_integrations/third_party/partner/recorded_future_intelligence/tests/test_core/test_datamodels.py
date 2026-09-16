############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Tests for the datamodels the actions and connectors render.

These objects decide what an analyst actually sees: the enrichment fields
stamped onto an entity, the tables in the case wall, and the severity a
connector assigns to an alert.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from recorded_future_intelligence.core.constants import (
    CLASSIC_ALERT_PRODUCT,
    DEFAULT_DEVICE_VENDOR,
    PLAYBOOK_ALERT_PRODUCT,
)
from recorded_future_intelligence.core.datamodels import (
    CVE,
    HASH,
    HOST,
    IP,
    URL,
    Alert,
    AlertDetails,
    AnalystNote,
    BaseModel,
    PlaybookAlert,
    RFIndicator,
)

EVIDENCE = [
    {
        "rule": "Historical Bad DNS",
        "criticalityLabel": "Unusual",
        "evidenceString": "Seen resolving a bad domain.",
        "timestamp": "2026-01-05T00:00:00.000Z",
    },
    {
        "rule": "Current C&C Server",
        "criticalityLabel": "Malicious",
        "evidenceString": "Reported as a C&C server.",
        "timestamp": "2026-09-01T00:00:00.000Z",
    },
]

# psengine parses API timestamps into datetimes before the datamodels see them.
TRIGGERED = datetime(2026, 9, 1, 3, 4, 5, tzinfo=timezone.utc)
ENDED = datetime(2026, 9, 2, 3, 4, 5, tzinfo=timezone.utc)


def make_indicator(cls: type[RFIndicator] = RFIndicator, **overrides: object) -> RFIndicator:
    """Build an indicator with the fields the enrichment path fills in."""
    fields = {
        "raw_data": {"entity": {"name": "1.1.1.1"}},
        "entity_id": "ip:1.1.1.1",
        "score": 75,
        "riskString": "2/70",
        "firstSeen": "01/02/2026 03:04:05",
        "lastSeen": "09/01/2026 03:04:05",
        "intelCard": "https://app.recordedfuture.com/live/sc/entity/ip:1.1.1.1",
        "criticality": 3,
        "links": {},
        "evidence_details": EVIDENCE,
    }
    fields.update(overrides)
    return cls(**fields)


# ---------------------------------------------------------------------------
# BaseModel
# ---------------------------------------------------------------------------


def test_base_model_returns_its_raw_data() -> None:
    """`to_json` is the passthrough the actions use for the raw API payload."""
    raw = {"id": "abc", "nested": {"key": "value"}}

    assert BaseModel(raw).to_json() == raw


# ---------------------------------------------------------------------------
# RFIndicator
# ---------------------------------------------------------------------------


def test_indicator_to_json_is_wrapped_in_a_tuple() -> None:
    """`RFIndicator` stores and returns `raw_data` wrapped in a one-tuple.

    The actions unwrap it on the way out, so the shape is load bearing even
    though it reads like a typo.
    """
    indicator = make_indicator(raw_data={"entity": {"name": "1.1.1.1"}})

    assert indicator.to_json() == ({"entity": {"name": "1.1.1.1"}},)


def test_indicator_to_json_substitutes_the_flattened_links() -> None:
    """The raw API links object is unusable in a widget; the flattened one is not."""
    indicator = make_indicator(raw_data={"links": {"hits": []}}, links={"Malware": []})

    assert indicator.to_json()[0]["links"] == {"Malware": []}


def test_indicator_derives_rule_names_from_evidence() -> None:
    """The rule names feed the `RF_risk_rules` enrichment field."""
    assert make_indicator().rule_names == ["Historical Bad DNS", "Current C&C Server"]


def test_indicator_to_csv() -> None:
    """The case wall CSV carries the score, rules, and reference dates."""
    assert make_indicator().to_csv() == {
        "Risk Score": 75,
        "Triggered Rules": "2/70",
        "First Reference": "01/02/2026 03:04:05",
        "Last Reference": "09/01/2026 03:04:05",
    }


def test_indicator_overview_table_is_a_single_row() -> None:
    """The overview widget renders one row per entity."""
    table = make_indicator().to_overview_table()

    assert len(table) == 1
    assert table[0]["Risk Score"] == 75


def test_risk_table_lists_the_most_recent_rule_first() -> None:
    """Evidence arrives oldest first; the analyst needs newest first."""
    table = make_indicator().to_risk_table()

    assert [row["Rule"] for row in table] == ["Current C&C Server", "Historical Bad DNS"]
    assert table[0]["Criticality"] == "Malicious"
    assert table[0]["Evidence"] == "Reported as a C&C server."


def test_risk_table_is_empty_without_evidence() -> None:
    """An entity with no triggered rules renders no risk rows."""
    assert make_indicator(evidence_details=[]).to_risk_table() == []


def test_links_table_flattens_each_section() -> None:
    """Links are grouped by section and flattened into one table."""
    links = {
        "Malware": [SimpleNamespace(name="Emotet", type_="Malware")],
        "Attacker": [SimpleNamespace(name="APT28", type_="Threat Actor")],
    }

    assert make_indicator(links=links).to_links_table() == [
        {"Entity": "Emotet", "Type": "Malware", "Relationship": "Malware"},
        {"Entity": "APT28", "Type": "Threat Actor", "Relationship": "Attacker"},
    ]


def test_enrichment_data_joins_the_rule_names() -> None:
    """`RF_risk_rules` is a single comma separated field on the entity."""
    assert make_indicator().get_enrichment_data() == {
        "intel_card": "https://app.recordedfuture.com/live/sc/entity/ip:1.1.1.1",
        "risk_string": "2/70",
        "risk_rules": "Historical Bad DNS,Current C&C Server",
        "risk_score": 75,
    }


def test_enrichment_data_is_prefixed() -> None:
    """Every field written to an entity is namespaced to Recorded Future."""
    enrichment = make_indicator().to_enrichment_data()

    assert set(enrichment) == {"RF_intel_card", "RF_risk_string", "RF_risk_rules", "RF_risk_score"}


def test_enrichment_data_drops_empty_fields() -> None:
    """A field the API did not return is left off the entity rather than blanked."""
    enrichment = make_indicator(intelCard=None, evidence_details=[]).to_enrichment_data()

    assert "RF_intel_card" not in enrichment
    assert "RF_risk_rules" not in enrichment


# ---------------------------------------------------------------------------
# IP
# ---------------------------------------------------------------------------


def make_ip(**overrides: object) -> IP:
    """Build an IP indicator carrying its geolocation."""
    fields = {
        "city": "Mountain View",
        "country": "United States",
        "asn": "AS15169",
        "organization": "Google LLC",
    }
    fields.update(overrides)
    return make_indicator(IP, **fields)


def test_ip_csv_replaces_the_dates_with_geolocation() -> None:
    """An IP's location is more useful on the case wall than its reference dates."""
    assert make_ip().to_csv() == {
        "Risk Score": 75,
        "Triggered Rules": "2/70",
        "Geo-City": "Mountain View",
        "Geo-Country": "United States",
        "Asn": "AS15169",
        "Org": "Google LLC",
    }


def test_ip_overview_table_carries_geolocation() -> None:
    """The IP widget shows the same geolocation columns."""
    assert make_ip().to_overview_table()[0]["Org"] == "Google LLC"


def test_ip_enrichment_data_adds_geolocation_fields() -> None:
    """An enriched IP entity gains the location fields on top of the risk fields."""
    enrichment = make_ip().get_enrichment_data()

    assert enrichment["city"] == "Mountain View"
    assert enrichment["country"] == "United States"
    assert enrichment["asn"] == "AS15169"
    assert enrichment["org"] == "Google LLC"


def test_ip_without_location_still_enriches() -> None:
    """The API omits location for some IPs; the risk fields must survive that."""
    enrichment = make_ip(city=None, country=None, asn=None, organization=None).to_enrichment_data()

    assert enrichment["RF_risk_score"] == 75
    assert "RF_city" not in enrichment


# ---------------------------------------------------------------------------
# HASH
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason="Bug: HASH.to_csv maps 'Hash Algorithm' to self.riskString "
    "(core/datamodels.py:266). The sibling to_overview_table uses "
    "self.hashAlgorithm correctly, so the CSV column reports the risk "
    "string instead of the algorithm. Remove this marker once fixed.",
)
def test_hash_csv_reports_the_algorithm() -> None:
    """The algorithm column must carry the algorithm, not the risk string."""
    csv = make_indicator(HASH, hashAlgorithm="SHA256").to_csv()

    assert csv["Hash Algorithm"] == "SHA256"
    assert csv["Triggered Rules"] == "2/70"


def test_hash_overview_table_reports_the_algorithm() -> None:
    """The hash widget shows which algorithm produced the value."""
    assert make_indicator(HASH, hashAlgorithm="SHA256").to_overview_table()[0]["Hash Algorithm"] == "SHA256"


# ---------------------------------------------------------------------------
# URL, CVE, HOST
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cls", [URL, CVE, HOST])
def test_plain_indicators_inherit_the_base_rendering(cls: type[RFIndicator]) -> None:
    """These types add no fields of their own, so they render like the base."""
    indicator = make_indicator(cls)

    assert indicator.to_csv()["Risk Score"] == 75
    assert indicator.to_risk_table()[0]["Rule"] == "Current C&C Server"


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------


def make_alert(severity: str = "High", **overrides: object) -> Alert:
    """Build a classic alert as the connector builds it."""
    fields = {
        "raw_data": {"id": "abc123", "title": "Suspected malware"},
        "id_": "abc123",
        "title": "Suspected malware",
        "rule": {"id": "rule-1"},
        "rule_name": "Malware Rule",
        "triggered": TRIGGERED,
        "severity": severity,
    }
    fields.update(overrides)
    return Alert(**fields)


@pytest.mark.parametrize(
    ("severity", "expected"),
    [("Low", 40), ("Medium", 60), ("High", 80), ("Critical", 100)],
)
def test_alert_severity_maps_to_a_secops_priority(severity: str, expected: int) -> None:
    """Recorded Future severities drive the case priority in Google SecOps."""
    assert make_alert(severity).get_siemplify_severity() == expected


def test_alert_severity_falls_back_to_medium() -> None:
    """An unrecognised severity must not crash the connector."""
    assert make_alert("Unheard Of").get_siemplify_severity() == 60


def test_alert_info_identifies_the_recorded_future_product() -> None:
    """The sync jobs find their alerts by vendor and product, so both must be stamped."""
    alert = make_alert()
    alert.events = [{"name": "event"}]

    info = alert.get_alert_info(
        SimpleNamespace(),
        SimpleNamespace(get_environment=lambda _: "Default Environment"),
    )

    assert info.device_vendor == DEFAULT_DEVICE_VENDOR
    assert info.device_product == CLASSIC_ALERT_PRODUCT
    assert info.ticket_id == "abc123"
    assert info.rule_generator == "Malware Rule"
    assert info.start_time == info.end_time


def test_alert_events_are_flattened() -> None:
    """Google SecOps events cannot carry nested structures."""
    alert = make_alert()
    alert.events = [{"outer": {"inner": "value"}}]

    assert alert.create_events() == [{"outer_inner": "value"}]


# ---------------------------------------------------------------------------
# AlertDetails and AnalystNote
# ---------------------------------------------------------------------------


def test_alert_details_returns_its_raw_data() -> None:
    """The details action returns the API payload untouched."""
    details = AlertDetails(raw_data={"id": "abc"}, alert_url="https://app.recordedfuture.com/alert")

    assert details.to_json() == {"id": "abc"}
    assert details.alert_url == "https://app.recordedfuture.com/alert"


def test_analyst_note_enrichment_carries_the_document_id() -> None:
    """A published note stamps its document ID so later actions can find it."""
    assert AnalystNote().to_enrichment_data(document_id="doc-1") == {"RF_doc_id": "doc-1"}


def test_analyst_note_enrichment_is_empty_without_a_document_id() -> None:
    """A note that was never published has nothing to stamp."""
    assert AnalystNote().to_enrichment_data() == {}


# ---------------------------------------------------------------------------
# PlaybookAlert
# ---------------------------------------------------------------------------


def make_playbook_alert(**overrides: object) -> PlaybookAlert:
    """Build a playbook alert as the connector builds it."""
    fields = {
        "raw_data": {"panel_status": {"status": "New"}},
        "id_": "task:abc-123",
        "alert_url": "https://app.recordedfuture.com/playbook-alerts/task:abc-123",
        "category": "domain_abuse",
        "label": "Domain Abuse",
        "start": TRIGGERED,
        "end": ENDED,
        "title": "Typosquat detected",
        "priority": "High",
    }
    fields.update(overrides)
    return PlaybookAlert(**fields)


def test_playbook_alert_prefers_an_explicit_severity() -> None:
    """A severity set by the connector overrides the alert's own priority."""
    assert make_playbook_alert(severity="Critical", priority="Informational").get_siemplify_severity() == 100


@pytest.mark.parametrize(
    ("priority", "expected"),
    [("Informational", 40), ("Moderate", 60), ("High", 80)],
)
def test_playbook_alert_priority_maps_to_a_secops_priority(priority: str, expected: int) -> None:
    """Playbook alert priorities use their own scale before mapping to SecOps."""
    assert make_playbook_alert(priority=priority).get_siemplify_severity() == expected


def test_playbook_alert_severity_falls_back_to_medium() -> None:
    """An unrecognised priority must not crash the connector."""
    assert make_playbook_alert(priority="Unheard Of").get_siemplify_severity() == 60


def test_playbook_alert_event_carries_its_category() -> None:
    """Widgets route on the category, which the API payload does not include."""
    event = make_playbook_alert().create_event()[0]

    assert event["category"] == "domain_abuse"
    assert event["panel_status_status"] == "New"


def test_playbook_alert_event_omits_linked_cases_when_unset() -> None:
    """A blank `linked_cases` field would render an empty row in the case wall."""
    event = make_playbook_alert().create_event()[0]

    assert not [key for key in event if key.startswith("linked_cases")]


def test_playbook_alert_event_includes_linked_cases_when_set() -> None:
    """Linked cases let an analyst pivot to the other cases for the same alert.

    Flattening expands the list into one indexed key per case.
    """
    event = make_playbook_alert(linked_cases=["1", "2"]).create_event()[0]

    assert event["linked_cases_1"] == "1"
    assert event["linked_cases_2"] == "2"


def test_playbook_alert_info_identifies_the_recorded_future_product() -> None:
    """The playbook alert sync job finds its alerts by vendor and product."""
    info = make_playbook_alert().get_alert_info(
        SimpleNamespace(),
        SimpleNamespace(get_environment=lambda _: "Default Environment"),
    )

    assert info.device_vendor == DEFAULT_DEVICE_VENDOR
    assert info.device_product == PLAYBOOK_ALERT_PRODUCT
    assert info.ticket_id == "task:abc-123"
    assert info.rule_generator == "Domain Abuse"
