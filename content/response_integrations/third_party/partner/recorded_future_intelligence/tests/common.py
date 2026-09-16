############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Shared fixtures and doubles for the Recorded Future integration tests."""

from __future__ import annotations

import pathlib
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

from soar_sdk.SiemplifyDataModel import DomainEntityInfo, EntityTypes
from TIPCommon.base.job import base_job
from TIPCommon.base.job.job_case import JobCase
from TIPCommon.data_models import CaseDataStatus

from recorded_future_intelligence.core.constants import (
    CLASSIC_ALERT_PRODUCT,
    SYNC_DEFAULT_CLOSE_REASON,
    SYNC_DEFAULT_CLOSE_ROOT_CAUSE,
)

if TYPE_CHECKING:
    from TIPCommon.types import SingleJson

    from recorded_future_intelligence.core.RecordedFutureSyncCommon import (
        RecordedFutureBaseSyncJob,
    )

INTEGRATION_PATH: pathlib.Path = pathlib.Path(__file__).parent.parent
CONFIG_PATH: pathlib.Path = INTEGRATION_PATH / "tests" / "config.json"

SOAR_API_ROOT = "https://secops.example.com/api"
SCRIPT_NAME = "test_script"
UNIQUE_IDENTIFIER = "test_uid"
EXPECTED_NAME_ID = f"{SCRIPT_NAME}_{UNIQUE_IDENTIFIER}"


def make_entity(
    identifier: str,
    entity_type: str = EntityTypes.DOMAIN,
    original_identifier: str | None = None,
    **additional: Any,
) -> DomainEntityInfo:
    """Build one target entity of a case, as an action receives it.

    `DomainEntityInfo` takes its whole field set positionally, and an action
    reads four of them at most, so everything else is defaulted here.

    Args:
        identifier (str): The entity identifier.
        entity_type (str): The Google SecOps entity type.
        original_identifier (str | None): The identifier before Google SecOps
            normalised it. `get_entity_original_identifier` prefers this one,
            so an action sends the analyst's spelling rather than the
            upper-cased form the platform stores.
        **additional (Any): Further `additional_properties` entries.

    Returns:
        DomainEntityInfo: The entity.

    """
    properties = dict(additional)
    if original_identifier is not None:
        properties["OriginalIdentifier"] = original_identifier

    return DomainEntityInfo(
        identifier=identifier,
        creation_time=0,
        modification_time=0,
        case_identifier="1",
        alert_identifier="1",
        entity_type=entity_type,
        is_internal=False,
        is_suspicious=False,
        is_artifact=False,
        is_enriched=False,
        is_vulnerable=False,
        is_pivot=False,
        additional_properties=properties,
    )


def make_enrichment_record(
    entity: str,
    entity_type: str,
    score: int = 0,
    evidence: list[SingleJson] | None = None,
    **extra: Any,
) -> SingleJson:
    """Build the `data` payload the `/v2/{entity_type}/{entity}` endpoint returns.

    Only the fields `build_siemplify_object` reads are populated; everything
    else on the psengine model defaults.

    Args:
        entity (str): The entity value.
        entity_type (str): The Recorded Future entity type.
        score (int): The risk score.
        evidence (list[SingleJson] | None): Risk rule evidence details.
        **extra (Any): Additional top level fields, e.g. `location`.

    Returns:
        SingleJson: The enrichment record.

    """
    return {
        "entity": {"id": f"{entity_type}:{entity}", "name": entity, "type": entity_type},
        "intelCard": f"https://app.recordedfuture.com/live/sc/entity/{entity_type}:{entity}",
        "timestamps": {"firstSeen": "2026-01-02T03:04:05.000Z", "lastSeen": "2026-09-01T03:04:05.000Z"},
        "risk": {
            "score": score,
            "criticality": score // 25,
            "criticalityLabel": "Malicious" if score >= 65 else "Unusual",  # noqa: PLR2004
            "riskString": f"{len(evidence or [])}/70",
            "riskSummary": f"{len(evidence or [])} of 70 Risk Rules currently observed.",
            "rules": len(evidence or []),
            "evidenceDetails": evidence or [],
        },
        **extra,
    }


def make_evidence(
    rule: str,
    criticality: int = 3,
    label: str = "Malicious",
) -> SingleJson:
    """Build one risk rule evidence entry.

    Args:
        rule (str): The risk rule name.
        criticality (int): The rule criticality.
        label (str): The criticality label.

    Returns:
        SingleJson: The evidence entry.

    """
    return {
        "rule": rule,
        "criticality": criticality,
        "criticalityLabel": label,
        "evidenceString": f"Observed by {rule}.",
        "mitigationString": "",
        "timestamp": "2026-09-01T03:04:05.000Z",
    }


def make_soar_record(
    entity: str,
    soar_type: str,
    score: int = 0,
    evidence: SingleJson | None = None,
) -> SingleJson:
    """Build one result of the `/soar/v3/enrichment` bulk endpoint.

    The bulk endpoint returns a differently shaped record than the
    single-entity lookup: risk rules arrive nested under `risk.rule`, with
    evidence keyed by rule name rather than listed, and the entity type is the
    Recorded Future ontology name (`IpAddress`) rather than the lookup's short
    form (`ip`).

    Args:
        entity (str): The entity value.
        soar_type (str): The Recorded Future ontology entity type, as it
            appears in `SOAR_ENTITY_DATAMODEL_MAP`.
        score (int): The risk score.
        evidence (SingleJson | None): Risk rule evidence, keyed by rule name.

    Returns:
        SingleJson: The bulk enrichment record.

    """
    evidence = evidence or {}
    return {
        "entity": {"id": f"{soar_type.lower()}:{entity}", "name": entity, "type": soar_type},
        "risk": {
            "score": score,
            "level": score // 25,
            "context": {},
            "rule": {
                "count": len(evidence),
                "maxCount": 70,
                "score": score,
                "summary": [],
                "mostCritical": next(
                    (rule["rule"] for rule in evidence.values()),
                    "",
                ),
                "evidence": evidence,
            },
        },
    }


def make_soar_evidence(
    rule: str,
    level: int = 4,
    count: int = 1,
) -> SingleJson:
    """Build one risk rule evidence entry of a bulk enrichment record.

    Args:
        rule (str): The risk rule name.
        level (int): The rule's criticality level.
        count (int): How many times the rule fired.

    Returns:
        SingleJson: The evidence entry.

    """
    return {
        "count": count,
        "timestamp": "2026-09-01T03:04:05.000Z",
        "description": f"Observed by {rule}.",
        "rule": rule,
        "sightings": count,
        "mitigation": "",
        "level": level,
    }


def make_hash_report(
    sha256: str,
    score: int = 8,
    task: str = "behavioural1",
    flows: list[SingleJson] | None = None,
    signatures: list[SingleJson] | None = None,
    extensions: list[str] | None = None,
) -> SingleJson:
    """Build one sandbox report of the malware intelligence reports endpoint.

    Args:
        sha256 (str): The sample's SHA256.
        score (int): The sandbox verdict score.
        task (str): The sandbox task that produced the report.
        flows (list[SingleJson] | None): Observed network flows.
        signatures (list[SingleJson] | None): Behavioural signatures that fired.
        extensions (list[str] | None): File extensions seen in the sample.

    Returns:
        SingleJson: The sandbox report.

    """
    return {
        "id": f"report-{sha256[:8]}",
        "file": f"{sha256[:8]}.exe",
        "task": task,
        "metadata": {"source": "sandbox"},
        "sample": {
            "id": f"sample-{sha256[:8]}",
            "score": score,
            "tags": ["malware"],
            "created": "2026-09-01T03:04:05",
            "completed": "2026-09-01T03:06:05",
        },
        "static": {
            "sha256": sha256,
            "exts": extensions if extensions is not None else ["exe"],
            "signatures": [],
        },
        "dynamic": {
            "network": {"flows": flows or []},
            "signatures": signatures or [],
        },
    }


def make_sandbox_flow(
    dst_ip: str,
    dst_port: int = 443,
    proto: str = "tcp",
    layer_7: list[str] | None = None,
) -> SingleJson:
    """Build one observed network flow of a sandbox report.

    Args:
        dst_ip (str): The destination IP.
        dst_port (int): The destination port.
        proto (str): The transport protocol.
        layer_7 (list[str] | None): The application protocols seen on the flow.

    Returns:
        SingleJson: The network flow entry.

    """
    return {
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto": proto,
        "layer_7": layer_7 if layer_7 is not None else ["tls"],
    }


def make_sandbox_signature(
    name: str,
    desc: str | None = None,
    score: int = 5,
    tags: list[str] | None = None,
    ttp: list[str] | None = None,
) -> SingleJson:
    """Build one behavioural signature of a sandbox report.

    Args:
        name (str): The signature name.
        desc (str | None): The signature description. A signature with no
            description is dropped by the transformation layer.
        score (int): The signature's contribution to the verdict.
        tags (list[str] | None): The signature's tags.
        ttp (list[str] | None): The MITRE techniques the signature maps to.

    Returns:
        SingleJson: The signature entry.

    """
    return {
        "name": name,
        "desc": desc if desc is not None else f"{name} was observed.",
        "score": score,
        "tags": tags if tags is not None else ["evasion"],
        "ttp": ttp if ttp is not None else ["T1027"],
    }


def make_classic_alert(
    alert_id: str,
    title: str = "Alert title",
    status: str = "unassigned",
    rule_name: str = "Typosquat rule",
    rule_id: str = "rule-1",
    triggered: str = "2026-09-01T03:04:05.000Z",
    hits: list[SingleJson] | None = None,
    ai_insights: SingleJson | None = None,
) -> SingleJson:
    """Build the `/v3/alerts/{id}` payload for one classic alert.

    Only the fields psengine requires plus the ones `build_alert` and
    `build_siemplify_alert_object` read are populated.

    Args:
        alert_id (str): The Recorded Future alert ID.
        title (str): The alert title.
        status (str): The alert's portal status.
        rule_name (str): The name of the rule that triggered it.
        rule_id (str): The ID of the rule that triggered it.
        triggered (str): When the alert triggered.
        hits (list[SingleJson] | None): The alert's hits. A `triggered_by`
            entry is derived for each one, because `build_alert` looks one up
            per hit and psengine's `triggered_by` defaults to None - an alert
            carrying hits without it raises a `TypeError` that `build_alert`
            does not catch.
        ai_insights (SingleJson | None): The AI Insights block. Omitted
            entirely when None, which is what an alert without one looks like.

    Returns:
        SingleJson: The classic alert record.

    """
    hits = hits or []
    record = {
        "id": alert_id,
        "title": title,
        "type": "ENTITY",
        "log": {"triggered": triggered, "status": status},
        "review": {"status_in_portal": status, "assignee": None, "note": None},
        # psengine's `AlertDeprecation` requires the rule's own portal URL, and
        # `AlertURL` requires both halves of the alert's URL pair.
        "rule": {
            "id": rule_id,
            "name": rule_name,
            "url": {"portal": f"https://app.recordedfuture.com/live/sc/ta/{rule_id}"},
        },
        "url": {
            "api": f"https://api.recordedfuture.com/v3/alerts/{alert_id}",
            "portal": f"https://app.recordedfuture.com/live/sc/notification/{alert_id}",
        },
        "hits": hits,
        "triggered_by": [
            {
                "reference_id": hit["id"],
                "entity_paths": [
                    [{"entity": entity} for entity in hit["entities"]],
                ],
            }
            for hit in hits
        ],
        "enriched_entities": [],
        "owner_organisation_details": {
            "organisations": [],
            "enterprise_id": "uhash:enterprise",
            "enterprise_name": "Example Enterprise",
        },
    }
    if ai_insights is not None:
        record["ai_insights"] = ai_insights

    return record


def make_classic_alert_hit(
    hit_id: str = "hit-1",
    entities: list[SingleJson] | None = None,
    fragment: str = "Observed in a document.",
    doc_title: str = "Source document",
) -> SingleJson:
    """Build one hit of a classic alert.

    Args:
        hit_id (str): The hit ID.
        entities (list[SingleJson] | None): The entities the hit mentions.
        fragment (str): The matched text fragment.
        doc_title (str): The title of the document the hit came from.

    Returns:
        SingleJson: The hit record.

    """
    return {
        "id": hit_id,
        "entities": entities
        or [{"id": "idn:bad-example.com", "name": "bad-example.com", "type": "InternetDomainName"}],
        "fragment": fragment,
        "language": "eng",
        "document": {
            "title": doc_title,
            "url": "https://news.example.com/article",
            "source": {"id": "source-1", "name": "Example News", "type": "Source"},
            "authors": [],
        },
    }


def make_alert_rule(
    rule_id: str = "rule-1",
    title: str = "Typosquat rule",
    enabled: bool = True,
) -> SingleJson:
    """Build one entry of the `/v2/alert/rule` catalogue.

    psengine's `AlertRuleOut` requires the whole administrative field set, not
    just the ID and title the integration reads, so all of it is populated.

    Args:
        rule_id (str): The alert rule ID.
        title (str): The rule title.
        enabled (bool): Whether the rule is enabled.

    Returns:
        SingleJson: The alert rule record.

    """
    return {
        "id": rule_id,
        "title": title,
        "enabled": enabled,
        "created": "2026-01-02T03:04:05.000Z",
        "owner": {"id": "uhash:owner", "name": "Example Enterprise"},
        "intelligence_goals": [{"id": "goal-1", "name": "Brand Protection"}],
        "notification_settings": {"email_subscribers": [], "mobile_subscribers": []},
    }


def make_playbook_alert(
    alert_id: str,
    category: str = "domain_abuse",
    entity_id: str = "idn:bad-example.com",
    entity_name: str = "bad-example.com",
    status: str = "New",
    priority: str = "High",
    screenshots: list[SingleJson] | None = None,
    resolved_records: list[SingleJson] | None = None,
    logs: list[SingleJson] | None = None,
) -> SingleJson:
    """Build the `/playbook-alert/{category}/{id}` payload for one alert.

    Args:
        alert_id (str): The playbook alert ID.
        category (str): The alert category.
        entity_id (str): The prefixed entity the alert is about.
        entity_name (str): The entity's display name.
        status (str): The alert status.
        priority (str): The alert priority.
        screenshots (list[SingleJson] | None): Screenshot metadata entries.
        resolved_records (list[SingleJson] | None): Resolved DNS record entries.
        logs (list[SingleJson] | None): `panel_log_v2` entries. Omitted from
            the payload entirely when None, which is how an alert fetched
            without the log panel arrives - the tracking connector reads the
            key unguarded, so the distinction matters.

    Returns:
        SingleJson: The playbook alert record.

    """
    record = {
        "playbook_alert_id": alert_id,
        "category": category,
        "priority": priority,
        "title": f"{entity_name} - {category}",
        "panel_status": {
            "entity_id": entity_id,
            "entity_name": entity_name,
            "status": status,
            "priority": priority,
            "created": "2026-09-01T03:04:05.000Z",
            "updated": "2026-09-02T03:04:05.000Z",
            # psengine's `AlertRule` requires `label`; `name` is the optional half.
            "alert_rule": {"id": "rule-1", "label": "Domain Abuse", "name": "Domain Abuse"},
            "actions_taken": [],
            "case_rule_label": "Domain Abuse",
            "targets": [],
        },
        "panel_evidence_summary": {
            "screenshots": screenshots or [],
            "resolved_record_list": resolved_records or [],
        },
    }
    if logs is not None:
        record["panel_log_v2"] = logs

    return record


def make_panel_log(
    changes: list[SingleJson],
    created: str = "2026-09-02T03:04:05.123Z",
    log_id: str = "uuid:log-1",
) -> SingleJson:
    """Build one `panel_log_v2` entry.

    The default `created` carries sub-second precision on purpose: psengine
    round-trips the timestamp through a `datetime` and drops a zero
    microsecond component, which the tracking connector's
    `%Y-%m-%dT%H:%M:%S.%f` parse cannot read back. Real log timestamps have
    microseconds, so this reflects them rather than papering over the gap -
    see `test_playbook_alerts_tracking_connector` for the case that pins it.

    Args:
        changes (list[SingleJson]): The changes the entry records.
        created (str): When the change was logged.
        log_id (str): The log entry ID.

    Returns:
        SingleJson: The log entry.

    """
    return {
        "id": log_id,
        "created": created,
        "author_id": "uhash:analyst",
        "author_name": "Analyst",
        "changes": changes,
    }


def make_status_change(old: str = "Resolved", new: str = "New") -> SingleJson:
    """Build a `status_change` log entry change.

    The default is the Resolved to New transition the tracking connector reads
    as a reopen.

    Args:
        old (str): The status before the change.
        new (str): The status after it.

    Returns:
        SingleJson: The change entry.

    """
    return {"type": "status_change", "old": old, "new": new, "actions_taken": []}


def make_priority_change(old: str = "Informational", new: str = "Moderate") -> SingleJson:
    """Build a `priority_change` log entry change.

    Args:
        old (str): The priority before the change.
        new (str): The priority after it.

    Returns:
        SingleJson: The change entry.

    """
    return {"type": "priority_change", "old": old, "new": new}


def make_assessment_change(
    added: list[str] | None = None,
    removed: list[str] | None = None,
) -> SingleJson:
    """Build an `assessment_ids_change` log entry change.

    Args:
        added (list[str] | None): The assessment IDs added.
        removed (list[str] | None): The assessment IDs removed.

    Returns:
        SingleJson: The change entry.

    """
    return {
        "type": "assessment_ids_change",
        "added": added if added is not None else ["assessment-1"],
        "removed": removed or [],
    }


def make_entities_change(
    added: list[SingleJson] | None = None,
    removed: list[SingleJson] | None = None,
) -> SingleJson:
    """Build an `entities_change` log entry change.

    Args:
        added (list[SingleJson] | None): The entities added.
        removed (list[SingleJson] | None): The entities removed.

    Returns:
        SingleJson: The change entry.

    """
    return {
        "type": "entities_change",
        "added": (added if added is not None else [{"id": "ip:9.9.9.9", "name": "9.9.9.9", "type": "IpAddress"}]),
        "removed": removed or [],
    }


def make_screenshot(image_id: str, description: str = "Landing page") -> SingleJson:
    """Build one screenshot metadata entry of a Domain Abuse alert.

    Args:
        image_id (str): The image ID the images endpoint serves it under.
        description (str): The screenshot description.

    Returns:
        SingleJson: The screenshot metadata entry.

    """
    return {
        "image_id": image_id,
        "description": description,
        "created": "2026-09-01T03:04:05.000Z",
        "tag": "analyst",
    }


def make_entity_list(
    list_id: str = "list-1",
    name: str = "SOAR blocklist",
    list_type: str = "entity",
) -> SingleJson:
    """Build one list record of the List API.

    Args:
        list_id (str): The list ID.
        name (str): The list name.
        list_type (str): The list type.

    Returns:
        SingleJson: The list record.

    """
    return {
        "id": list_id,
        "name": name,
        "type": list_type,
        "created": "2026-01-02T03:04:05.000Z",
        "updated": "2026-09-01T03:04:05.000Z",
        "owner_id": "uhash:owner",
        "owner_name": "Example Enterprise",
        "organisation_id": "uhash:org",
        "organisation_name": "Example Enterprise",
    }


def make_list_member(
    entity_id: str = "ip:1.1.1.1",
    name: str | None = None,
    entity_type: str = "IpAddress",
) -> SingleJson:
    """Build one member of a list.

    Args:
        entity_id (str): The prefixed entity ID.
        name (str | None): The entity's display name; derived from the ID when
            omitted.
        entity_type (str): The Recorded Future ontology entity type.

    Returns:
        SingleJson: The membership record.

    """
    return {
        "entity": {
            "id": entity_id,
            "name": name if name is not None else entity_id.split(":", 1)[-1],
            "type": entity_type,
        },
        "status": "added",
        "added": "2026-09-01T03:04:05.000Z",
    }


def make_entity_match(
    entity_id: str = "ip:1.1.1.1",
    name: str = "1.1.1.1",
    entity_type: str = "IpAddress",
) -> SingleJson:
    """Build one hit of the `/entity-match/match` endpoint.

    Args:
        entity_id (str): The resolved entity ID.
        name (str): The entity name that matched.
        entity_type (str): The entity type.

    Returns:
        SingleJson: The match.

    """
    return {"id": entity_id, "name": name, "type": entity_type}


def make_entity_lookup(
    entity_id: str = "L37nw-",
    name: str = "BlueDelta",
    entity_type: str = "Organization",
    is_threat_actor: bool = True,
) -> SingleJson:
    """Build the `/entity-match/entity/{id}` payload for one entity.

    Args:
        entity_id (str): The entity ID.
        name (str): The entity's primary name.
        entity_type (str): The entity type.
        is_threat_actor (bool): Whether Recorded Future tracks it as an actor.

    Returns:
        SingleJson: The entity record.

    """
    return {
        "id": entity_id,
        "type": entity_type,
        "attributes": {
            "name": name,
            "common_names": [name],
            "alias": [],
            "is_threat_actor": is_threat_actor,
        },
    }


def make_detection_rule(
    rule_id: str = "doc:rule-1",
    rule_type: str = "sigma",
    title: str = "Suspicious PowerShell",
    content: str = "title: Suspicious PowerShell\ndetection:\n  condition: selection",
    entities: list[SingleJson] | None = None,
) -> SingleJson:
    """Build one rule of the detection rule catalogue.

    Args:
        rule_id (str): The rule's document ID.
        rule_type (str): The rule type, e.g. `sigma`, `yara` or `snort`.
        title (str): The rule title.
        content (str): The rule text itself.
        entities (list[SingleJson] | None): The entities the rule is tagged with.

    Returns:
        SingleJson: The detection rule record.

    """
    return {
        "id": rule_id,
        "type": rule_type,
        "title": title,
        "description": f"{title} detection rule.",
        "created": "2026-01-02T03:04:05.000Z",
        "updated": "2026-09-01T03:04:05.000Z",
        "rules": [
            {
                "entities": entities or [{"id": "hash:" + "a" * 64, "name": "a" * 64, "type": "Hash"}],
                "content": content,
                "file_name": f"{rule_id.split(':')[-1]}.yml",
            },
        ],
    }


def make_leaked_identity(
    subject: str = "user@example.com",
    hash_prefix: str = "abc123",
    algorithm: str = "SHA1",
    dump_name: str = "Example Stealer Log",
) -> SingleJson:
    """Build one exposure record of the identity lookup endpoints.

    Args:
        subject (str): The exposed subject.
        hash_prefix (str): The prefix of the exposed secret's hash.
        algorithm (str): The hash algorithm.
        dump_name (str): The name of the dump it was found in.

    Returns:
        SingleJson: The exposure record.

    """
    return {
        "identity": {"subjects": [subject]},
        "count": 1,
        "credentials": [
            {
                "subject": subject,
                "dumps": [make_dump(dump_name)],
                "first_downloaded": "2026-08-01T03:04:05.000Z",
                "latest_downloaded": "2026-09-01T03:04:05.000Z",
                "exposed_secret": {
                    "type": "sha1",
                    "hashes": [{"algorithm": algorithm, "hash_prefix": hash_prefix}],
                    "details": {"properties": ["Letter", "Number"]},
                    "effectively_clear": False,
                },
            },
        ],
    }


def make_credential_search_hit(
    login: str = "user",
    domain: str = "example.com",
) -> SingleJson:
    """Build one hit of `/identity/credentials/search`.

    Args:
        login (str): The exposed login.
        domain (str): The domain it belongs to.

    Returns:
        SingleJson: The hit.

    """
    return {"login": login, "domain": domain}


def make_password_exposure(
    hash_prefix: str = "abc123",
    algorithm: str = "SHA1",
    exposure_status: str = "Common",
) -> SingleJson:
    """Build one result of `/identity/password/lookup`.

    Args:
        hash_prefix (str): The prefix of the hash looked up.
        algorithm (str): The hash algorithm.
        exposure_status (str): How widely the password is known.

    Returns:
        SingleJson: The exposure result.

    """
    return {
        "password": {"algorithm": algorithm, "hash_prefix": hash_prefix},
        "exposure_status": exposure_status,
    }


def make_dump(name: str = "Example Stealer Log") -> SingleJson:
    """Build one dump metadata record.

    Args:
        name (str): The dump name.

    Returns:
        SingleJson: The dump record.

    """
    return {
        "name": name,
        "source": "stealer-log",
        "description": f"{name} credential dump.",
        "downloaded": "2026-09-01T03:04:05.000Z",
    }


def make_incident_report(
    subject: str = "user@example.com",
    malware_family: str = "Example Stealer",
    include_details: bool = True,
) -> SingleJson:
    """Build the `/identity/incident/report` payload for one malware log.

    Args:
        subject (str): The exposed login.
        malware_family (str): The malware that exfiltrated it.
        include_details (bool): Whether to include the infected machine's
            details, which the endpoint omits when the caller opts out.

    Returns:
        SingleJson: The incident report.

    """
    report = {
        "credentials": [
            {
                "authorization_domain": "example.com",
                "email_or_login": subject,
                "password": "hunter2",
                "password_sha1": "f3bbbd66a63d4bf1747940578ec3d0103530e21d",
                "contains_high_risk_technologies": False,
                "contains_cookies": False,
                "contains_active_cookies": False,
            },
        ],
        "details": [],
    }
    if include_details:
        report["details"] = [
            {
                "exfiltration_date": "2026-09-01T03:04:05.000Z",
                "malware_family": malware_family,
                "ip_address": "9.9.9.9",
                "country": "US",
            },
        ]

    return report


def make_links_result(
    entity_id: str = "ip:1.1.1.1",
    name: str = "1.1.1.1",
    entity_type: str = "IpAddress",
    links: list[SingleJson] | None = None,
    error: SingleJson | None = None,
) -> SingleJson:
    """Build one entity's result of `/links/search`.

    Args:
        entity_id (str): The entity the links belong to.
        name (str): The entity's display name.
        entity_type (str): The entity type.
        links (list[SingleJson] | None): The linked entities found.
        error (SingleJson | None): The per-entity error, for a batch where the
            API failed for this entity but succeeded for the others.

    Returns:
        SingleJson: The links result.

    """
    record = {
        "entity": {"id": entity_id, "name": name, "type": entity_type},
        "links": links
        if links is not None
        else [
            {
                "id": "K8mKs-",
                "name": "Example Stealer",
                "type": "Malware",
                "source": "Insikt Group",
                "section": "Actors, Tools & TTPs",
            },
        ],
    }
    if error is not None:
        record["error"] = error

    return record


def make_sigma_job(
    job_id: str = "sigma-job-1",
    name: str = "SOAR Sigma job",
    status: str = "FINISHED",
) -> SingleJson:
    """Build one Auto Sigma rule generation job.

    Args:
        job_id (str): The job ID.
        name (str): The job name.
        status (str): The job status. `FINISHED` is what the action polls for.

    Returns:
        SingleJson: The job record.

    """
    return {
        "job_id": job_id,
        "name": name,
        "status": status,
        "created": "2026-09-01T03:04:05.000Z",
        "query": "malwareFamily:ExampleStealer",
        "start_date": "2026-08-01",
        "n_matched_hashes": 3,
        "sigma_rules": [],
    }


def make_yara_job(
    job_id: str = "yara-job-1",
    name: str = "SOAR YARA job",
    status: str = "FINISHED",
    rule: str | None = "rule Example { condition: true }",
) -> SingleJson:
    """Build one Auto YARA rule generation job.

    Args:
        job_id (str): The job ID.
        name (str): The job name.
        status (str): The job status. `FINISHED` is what the action polls for.
        rule (str | None): The generated rule. A job that has not finished has
            none.

    Returns:
        SingleJson: The job record.

    """
    return {
        "job": {
            "job_id": job_id,
            "name": name,
            "status": status,
            "created": "2026-09-01T03:04:05.000Z",
            "patterns": [],
            "yara_rule_str": rule,
            "coverage": {"covered_hashes": ["a" * 64], "uncovered_hashes": []},
        },
    }


def make_alert(
    identifier: str,
    ticket_id: str | None,
    device_product: str = CLASSIC_ALERT_PRODUCT,
    status: str = "opened",
) -> SimpleNamespace:
    """Build a stand-in for a Google SecOps alert card.

    Args:
        identifier (str): The Google SecOps alert identifier.
        ticket_id (str | None): The Recorded Future alert ID the connector
            stamped onto the alert.
        device_product (str): The alert's device product.
        status (str): The alert's status.

    Returns:
        SimpleNamespace: The alert double.

    """
    return SimpleNamespace(
        identifier=identifier,
        ticket_id=ticket_id,
        device_product=device_product,
        status=status,
        name=f"Alert {identifier}",
        closure_details={},
    )


def make_job_case(
    alerts: list[SimpleNamespace] | None = None,
    case_id: int = 42,
    status: CaseDataStatus = CaseDataStatus.OPENED,
    modification_time: int = 1_700_000_000_000,
) -> JobCase:
    """Build a real `JobCase` around lightweight case and alert doubles.

    Args:
        alerts (list[SimpleNamespace] | None): The case's alerts.
        case_id (int): The case ID.
        status (CaseDataStatus): The case status.
        modification_time (int): The case modification time, in milliseconds.

    Returns:
        JobCase: The job case.

    """
    case_detail = SimpleNamespace(
        id_=case_id,
        alerts=list(alerts or []),
        status=status,
        tags=[],
        comments=[],
        assigned_user=None,
    )
    return JobCase(case_detail=case_detail, modification_time=modification_time)


def make_params(**overrides: Any) -> SimpleNamespace:
    """Build a job parameter container with the sync job defaults.

    Args:
        **overrides (Any): Parameter values to override.

    Returns:
        SimpleNamespace: The parameter container.

    """
    params = SimpleNamespace(
        environment_name="Default Environment",
        max_hours_backwards=24,
        closed_alert_reason=SYNC_DEFAULT_CLOSE_REASON,
        closed_alert_root_cause=SYNC_DEFAULT_CLOSE_ROOT_CAUSE,
        close_case_when_all_alerts_closed=False,
    )
    for name, value in overrides.items():
        setattr(params, name, value)

    return params


def build_job(
    job_class: type[RecordedFutureBaseSyncJob],
    params: SimpleNamespace | None = None,
    alert_state: dict[str, dict] | None = None,
) -> RecordedFutureBaseSyncJob:
    """Instantiate a sync job with its SOAR dependencies replaced by doubles.

    The job's real `__init__` runs, so context identifiers and the rest of the
    `BaseSyncJob` setup are exercised rather than faked.

    Args:
        job_class (type[RecordedFutureBaseSyncJob]): The job class to build.
        params (SimpleNamespace | None): Job parameters; defaults are used if
            omitted.
        alert_state (dict[str, dict] | None): Pre-existing per-alert sync state.

    Returns:
        RecordedFutureBaseSyncJob: The job, ready to exercise.

    """
    soar_job = MagicMock()
    soar_job.script_name = SCRIPT_NAME
    soar_job.unique_identifier = UNIQUE_IDENTIFIER
    soar_job.API_ROOT = SOAR_API_ROOT
    soar_job.get_job_context_property.return_value = None

    with (
        patch.object(base_job, "create_soar_job", return_value=soar_job),
        patch.object(base_job, "create_params_container", return_value=make_params()),
        patch.object(base_job, "create_logger", return_value=MagicMock()),
    ):
        job = job_class()

    job._params = params if params is not None else make_params()
    job._api_client = MagicMock()
    job.alert_state = dict(alert_state or {})
    job.last_run_time = 1_700_000_000_000

    return job
