############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""In-memory stand-in for the Recorded Future API.

Tests seed this with the records the API should return, then assert against
what the integration sent back to it. `RecordedFutureSession` is the only
thing that talks to it - tests never construct responses directly.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from TIPCommon.types import SingleJson


@dataclasses.dataclass(slots=True)
class RecordedFuture:
    """The Recorded Future API as the integration sees it."""

    enrichment: dict[tuple[str, str], SingleJson] = dataclasses.field(default_factory=dict)
    collective_insights: list[SingleJson] = dataclasses.field(default_factory=list)
    authorized: bool = True

    # Set False to make the Collective Insights endpoint fail, so a test can
    # exercise the paths that must not let a detection submission take the
    # enrichment down with it.
    collective_insights_available: bool = True

    # Bulk enrichment, keyed the way `/soar/v3/enrichment` reports results.
    soar_enrichment: dict[tuple[str, str], SingleJson] = dataclasses.field(default_factory=dict)

    # Sandbox reports, keyed by SHA256.
    hash_reports: dict[str, list[SingleJson]] = dataclasses.field(default_factory=dict)

    # Classic alerts: the rule catalogue, the alerts themselves, and a record of
    # every update the integration submitted.
    alert_rules: list[SingleJson] = dataclasses.field(default_factory=list)
    classic_alerts: dict[str, SingleJson] = dataclasses.field(default_factory=dict)
    alert_updates: list[SingleJson] = dataclasses.field(default_factory=list)

    # Analyst notes the integration published.
    published_notes: list[SingleJson] = dataclasses.field(default_factory=list)

    # Playbook alerts, keyed by (category, alert id), plus the updates submitted
    # against them and the screenshot bytes their images endpoint serves.
    playbook_alerts: dict[tuple[str, str], SingleJson] = dataclasses.field(default_factory=dict)
    playbook_alert_updates: list[SingleJson] = dataclasses.field(default_factory=list)
    screenshots: dict[str, bytes] = dataclasses.field(default_factory=dict)

    # Image IDs the API refuses to serve, so a test can exercise the per-image
    # failure path without taking the whole fetch down.
    unavailable_screenshots: set[str] = dataclasses.field(default_factory=set)

    # Entity lists, keyed by list ID, plus their members, their build status and
    # a record of every membership change the integration submitted.
    entity_lists: dict[str, SingleJson] = dataclasses.field(default_factory=dict)
    list_entities: dict[str, list[SingleJson]] = dataclasses.field(default_factory=dict)
    list_statuses: dict[str, SingleJson] = dataclasses.field(default_factory=dict)
    list_operations: list[SingleJson] = dataclasses.field(default_factory=list)

    # Entity match, keyed by the name searched for, and entity lookup by ID.
    entity_matches: dict[str, list[SingleJson]] = dataclasses.field(default_factory=dict)
    entity_lookups: dict[str, SingleJson] = dataclasses.field(default_factory=dict)

    # Detection rules the catalogue holds.
    detection_rules: list[SingleJson] = dataclasses.field(default_factory=list)

    # Auto Sigma and Auto YARA rule generation jobs, keyed by job ID, plus the
    # job creations the integration submitted.
    sigma_jobs: dict[str, SingleJson] = dataclasses.field(default_factory=dict)
    yara_jobs: dict[str, SingleJson] = dataclasses.field(default_factory=dict)
    rule_job_requests: list[SingleJson] = dataclasses.field(default_factory=list)

    # Identity: leaked credentials keyed by the subject, hostname or IP they are
    # exposed under, plus password exposure, dump metadata and incident reports.
    leaked_identities: dict[str, SingleJson] = dataclasses.field(default_factory=dict)
    credential_search_results: dict[str, list[SingleJson]] = dataclasses.field(default_factory=dict)
    password_exposures: dict[str, SingleJson] = dataclasses.field(default_factory=dict)
    dumps: dict[str, SingleJson] = dataclasses.field(default_factory=dict)
    incident_reports: dict[str, SingleJson] = dataclasses.field(default_factory=dict)

    # Links, keyed by the entity they were found for.
    links: dict[str, SingleJson] = dataclasses.field(default_factory=dict)

    def set_enrichment(self, entity_type: str, entity: str, record: SingleJson) -> None:
        """Make `/v2/{entity_type}/{entity}` return `record`."""
        self.enrichment[entity_type, entity] = record

    def get_enrichment(self, entity_type: str, entity: str) -> SingleJson | None:
        """Return the seeded record, or None for an entity the API has never seen."""
        return self.enrichment.get((entity_type, entity))

    def add_collective_insights(self, payload: SingleJson) -> None:
        """Record a Collective Insights submission for later assertion."""
        self.collective_insights.append(payload)

    def set_soar_enrichment(self, entity_type: str, entity: str, record: SingleJson) -> None:
        """Make `/soar/v3/enrichment` return `record` for one entity."""
        self.soar_enrichment[entity_type, entity] = record

    def get_soar_enrichment(self, requested: dict[str, list[str]]) -> list[SingleJson]:
        """Return the seeded bulk records matching a SOAR request body.

        Args:
            requested: The request body, mapping entity type to entity values.

        Returns:
            The seeded records for the requested entities, in request order.
            An entity with nothing seeded is omitted, which is what the real
            endpoint does for an entity it holds no data on.

        """
        records = []
        for entity_type, entities in requested.items():
            # psengine sends `hash_` for hashes, matching its keyword argument.
            key = entity_type.rstrip("_")
            records.extend(
                self.soar_enrichment[key, entity] for entity in entities if (key, entity) in self.soar_enrichment
            )
        return records

    def set_hash_report(self, sha256: str, reports: list[SingleJson]) -> None:
        """Make `/malware-intelligence/v1/reports` return `reports` for a hash."""
        self.hash_reports[sha256] = reports

    def get_hash_reports(self, sha256: str) -> list[SingleJson]:
        """Return the seeded sandbox reports for a hash, or none."""
        return self.hash_reports.get(sha256, [])

    def set_classic_alert(self, alert_id: str, record: SingleJson) -> None:
        """Make `/v3/alerts/{id}` return `record`."""
        self.classic_alerts[alert_id] = record

    def get_classic_alert(self, alert_id: str) -> SingleJson | None:
        """Return the seeded classic alert, or None."""
        return self.classic_alerts.get(alert_id)

    def add_alert_rule(self, record: SingleJson) -> None:
        """Add one rule to the `/v2/alert/rule` catalogue."""
        self.alert_rules.append(record)

    def search_alert_rules(self, freetext: str | None) -> list[SingleJson]:
        """Return catalogue rules whose title contains `freetext`.

        Args:
            freetext: The search term. None returns the whole catalogue, which
                is what the endpoint does with no `freetext` parameter.

        Returns:
            The matching rules, in seeding order.

        """
        if not freetext:
            return list(self.alert_rules)

        return [rule for rule in self.alert_rules if freetext.lower() in rule["title"].lower()]

    def search_classic_alerts(
        self,
        status: str | None = None,
        rule_id: str | None = None,
    ) -> list[SingleJson]:
        """Return the seeded classic alerts matching a search.

        Args:
            status: The portal status to match. None matches every status.
            rule_id: The triggering rule to match. None matches every rule.

        Returns:
            The matching alerts, in seeding order.

        """
        return [
            record
            for record in self.classic_alerts.values()
            if (status is None or record.get("review", {}).get("status_in_portal") == status)
            and (rule_id is None or record.get("rule", {}).get("id") == rule_id)
        ]

    def add_alert_update(self, payload: SingleJson) -> None:
        """Record a classic alert update for later assertion."""
        self.alert_updates.append(payload)

    def add_published_note(self, payload: SingleJson) -> None:
        """Record an analyst note publication for later assertion."""
        self.published_notes.append(payload)

    def set_playbook_alert(self, category: str, alert_id: str, record: SingleJson) -> None:
        """Make `/playbook-alert/{category}/{id}` return `record`."""
        self.playbook_alerts[category, alert_id] = record

    def get_playbook_alert(self, category: str, alert_id: str) -> SingleJson | None:
        """Return the seeded playbook alert, or None."""
        return self.playbook_alerts.get((category, alert_id))

    def get_playbook_alerts_bulk(self, category: str, alert_ids: list[str]) -> list[SingleJson]:
        """Return the seeded alerts of one category, for the requested IDs.

        Args:
            category: The category the alerts belong to.
            alert_ids: The IDs to return.

        Returns:
            The seeded records, in request order. An unseeded ID is omitted.

        """
        return [
            self.playbook_alerts[category, alert_id]
            for alert_id in alert_ids
            if (category, alert_id) in self.playbook_alerts
        ]

    def search_playbook_alerts(
        self,
        categories: list[str],
        statuses: list[str] | None = None,
        priorities: list[str] | None = None,
    ) -> list[SingleJson]:
        """Return the seeded playbook alerts matching a search filter.

        A hit is not the alert itself: the endpoint returns a flat summary drawn
        from the alert's status panel, which is what is built here so psengine's
        `SearchData` validates against it.

        Args:
            categories: The categories to match. An empty list matches all of
                them, which is what the endpoint does with no category filter.
            statuses: The statuses to match, or None to match every status.
            priorities: The priorities to match, or None to match every priority.

        Returns:
            The matching alerts as search hits, in seeding order.

        """
        hits = []
        for (category, alert_id), record in self.playbook_alerts.items():
            if categories and category not in categories:
                continue

            panel = record["panel_status"]
            if statuses and panel["status"] not in statuses:
                continue
            if priorities and panel["priority"] not in priorities:
                continue

            hits.append(
                {
                    "playbook_alert_id": alert_id,
                    "category": category,
                    "title": record.get("title", alert_id),
                    "alert_rule": panel["alert_rule"],
                    "status": panel["status"],
                    "priority": panel["priority"],
                    "created": panel["created"],
                    "updated": panel["updated"],
                    "actions_taken": panel["actions_taken"],
                },
            )

        return hits

    def add_playbook_alert_update(self, payload: SingleJson) -> None:
        """Record a playbook alert update for later assertion."""
        self.playbook_alert_updates.append(payload)

    def set_screenshot(self, image_id: str, content: bytes) -> None:
        """Make the images endpoint serve `content` for `image_id`."""
        self.screenshots[image_id] = content

    def get_screenshot(self, image_id: str) -> bytes | None:
        """Return the seeded image bytes, or None if the API will not serve it."""
        if image_id in self.unavailable_screenshots:
            return None
        return self.screenshots.get(image_id)

    def set_entity_list(
        self,
        list_id: str,
        record: SingleJson,
        entities: list[SingleJson] | None = None,
        status: SingleJson | None = None,
    ) -> None:
        """Make the List API serve one list, its members and its build status.

        Args:
            list_id: The list ID.
            record: The list record `/list/{id}/info` returns.
            entities: The list's members.
            status: The list's build status. Defaults to a ready list, because
                a bulk add polls until the status reads `ready` and would
                otherwise spin.

        """
        self.entity_lists[list_id] = record
        self.list_entities[list_id] = list(entities or [])
        self.list_statuses[list_id] = status or {
            "size": len(entities or []),
            "status": "ready",
        }

    def get_entity_list(self, list_id: str) -> SingleJson | None:
        """Return the seeded list record, or None."""
        return self.entity_lists.get(list_id)

    def create_entity_list(self, name: str, list_type: str) -> SingleJson:
        """Create a list and return the record the API answers with.

        Args:
            name: The list name.
            list_type: The list type.

        Returns:
            The new list's record.

        """
        list_id = f"list-{len(self.entity_lists) + 1}"
        record = {
            "id": list_id,
            "name": name,
            "type": list_type,
            "created": "2026-09-01T03:04:05.000Z",
            "updated": "2026-09-01T03:04:05.000Z",
            "owner_id": "uhash:owner",
            "owner_name": "Example Enterprise",
            "organisation_id": "uhash:org",
            "organisation_name": "Example Enterprise",
        }
        self.set_entity_list(list_id, record)
        return record

    def search_entity_lists(
        self,
        name: str | None = None,
        list_type: str | None = None,
    ) -> list[SingleJson]:
        """Return the seeded lists matching a search.

        Args:
            name: A substring of the list name to match, or None for any name.
            list_type: The list type to match, or None for any type.

        Returns:
            The matching list records, in seeding order.

        """
        return [
            record
            for record in self.entity_lists.values()
            if (name is None or name.lower() in record["name"].lower())
            and (list_type is None or record["type"] == list_type)
        ]

    def get_list_entities(self, list_id: str) -> list[SingleJson]:
        """Return the seeded members of a list."""
        return self.list_entities.get(list_id, [])

    def get_list_status(self, list_id: str) -> SingleJson | None:
        """Return the seeded build status of a list, or None."""
        return self.list_statuses.get(list_id)

    def add_list_operation(self, list_id: str, operation: str, entity_id: str) -> str:
        """Record a membership change and report what it did.

        Args:
            list_id: The list the change was made against.
            operation: `added` or `removed`.
            entity_id: The prefixed entity ID.

        Returns:
            The result the API reports: the operation itself, or `unchanged`
            when the list is already in the requested state.

        """
        self.list_operations.append(
            {"list_id": list_id, "operation": operation, "entity": entity_id},
        )
        members = self.list_entities.setdefault(list_id, [])
        present = any(member["entity"]["id"] == entity_id for member in members)

        if operation == "added" and not present:
            members.append(
                {
                    "entity": {"id": entity_id, "name": entity_id.split(":", 1)[-1], "type": "IpAddress"},
                    "status": "added",
                    "added": "2026-09-01T03:04:05.000Z",
                },
            )
            return "added"

        if operation == "removed" and present:
            self.list_entities[list_id] = [member for member in members if member["entity"]["id"] != entity_id]
            return "removed"

        return "unchanged"

    def set_entity_match(self, name: str, matches: list[SingleJson]) -> None:
        """Make `/entity-match/match` return `matches` for a name."""
        self.entity_matches[name] = matches

    def get_entity_matches(self, name: str) -> list[SingleJson]:
        """Return the seeded matches for a name, or none."""
        return self.entity_matches.get(name, [])

    def set_entity_lookup(self, entity_id: str, record: SingleJson) -> None:
        """Make `/entity-match/entity/{id}` return `record`."""
        self.entity_lookups[entity_id] = record

    def get_entity_lookup(self, entity_id: str) -> SingleJson | None:
        """Return the seeded entity record, or None."""
        return self.entity_lookups.get(entity_id)

    def add_detection_rule(self, record: SingleJson) -> None:
        """Add one rule to the detection rule catalogue."""
        self.detection_rules.append(record)

    def search_detection_rules(
        self,
        types: list[str] | None = None,
        doc_id: str | None = None,
        title: str | None = None,
    ) -> list[SingleJson]:
        """Return the catalogue rules matching a search filter.

        Args:
            types: The rule types to match, or None for any type.
            doc_id: The rule ID to match, or None for any rule.
            title: A substring of the title to match, or None for any title.

        Returns:
            The matching rules, in seeding order.

        """
        return [
            rule
            for rule in self.detection_rules
            if (not types or rule["type"] in types)
            and (doc_id is None or rule["id"] == doc_id)
            and (title is None or title.lower() in rule["title"].lower())
        ]

    def create_rule_job(self, kind: str, request: SingleJson) -> SingleJson:
        """Create an Auto Sigma or Auto YARA job and return its ID.

        A job is seeded with the result it will report; this only records the
        creation and hands back the ID the API assigns, so a test can seed a
        FINISHED, RUNNING or FAILED job under a known ID.

        Args:
            kind: `sigma` or `yara`.
            request: The creation request body.

        Returns:
            The `{"job_id": ...}` body the API answers with.

        """
        jobs = self.sigma_jobs if kind == "sigma" else self.yara_jobs
        self.rule_job_requests.append({"kind": kind, **request})
        job_id = next(iter(jobs), f"{kind}-job-1")
        return {"job_id": job_id}

    def set_sigma_job(self, job_id: str, record: SingleJson) -> None:
        """Make the Auto Sigma job endpoint return `record` for a job."""
        self.sigma_jobs[job_id] = record

    def set_yara_job(self, job_id: str, record: SingleJson) -> None:
        """Make the Auto YARA job endpoint return `record` for a job."""
        self.yara_jobs[job_id] = record

    def get_rule_job(self, kind: str, job_id: str) -> SingleJson | None:
        """Return the seeded rule generation job, or None."""
        jobs = self.sigma_jobs if kind == "sigma" else self.yara_jobs
        return jobs.get(job_id)

    def set_leaked_identity(self, key: str, record: SingleJson) -> None:
        """Make a credentials, hostname or IP lookup return `record` for `key`."""
        self.leaked_identities[key] = record

    def get_leaked_identities(self, keys: list[str]) -> list[SingleJson]:
        """Return the seeded exposures for the keys a lookup asked about.

        Args:
            keys: The subjects, hostnames or IPs requested.

        Returns:
            The seeded records, in request order. A key with nothing seeded is
            omitted, which is what the endpoint does for an unexposed one.

        """
        return [self.leaked_identities[key] for key in keys if key in self.leaked_identities]

    def set_credential_search(self, domain: str, results: list[SingleJson]) -> None:
        """Make `/identity/credentials/search` return `results` for a domain."""
        self.credential_search_results[domain] = results

    def get_credential_search(self, domains: list[str]) -> list[SingleJson]:
        """Return the seeded credentials for the domains a search asked about."""
        results = []
        for domain in domains:
            results.extend(self.credential_search_results.get(domain, []))
        return results

    def set_password_exposure(self, hash_prefix: str, record: SingleJson) -> None:
        """Make `/identity/password/lookup` return `record` for a hash."""
        self.password_exposures[hash_prefix] = record

    def get_password_exposures(self, hash_prefixes: list[str]) -> list[SingleJson]:
        """Return the seeded exposure status of each hash the API holds one for."""
        return [self.password_exposures[prefix] for prefix in hash_prefixes if prefix in self.password_exposures]

    def set_dump(self, name: str, record: SingleJson) -> None:
        """Make `/identity/metadata/dump/search` return `record` for a dump name."""
        self.dumps[name] = record

    def get_dumps(self, names: list[str]) -> list[SingleJson]:
        """Return the seeded dump metadata for the names a search asked about."""
        return [self.dumps[name] for name in names if name in self.dumps]

    def set_incident_report(self, source: str, record: SingleJson) -> None:
        """Make `/identity/incident/report` return `record` for a malware log."""
        self.incident_reports[source] = record

    def get_incident_report(self, source: str) -> SingleJson | None:
        """Return the seeded incident report, or None."""
        return self.incident_reports.get(source)

    def set_links(self, entity_id: str, record: SingleJson) -> None:
        """Make `/links/search` return `record` for one entity."""
        self.links[entity_id] = record

    def get_links(self, entity_ids: list[str]) -> list[SingleJson]:
        """Return the seeded links for the entities a search asked about."""
        return [self.links[entity_id] for entity_id in entity_ids if entity_id in self.links]
