############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Routes the Recorded Future API endpoints psengine calls to `RecordedFuture`.

Paths mirror `psengine.endpoints`; `MockSession` matches them with
`re.fullmatch` against the request path, so every pattern is anchored.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import TYPE_CHECKING, Any

from integration_testing import router
from integration_testing.request import MockRequest
from integration_testing.requests.response import MockResponse
from integration_testing.requests.session import MockSession, Response, RouteFunction

from .product import RecordedFuture

if TYPE_CHECKING:
    from collections.abc import Iterable

UNAUTHORIZED = MockResponse(content={"message": "Invalid token"}, status_code=401)


class BinaryResponse(MockResponse):
    """A response whose body is raw bytes rather than JSON.

    `MockResponse` JSON-encodes whatever content it is handed, which a
    screenshot's bytes cannot survive. This keeps them intact, so
    `response.content` is byte for byte what the API served.
    """

    def __init__(self, content: bytes, status_code: int = 200) -> None:
        """Initialise the response.

        Args:
            content: The raw body bytes.
            status_code: The HTTP status code.

        """
        super().__init__(content="", status_code=status_code)
        self._content = content


# The playbook alert URL segment is not always the category name: psengine
# posts a `cyber_vulnerability` alert to `/playbook-alert/vulnerability`. Every
# other category's segment matches its name.
URL_SEGMENT_TO_CATEGORY = {"vulnerability": "cyber_vulnerability"}


def request_params(request: MockRequest) -> dict:
    """Return a request's query parameters, or an empty dict when it has none.

    Args:
        request: The intercepted request.

    Returns:
        The query parameters.

    """
    return request.kwargs.get("params") or {}


def request_body(request: MockRequest) -> Any:
    """Decode a request's body.

    Deliberately not `integration_testing.common.get_request_payload`: that
    helper searches `("json", "payload", "params", "data")` in order and
    returns the first key *present*, and psengine passes an explicit
    `params=None` on every call, so it returns None before ever reaching the
    body. Only the two keys that can carry a body are consulted here, and
    psengine serialises its own payloads into `data` as a JSON string, so that
    is decoded too - leaving every route looking at decoded JSON.

    Args:
        request: The intercepted request.

    Returns:
        The decoded body, or an empty dict when there is no body to speak of.

    """
    for key in ("json", "data"):
        payload = request.kwargs.get(key)
        if payload is None:
            continue

        return json.loads(payload) if isinstance(payload, (str, bytes)) else payload

    return {}


class RecordedFutureSession(MockSession[MockRequest, MockResponse, RecordedFuture]):
    """The Recorded Future API, served from the in-memory product."""

    def get_routed_functions(self) -> Iterable[RouteFunction[Response]]:
        """Return every routed endpoint."""
        return [
            self.enrichment_lookup,
            self.collective_insights,
            self.soar_enrichment,
            self.hash_reports,
            self.classic_alert_rules,
            self.classic_alert_update,
            self.classic_alert_search,
            self.classic_alert_fetch,
            self.analyst_note_publish,
            # Registered ahead of the category routes, whose patterns would
            # otherwise swallow `search` and `common` as category names.
            self.playbook_alert_search,
            self.playbook_alert_common,
            self.playbook_alert_update,
            self.playbook_alert_domain_abuse_image,
            self.playbook_alert_image,
            self.playbook_alert_by_id,
            self.playbook_alert_bulk,
            self.list_create,
            self.list_search,
            self.list_info,
            self.list_entities,
            self.list_status,
            self.list_entity_operation,
            self.entity_match,
            self.entity_lookup,
            self.detection_rule_search,
            self.auto_sigma_create,
            self.auto_sigma_job,
            self.auto_yara_create,
            self.auto_yara_job,
            self.identity_credentials_lookup,
            self.identity_credentials_search,
            self.identity_hostname_lookup,
            self.identity_ip_lookup,
            self.identity_password_lookup,
            self.identity_dump_search,
            self.identity_incident_report,
            self.links_search,
        ]

    def _paged(self, results: list, key: str) -> MockResponse:
        """Wrap results the way psengine's paged POST reader expects them.

        `RFClient.request_paged` reads `counts` to decide whether to ask for
        another page, and looks for `next_offset` first. Reporting every result
        as one page is what an unpaged answer looks like to it.

        Args:
            results: The results to return.
            key: The body key they belong under.

        Returns:
            The response.

        """
        return MockResponse(
            content={
                key: results,
                "counts": {"returned": len(results), "total": len(results)},
            },
            status_code=200,
        )

    @router.get(r"/v2/(?:ip|domain|hash|url|vulnerability|malware)/.+")
    def enrichment_lookup(self, request: MockRequest) -> MockResponse:
        """`/v2/{entity_type}/{entity}` - single entity enrichment."""
        if not self._product.authorized:
            return UNAUTHORIZED

        # psengine percent-encodes the entity, so a URL arrives as one path segment.
        _, _, entity_type, entity = request.url.path.split("/", 3)
        record = self._product.get_enrichment(entity_type, urllib.parse.unquote(entity))
        if record is None:
            return MockResponse(content={}, status_code=404)

        return MockResponse(content={"data": record}, status_code=200)

    @router.post(r"/collective-insights/detections")
    def collective_insights(self, request: MockRequest) -> MockResponse:
        """`/collective-insights/detections` - detection submission."""
        if not self._product.collective_insights_available:
            return MockResponse(content={"message": "Service unavailable"}, status_code=503)

        body = request_body(request)
        self._product.add_collective_insights(body)
        # The endpoint echoes `debug` back and counts what it processed per IOC
        # type; psengine requires both, so the submission has to be read to
        # answer it.
        processed = {"ip": 0, "domain": 0, "hash": 0, "vulnerability": 0, "url": 0}
        for detection in body.get("data") or []:
            ioc_type = detection["ioc"]["type"]
            processed[ioc_type] = processed.get(ioc_type, 0) + 1

        return MockResponse(
            content={
                "result": {
                    "status": "ok",
                    "debug": bool((body.get("options") or {}).get("debug")),
                    "summary": {"processed": processed},
                },
            },
            status_code=200,
        )

    @router.post(r"/soar/v3/enrichment")
    def soar_enrichment(self, request: MockRequest) -> MockResponse:
        """`/soar/v3/enrichment` - bulk entity enrichment."""
        if not self._product.authorized:
            return UNAUTHORIZED

        requested = request_body(request)
        records = self._product.get_soar_enrichment(requested)
        return MockResponse(content={"data": {"results": records}}, status_code=200)

    @router.post(r"/malware-intelligence/v1/reports")
    def hash_reports(self, request: MockRequest) -> MockResponse:
        """`/malware-intelligence/v1/reports` - sandbox reports for a sample."""
        if not self._product.authorized:
            return UNAUTHORIZED

        sha256 = request_body(request).get("sha256", "")
        return MockResponse(
            content={"reports": self._product.get_hash_reports(sha256)},
            status_code=200,
        )

    @router.get(r"/v2/alert/rule")
    def classic_alert_rules(self, request: MockRequest) -> MockResponse:
        """`/v2/alert/rule` - the alert rule catalogue."""
        if not self._product.authorized:
            return UNAUTHORIZED

        rules = self._product.search_alert_rules(request_params(request).get("freetext"))
        return MockResponse(
            content={
                "data": {
                    "results": rules,
                    "counts": {"returned": len(rules), "total": len(rules)},
                },
            },
            status_code=200,
        )

    @router.post(r"/v2/alert/update")
    def classic_alert_update(self, request: MockRequest) -> MockResponse:
        """`/v2/alert/update` - status, assignee and note updates."""
        if not self._product.authorized:
            return UNAUTHORIZED

        for update in request_body(request):
            self._product.add_alert_update(update)

        return MockResponse(content={"success": True}, status_code=200)

    # Anchored ahead of `classic_alert_fetch`: psengine searches against the
    # collection URL, which is the fetch URL with an empty ID.
    @router.get(r"/v3/alerts/")
    def classic_alert_search(self, request: MockRequest) -> MockResponse:
        """`/v3/alerts/` - search for alerts by rule and status."""
        if not self._product.authorized:
            return UNAUTHORIZED

        params = request_params(request)
        hits = self._product.search_classic_alerts(
            status=params.get("statusInPortal"),
            rule_id=params.get("alertRule"),
        )
        return MockResponse(
            content={"data": hits, "counts": {"returned": len(hits), "total": len(hits)}},
            status_code=200,
        )

    @router.get(r"/v3/alerts/(?P<alert_id>[^/]+)")
    def classic_alert_fetch(self, request: MockRequest) -> MockResponse:
        """`/v3/alerts/{id}` - a single classic alert."""
        if not self._product.authorized:
            return UNAUTHORIZED

        alert_id = request.url.path.rsplit("/", 1)[-1]
        record = self._product.get_classic_alert(urllib.parse.unquote(alert_id))
        if record is None:
            return MockResponse(content={}, status_code=404)

        return MockResponse(content={"data": record}, status_code=200)

    @router.post(r"/analyst-note/publish")
    def analyst_note_publish(self, request: MockRequest) -> MockResponse:
        """`/analyst-note/publish` - publish a note."""
        if not self._product.authorized:
            return UNAUTHORIZED

        payload = request_body(request)
        self._product.add_published_note(payload)
        return MockResponse(
            content={"document_id": "doc:published", "note_id": "note:published"},
            status_code=200,
        )

    @router.post(r"/playbook-alert/search")
    def playbook_alert_search(self, request: MockRequest) -> MockResponse:
        """`/playbook-alert/search` - find alerts matching a filter."""
        if not self._product.authorized:
            return UNAUTHORIZED

        body = request_body(request)
        hits = self._product.search_playbook_alerts(
            categories=body.get("category") or [],
            statuses=body.get("statuses"),
            priorities=body.get("priority"),
        )
        return MockResponse(
            content={"data": hits, "counts": {"total": len(hits), "returned": len(hits)}},
            status_code=200,
        )

    @router.get(r"/playbook-alert/common/(?P<alert_id>.+)")
    def playbook_alert_common(self, request: MockRequest) -> MockResponse:
        """`/playbook-alert/common/{id}` - the category of an alert.

        psengine calls this to discover an alert's category when `fetch` is not
        told one, so it has to find the alert without knowing its category.
        """
        if not self._product.authorized:
            return UNAUTHORIZED

        alert_id = urllib.parse.unquote(request.url.path.rsplit("/", 1)[-1])
        for (category, seeded_id), record in self._product.playbook_alerts.items():
            if seeded_id == alert_id:
                return MockResponse(
                    content={
                        "data": {
                            "playbook_alert_id": alert_id,
                            "category": category,
                            "priority": record["priority"],
                        },
                    },
                    status_code=200,
                )

        return MockResponse(content={}, status_code=404)

    @router.put(r"/playbook-alert/common/(?P<alert_id>.+)")
    def playbook_alert_update(self, request: MockRequest) -> MockResponse:
        """`/playbook-alert/common/{id}` - update one alert's fields."""
        if not self._product.authorized:
            return UNAUTHORIZED

        alert_id = urllib.parse.unquote(request.url.path.rsplit("/", 1)[-1])
        self._product.add_playbook_alert_update({"id": alert_id, **request_body(request)})
        return MockResponse(
            content={"status": {"status_code": "Ok", "status_message": "Updated"}},
            status_code=200,
        )

    # Domain Abuse serves its images under the alert, unlike every other
    # category, so it needs its own pattern ahead of the shared one.
    @router.get(r"/playbook-alert/domain_abuse/(?P<alert_id>[^/]+)/image/(?P<image_id>.+)")
    def playbook_alert_domain_abuse_image(self, request: MockRequest) -> MockResponse:
        """`/playbook-alert/domain_abuse/{id}/image/{image_id}` - a screenshot."""
        return self._serve_screenshot(request)

    @router.get(r"/playbook-alert/(?P<category>[^/]+)/image/(?P<image_id>.+)")
    def playbook_alert_image(self, request: MockRequest) -> MockResponse:
        """`/playbook-alert/{category}/image/{image_id}` - a screenshot."""
        return self._serve_screenshot(request)

    def _serve_screenshot(self, request: MockRequest) -> MockResponse:
        """Serve the seeded bytes for the image ID in a request's path.

        Args:
            request: The intercepted request.

        Returns:
            The image bytes, or a 404 for an image the API will not serve.

        """
        if not self._product.authorized:
            return UNAUTHORIZED

        image_id = request.url.path.split("/image/", 1)[-1]
        content = self._product.get_screenshot(urllib.parse.unquote(image_id))
        if content is None:
            return MockResponse(content={}, status_code=404)

        return BinaryResponse(content=content, status_code=200)

    @router.post(r"/playbook-alert/(?P<category>[^/]+)/(?P<alert_id>.+)")
    def playbook_alert_by_id(self, request: MockRequest) -> MockResponse:
        """`/playbook-alert/{category}/{id}` - fetch one alert."""
        if not self._product.authorized:
            return UNAUTHORIZED

        _, _, segment, alert_id = request.url.path.split("/", 3)
        category = URL_SEGMENT_TO_CATEGORY.get(segment, segment)
        record = self._product.get_playbook_alert(category, urllib.parse.unquote(alert_id))
        if record is None:
            return MockResponse(content={}, status_code=404)

        return MockResponse(
            content={"status": {"status_code": "Ok"}, "data": record},
            status_code=200,
        )

    @router.post(r"/list/create")
    def list_create(self, request: MockRequest) -> MockResponse:
        """`/list/create` - create a list."""
        if not self._product.authorized:
            return UNAUTHORIZED

        body = request_body(request)
        record = self._product.create_entity_list(body.get("name"), body.get("type"))
        return MockResponse(content=record, status_code=200)

    @router.post(r"/list/search")
    def list_search(self, request: MockRequest) -> MockResponse:
        """`/list/search` - find lists by name and type."""
        if not self._product.authorized:
            return UNAUTHORIZED

        body = request_body(request)
        records = self._product.search_entity_lists(body.get("name"), body.get("type"))
        return MockResponse(content=records, status_code=200)

    @router.get(r"/list/(?P<list_id>[^/]+)/info")
    def list_info(self, request: MockRequest) -> MockResponse:
        """`/list/{id}/info` - one list's details."""
        if not self._product.authorized:
            return UNAUTHORIZED

        record = self._product.get_entity_list(self._list_id(request))
        if record is None:
            return MockResponse(content={}, status_code=404)

        return MockResponse(content=record, status_code=200)

    @router.get(r"/list/(?P<list_id>[^/]+)/entities")
    def list_entities(self, request: MockRequest) -> MockResponse:
        """`/list/{id}/entities` - a list's members."""
        if not self._product.authorized:
            return UNAUTHORIZED

        return MockResponse(
            content=self._product.get_list_entities(self._list_id(request)),
            status_code=200,
        )

    @router.get(r"/list/(?P<list_id>[^/]+)/status")
    def list_status(self, request: MockRequest) -> MockResponse:
        """`/list/{id}/status` - a list's size and build status."""
        if not self._product.authorized:
            return UNAUTHORIZED

        status = self._product.get_list_status(self._list_id(request))
        if status is None:
            return MockResponse(content={}, status_code=404)

        return MockResponse(content=status, status_code=200)

    @router.post(r"/list/(?P<list_id>[^/]+)/entity/(?P<operation>add|remove)")
    def list_entity_operation(self, request: MockRequest) -> MockResponse:
        """`/list/{id}/entity/{add,remove}` - change one list membership."""
        if not self._product.authorized:
            return UNAUTHORIZED

        _, _, list_id, _, operation = request.url.path.split("/", 4)
        # The API reports the operation in its past tense.
        past_tense = "added" if operation.endswith("add") else "removed"
        result = self._product.add_list_operation(
            urllib.parse.unquote(list_id),
            past_tense,
            request_body(request)["entity"]["id"],
        )
        return MockResponse(content={"result": result}, status_code=200)

    @staticmethod
    def _list_id(request: MockRequest) -> str:
        """Return the list ID out of a `/list/{id}/...` path."""
        return urllib.parse.unquote(request.url.path.split("/")[2])

    @router.post(r"/entity-match/match")
    def entity_match(self, request: MockRequest) -> MockResponse:
        """`/entity-match/match` - resolve a name to Recorded Future entities."""
        if not self._product.authorized:
            return UNAUTHORIZED

        body = request_body(request)
        matches = self._product.get_entity_matches(body.get("name", ""))
        types = body.get("type") or []
        if types:
            matches = [match for match in matches if match.get("type") in types]

        return MockResponse(content=matches[: body.get("limit") or len(matches)], status_code=200)

    @router.get(r"/entity-match/entity/(?P<entity_id>.+)")
    def entity_lookup(self, request: MockRequest) -> MockResponse:
        """`/entity-match/entity/{id}` - one entity's details."""
        if not self._product.authorized:
            return UNAUTHORIZED

        entity_id = urllib.parse.unquote(request.url.path.rsplit("/", 1)[-1])
        record = self._product.get_entity_lookup(entity_id)
        if record is None:
            return MockResponse(content={}, status_code=404)

        return MockResponse(content={"data": record}, status_code=200)

    @router.post(r"/detection-rule/search")
    def detection_rule_search(self, request: MockRequest) -> MockResponse:
        """`/detection-rule/search` - find detection rules."""
        if not self._product.authorized:
            return UNAUTHORIZED

        filters = request_body(request).get("filter") or {}
        rules = self._product.search_detection_rules(
            types=filters.get("types"),
            doc_id=filters.get("doc_id"),
            title=filters.get("title"),
        )
        return self._paged(rules, "result")

    @router.post(r"/malware-intelligence/v1/auto-sigma/jobs")
    def auto_sigma_create(self, request: MockRequest) -> MockResponse:
        """`/malware-intelligence/v1/auto-sigma/jobs` - start a Sigma rule job."""
        if not self._product.authorized:
            return UNAUTHORIZED

        return MockResponse(
            content=self._product.create_rule_job("sigma", request_body(request)),
            status_code=200,
        )

    @router.get(r"/malware-intelligence/v1/auto-sigma/jobs/(?P<job_id>.+)")
    def auto_sigma_job(self, request: MockRequest) -> MockResponse:
        """`/malware-intelligence/v1/auto-sigma/jobs/{id}` - a Sigma job's result."""
        return self._serve_rule_job(request, "sigma")

    @router.post(r"/malware-intelligence/v1/auto-yara/jobs")
    def auto_yara_create(self, request: MockRequest) -> MockResponse:
        """`/malware-intelligence/v1/auto-yara/jobs` - start a YARA rule job."""
        if not self._product.authorized:
            return UNAUTHORIZED

        return MockResponse(
            content=self._product.create_rule_job("yara", request_body(request)),
            status_code=200,
        )

    @router.get(r"/malware-intelligence/v1/auto-yara/jobs/(?P<job_id>.+)")
    def auto_yara_job(self, request: MockRequest) -> MockResponse:
        """`/malware-intelligence/v1/auto-yara/jobs/{id}` - a YARA job's result."""
        return self._serve_rule_job(request, "yara")

    def _serve_rule_job(self, request: MockRequest, kind: str) -> MockResponse:
        """Serve the seeded result of a rule generation job.

        Args:
            request: The intercepted request.
            kind: `sigma` or `yara`.

        Returns:
            The job record, or a 404 for a job the API has never seen.

        """
        if not self._product.authorized:
            return UNAUTHORIZED

        job_id = urllib.parse.unquote(request.url.path.rsplit("/", 1)[-1])
        record = self._product.get_rule_job(kind, job_id)
        if record is None:
            return MockResponse(content={}, status_code=404)

        return MockResponse(content=record, status_code=200)

    @router.post(r"/identity/credentials/lookup")
    def identity_credentials_lookup(self, request: MockRequest) -> MockResponse:
        """`/identity/credentials/lookup` - exposures for known subjects."""
        if not self._product.authorized:
            return UNAUTHORIZED

        subjects = request_body(request).get("subjects") or []
        return self._paged(self._product.get_leaked_identities(subjects), "identities")

    @router.post(r"/identity/credentials/search")
    def identity_credentials_search(self, request: MockRequest) -> MockResponse:
        """`/identity/credentials/search` - exposed logins under a domain."""
        if not self._product.authorized:
            return UNAUTHORIZED

        domains = request_body(request).get("domains") or []
        return self._paged(self._product.get_credential_search(domains), "identities")

    @router.post(r"/identity/hostname/lookup")
    def identity_hostname_lookup(self, request: MockRequest) -> MockResponse:
        """`/identity/hostname/lookup` - exposures tied to a hostname."""
        if not self._product.authorized:
            return UNAUTHORIZED

        # The endpoint takes one hostname, not a list.
        hostname = request_body(request).get("hostname")
        return self._paged(
            self._product.get_leaked_identities([hostname] if hostname else []),
            "identities",
        )

    @router.post(r"/identity/ip/lookup")
    def identity_ip_lookup(self, request: MockRequest) -> MockResponse:
        """`/identity/ip/lookup` - exposures tied to an IP."""
        if not self._product.authorized:
            return UNAUTHORIZED

        # As with the hostname lookup, one IP rather than a list.
        ip = request_body(request).get("ip")
        return self._paged(
            self._product.get_leaked_identities([ip] if ip else []),
            "identities",
        )

    @router.post(r"/identity/password/lookup")
    def identity_password_lookup(self, request: MockRequest) -> MockResponse:
        """`/identity/password/lookup` - how exposed a password hash is."""
        if not self._product.authorized:
            return UNAUTHORIZED

        passwords = request_body(request).get("passwords") or []
        prefixes = [password["hash_prefix"] for password in passwords]
        return MockResponse(
            content={"results": self._product.get_password_exposures(prefixes)},
            status_code=200,
        )

    @router.post(r"/identity/metadata/dump/search")
    def identity_dump_search(self, request: MockRequest) -> MockResponse:
        """`/identity/metadata/dump/search` - metadata about named dumps."""
        if not self._product.authorized:
            return UNAUTHORIZED

        names = request_body(request).get("names") or []
        return MockResponse(
            content={"dumps": self._product.get_dumps(names)},
            status_code=200,
        )

    @router.post(r"/identity/incident/report")
    def identity_incident_report(self, request: MockRequest) -> MockResponse:
        """`/identity/incident/report` - one malware log's exposure report."""
        if not self._product.authorized:
            return UNAUTHORIZED

        report = self._product.get_incident_report(request_body(request).get("source", ""))
        if report is None:
            return MockResponse(content={}, status_code=404)

        return MockResponse(
            content={
                **report,
                "counts": {
                    "returned": len(report.get("credentials", [])),
                    "total": len(report.get("credentials", [])),
                },
            },
            status_code=200,
        )

    @router.post(r"/links/search")
    def links_search(self, request: MockRequest) -> MockResponse:
        """`/links/search` - the links known for one or more entities."""
        if not self._product.authorized:
            return UNAUTHORIZED

        entities = request_body(request).get("entities") or []
        return MockResponse(
            content={"data": self._product.get_links(entities)},
            status_code=200,
        )

    @router.post(r"/playbook-alert/(?P<category>[^/]+)")
    def playbook_alert_bulk(self, request: MockRequest) -> MockResponse:
        """`/playbook-alert/{category}` - fetch several alerts of one category.

        Distinguished from a single fetch only by the absence of an ID in the
        path; the IDs to return arrive in the body.
        """
        if not self._product.authorized:
            return UNAUTHORIZED

        segment = request.url.path.rsplit("/", 1)[-1]
        category = URL_SEGMENT_TO_CATEGORY.get(segment, segment)
        alert_ids = request_body(request).get("playbook_alert_ids") or []
        records = self._product.get_playbook_alerts_bulk(category, list(alert_ids))
        return MockResponse(
            content={"status": {"status_code": "Ok"}, "data": records},
            status_code=200,
        )
