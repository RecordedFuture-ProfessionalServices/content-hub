############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

from __future__ import annotations

from soar_sdk.SiemplifyDataModel import EntityTypes

PROVIDER_NAME = "RecordedFuture"
DEFAULT_DEVICE_VENDOR = "Recorded Future"
CLASSIC_ALERT_PRODUCT = "Recorded Future Classic Alert"
PLAYBOOK_ALERT_PRODUCT = "Recorded Future Playbook Alert"

# Actions name
PING_SCRIPT_NAME = "Ping"
DETONATE_FILE_SCRIPT_NAME = f"{PROVIDER_NAME} - Detonate File"
DETONATE_URL_SCRIPT_NAME = f"{PROVIDER_NAME} - Detonate URL"
ENRICH_CVE_SCRIPT_NAME = f"{PROVIDER_NAME} - Enrich CVE"
ENRICH_HASH_SCRIPT_NAME = f"{PROVIDER_NAME} - Enrich Hash"
ENRICH_HOST_SCRIPT_NAME = f"{PROVIDER_NAME} - Enrich Host"
ENRICH_IP_SCRIPT_NAME = f"{PROVIDER_NAME} - Enrich IP"
ENRICH_URL_SCRIPT_NAME = f"{PROVIDER_NAME} - Enrich URL"
ENRICH_IOC_SCRIPT_NAME = f"{PROVIDER_NAME} - Enrich IOC"
ENRICH_IOC_SOAR_SCRIPT_NAME = f"{PROVIDER_NAME} - Enrich IOCs Bulk"
SEARCH_HASH_SCRIPT_NAME = f"{PROVIDER_NAME} - Search Hash Malware Intelligence"
GET_ALERT_DETAILS_SCRIPT_NAME = f"{PROVIDER_NAME} - Get Alert Details"
GET_PBA_DETAILS_SCRIPT_NAME = f"{PROVIDER_NAME} - Get Playbook Alert Details"
ADD_ANALYST_NOTE_SCRIPT_NAME = f"{PROVIDER_NAME} - Add Analyst Note"
REFRESH_PBA_DETAILS_SCRIPT_NAME = f"{PROVIDER_NAME} - Refresh Playbook Alert"
UPDATE_ALERT_SCRIPT_NAME = f"{PROVIDER_NAME} - Update Alert"
UPDATE_PBA_SCRIPT_NAME = f"{PROVIDER_NAME} - Update Playbook Alert"

# Connector
CONNECTOR_NAME = "Recorded Future - Security Alerts Connector"
PLAYBOOK_ALERT_CONNECTOR_NAME = "Recorded Future - Playbook Alerts Connector"
PLAYBOOK_ALERT_TRACKING_CONNECTOR_NAME = "Recorded Future - Playbook Alerts Tracking Connector"
DEFAULT_TIME_FRAME = 0
CONNECTOR_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
CI_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_LIMIT = 100
PBA_SEVERITY_MAP = {"Informational": "Low", "Moderate": "Medium", "High": "High"}
PBA_SEVERITY_MAP_INTEGER = {"Informational": 0, "Moderate": 1, "High": 2}
SEVERITY_MAP = {"Low": 40, "Medium": 60, "High": 80, "Critical": 100}
STORED_IDS_LIMIT = 3000
ALERT_ID_FIELD = "id"
CSV_DELIMETER = ","

# Ping requirement
PING_IP = "8.8.8.8"

# Collective Insights
CI_DETECTION_TYPE = "playbook"
CI_INCIDENT_TYPE = "google-secops-threat-detection"

# Detection Rules
DETECTION_RULE_TYPES = ["yara", "snort", "sigma"]

# Enrichment
DEFAULT_THRESHOLD = 25
DEFAULT_SCORE = 0
SUPPORTED_ENTITY_TYPES_ENRICHMENT = [
    "URL",
    "ADDRESS",
    "FILEHASH",
    "CVE",
    "HOSTNAME",
    "DOMAIN",
]
SUPPORTED_ENTITY_TYPES_RELATED_ENTITIES = ["ADDRESS", "FILEHASH", "CVE", "HOSTNAME"]
ENRICHMENT_DATA_PREFIX = "RF"
ENTITY_TYPE_ENRICHMENT_MAP = {
    EntityTypes.ADDRESS: "ip",
    EntityTypes.DOMAIN: "domain",
    EntityTypes.HOSTNAME: "domain",
    EntityTypes.FILEHASH: "hash",
    EntityTypes.URL: "url",
    EntityTypes.CVE: "vulnerability",
}

ENTITY_IP = "entity_ips"
ENTITY_DOMAIN = "entity_domains"
ENTITY_EMAIL = "entity_emails"
ENTITY_HASH = "entity_hashes"
ENTITY_URL = "entity_urls"
ENTITY_VULN = "entity_vulns"

# Identity
DOMAIN_TYPES = ["Authorization", "Email"]

CLASSIC_ALERT_ENTITY_MAPPING = {
    "entity_ips": "IpAddress",
    "entity_domains": "InternetDomainName",
    "entity_emails": "EmailAddress",
    "entity_hashes": "Hash",
    "entity_urls": "URL",
    "entity_vulns": "CyberVulnerability",
}

TOPIC_MAP = {
    "None": None,
    "Actor Profile": "TXSFt2",
    "Analyst On-Demand Report": "VlIhvH",
    "Cyber Threat Analysis": "TXSFt1",
    "Flash Report": "TXSFt0",
    "Indicator": "TXSFt4",
    "Informational": "UrMRnT",
    "Malware/Tool Profile": "UX0YlU",
    "Source Profile": "UZmDut",
    "Threat Lead": "TXSFt3",
    "Validated Intelligence Event": "TXSFt5",
    "Weekly Threat Landscape": "VlIhvG",
    "YARA Rule": "VTrvnW",
}

LABEL_MAP = {
    "Domain Abuse": "domain_abuse",
    "Cyber Vulnerability": "cyber_vulnerability",
    "Data Leakage on Code Repository": "code_repo_leakage",
    "Third Party Risk": "third_party_risk",
    "Novel Identity Exposure": "identity_novel_exposures",
    "Geopolitics Facility": "geopolitics_facility",
}

ENTITY_PREFIX_TYPE_MAP = {
    "ip": EntityTypes.ADDRESS,
    "idn": EntityTypes.DOMAIN,
    "url": EntityTypes.URL,
    "hash": EntityTypes.FILEHASH,
    "email": EntityTypes.EMAILMESSAGE,
}

ENTITY_PREFIX_TYPE_MAP_LIST_OPS = {
    EntityTypes.ADDRESS: "ip",
    EntityTypes.DOMAIN: "idn",
    EntityTypes.HOSTNAME: "idn",
    EntityTypes.URL: "url",
    EntityTypes.FILEHASH: "hash",
    EntityTypes.EMAILMESSAGE: "email",
}

# Classic Alerts Connector
CLASSIC_ALERT_DEFAULT_STATUSES = ["New"]
CLASSIC_ALERT_STATUSES = ["New", "Pending", "Resolved", "Dismissed", "Flag for Tuning"]

# Alert Status Sync Jobs
CLASSIC_ALERT_SYNC_JOB_SCRIPT_NAME = "Recorded Future - Classic Alert Status Sync"
PLAYBOOK_ALERT_SYNC_JOB_SCRIPT_NAME = "Recorded Future - Playbook Alert Status Sync"
CLASSIC_ALERT_SYNC_CONTEXT_KEY = "recorded_future_classic_alert_status_sync"
PLAYBOOK_ALERT_SYNC_CONTEXT_KEY = "recorded_future_playbook_alert_status_sync"

# Suffix appended to a sync job's context identifier to store the per-alert sync
# state (last observed Recorded Future status, and whether the job closed the
# Google SecOps alert itself). This state is what prevents the two sync
# directions from re-triggering each other on every iteration.
SYNC_STATE_CONTEXT_SUFFIX = "_alert_state"
SYNC_STATE_STATUS_KEY = "recorded_future_status"
SYNC_STATE_CLOSED_BY_JOB_KEY = "closed_by_job"
SYNC_STATE_PRODUCT_ID_KEY = "recorded_future_alert_id"

# Recorded Future statuses that represent a terminal (closed) alert. Applies to
# both classic and playbook alerts.
SYNC_TERMINAL_STATUSES = frozenset({"Resolved", "Dismissed"})

# Status written back to Recorded Future when a Google SecOps alert or case is
# closed by an analyst.
SYNC_OUTBOUND_CLOSED_STATUS = "Resolved"

# Google SecOps alert status values that represent a closed alert.
SOAR_CLOSED_ALERT_STATUSES = frozenset({"close", "closed"})

SYNC_COMMENT_PREFIX = "[Recorded Future Status Sync]"
SYNC_DEFAULT_MAX_HOURS_BACKWARDS = 24
SYNC_MIN_HOURS_BACKWARDS = 1
SYNC_MAX_HOURS_BACKWARDS = 720
SYNC_DEFAULT_CLOSE_REASON = "Inconclusive"
SYNC_DEFAULT_CLOSE_ROOT_CAUSE = "No clear conclusion"
SYNC_CASE_CLOSE_REASON = "Closed by Recorded Future Status Sync"
SYNC_REOPEN_ALERT_ENDPOINT = "external/v1/dynamic-cases/ReopenAlert"
SYNC_REOPEN_CASE_ENDPOINT = "external/v1/cases/ExecuteBulkReopenCase"
SYNC_PRODUCT_FETCH_MAX_WORKERS = 10

# Playbook Alerts Connector
PLAYBOOK_ALERT_API_LIMIT = 200
PLAYBOOK_ALERT_CATEGORIES = [
    "domain_abuse",
    "cyber_vulnerability",
    "code_repo_leakage",
    "third_party_risk",
    "identity_novel_exposures",
    "geopolitics_facility",
    "malware_report",
]
PLAYBOOK_ALERT_STATUSES = ["New", "InProgress", "Resolved", "Dismissed"]
PLAYBOOK_ALERT_PRIORITIES = ["Informational", "Moderate", "High"]

DATETIME_ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DATETIME_READABLE_FORMAT = "%m/%d/%Y %H:%M:%S"

ENTITY_CHANGE_CASES = [
    "dns_change",
    "screenshot_mentions_change",
    "entities_change",
    "related_entities_change",
]

# HTML Text
INSIKT_VULNERABILITY_NOTE_HTML = """
<div class="note">
    <p><span class="label">Note Title:</span> {} [RecordedFutureIntelligence_Refresh Playbook Alert_1.JsonResult| "panel_evidence_summary_insikt_notes_1_title"]</p>
    <p><span class="label">Published:</span> <span id="note-published"> {} [RecordedFutureIntelligence_Refresh Playbook Alert_1.JsonResult| "panel_evidence_summary_insikt_notes_1_published"]</span></p>
    <p><span class="label">Topic:</span> {} [RecordedFutureIntelligence_Refresh Playbook Alert_1.JsonResult| "panel_evidence_summary_insikt_notes_1_topic"]</p>
    <p><span class="label">Fragment:</span> {} [RecordedFutureIntelligence_Refresh Playbook Alert_1.JsonResult| "panel_evidence_summary_insikt_notes_1_fragment"]</p>
    <p><span class="label">View Full Insikt Note:</span>
        <a href="https://app.recordedfuture.com/portal/research/insikt/{}" target="_blank" style="color: lightgrey;">
            https://app.recordedfuture.com/portal/research/insikt/{}
        </a>
    </p>
    <div class="divider"></div>
</div>
"""  # noqa: E501

# Sandbox Actions
SANDBOX_SLEEP = 30
SANDBOX_API_URLS = [
    "https://sandbox.recordedfuture.com",
    "https://private.tria.ge",
    "https://tria.ge",
]
DEFAULT_ACTION_CONTEXT = """{
    "submissions": {},
    "failed_extractions": {}
}"""
DEFAULT_TIMEOUT = 300
SANDBOX_TIMEOUT_THRESHOLD_IN_MIN = 1

FILE_SOURCE_BUCKET = "GCP Bucket"
FILE_SOURCE_FILESYSTEM = "Local File System"
INVALID_SAMPLE_TEXT = "<h2>No Samples detected in this report</h2>"
