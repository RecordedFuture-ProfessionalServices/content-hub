############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

from __future__ import annotations

from datetime import datetime, timezone

from psengine.collective_insights import CollectiveInsights, CollectiveInsightsError
from psengine.config import Config
from pydantic import ValidationError
from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyUtils import output_handler
from TIPCommon.extraction import extract_action_param, extract_configuration_param

from ..core.constants import (
    CI_DETECTION_TYPE,
    CI_DETECTION_TYPE_RULE,
    CI_TIMESTAMP_FORMAT,
    ENTITY_TYPE_ENRICHMENT_MAP,
    PROVIDER_NAME,
    SUBMIT_CI_SCRIPT_NAME,
)
from ..core.version import __version__ as version


def clean_input(input_str: str | None) -> str | None:
    """
    Normalizes an action parameter, mapping the 'None' ddl option and empty
    strings onto a real None so they are omitted from the insight.
    """
    if input_str is None:
        return None
    stripped = input_str.strip()
    return None if stripped in ("", "None") else stripped


def split_csv(input_str: str | None) -> list[str] | None:
    """
    Splits a comma separated action parameter into a list of trimmed values.
    Returns None when nothing usable was supplied, so the field is omitted.
    """
    cleaned = clean_input(input_str)
    if not cleaned:
        return None
    values = [value.strip() for value in cleaned.split(",") if value.strip()]
    return values or None


def map_secops_entities_to_iocs(entities: list) -> tuple[list[tuple[str, str]], list[dict]]:
    """
    Maps SecOps case target entities onto the IOC types supported by the
    Recorded Future Collective Insights API (ip, domain, hash, url, vulnerability).

    Returns
    -------
        iocs (list[tuple[str, str]]): (ioc_value, ioc_type) pairs to submit
        skipped (list[dict]): entities whose type has no Collective Insights equivalent
    """
    iocs = []
    skipped = []
    for entity in entities:
        ioc_type = ENTITY_TYPE_ENRICHMENT_MAP.get(entity.entity_type)
        if ioc_type:
            iocs.append((entity.identifier, ioc_type))
        else:
            skipped.append({"identifier": entity.identifier, "entity_type": entity.entity_type})
    return iocs, skipped


@output_handler
def main() -> None:
    siemplify = SiemplifyAction()
    siemplify.script_name = SUBMIT_CI_SCRIPT_NAME

    api_key = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="ApiKey",
    )
    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Verify SSL",
        default_value=False,
        input_type=bool,
    )
    detection_type = extract_action_param(
        siemplify,
        param_name="Detection Type",
        default_value=CI_DETECTION_TYPE,
        print_value=True,
    )
    detection_sub_type = extract_action_param(
        siemplify,
        param_name="Detection Sub Type",
        is_mandatory=False,
        print_value=True,
    )
    detection_id = extract_action_param(
        siemplify,
        param_name="Detection ID",
        is_mandatory=False,
        print_value=True,
    )
    detection_name = extract_action_param(
        siemplify,
        param_name="Detection Name",
        is_mandatory=False,
        print_value=True,
    )
    incident_id = extract_action_param(
        siemplify,
        param_name="Incident ID",
        is_mandatory=False,
        print_value=True,
    )
    incident_name = extract_action_param(
        siemplify,
        param_name="Incident Name",
        is_mandatory=False,
        print_value=True,
    )
    incident_type = extract_action_param(
        siemplify,
        param_name="Incident Type",
        is_mandatory=False,
        print_value=True,
    )
    timestamp = extract_action_param(
        siemplify,
        param_name="Timestamp",
        is_mandatory=False,
        print_value=True,
    )
    ioc_field = extract_action_param(
        siemplify,
        param_name="IOC Field",
        is_mandatory=False,
        print_value=True,
    )
    ioc_source_type = extract_action_param(
        siemplify,
        param_name="IOC Source Type",
        is_mandatory=False,
        print_value=True,
    )
    mitre_codes = extract_action_param(
        siemplify,
        param_name="MITRE Codes",
        is_mandatory=False,
        print_value=True,
    )
    malwares = extract_action_param(
        siemplify,
        param_name="Malware",
        is_mandatory=False,
        print_value=True,
    )
    organization_ids = extract_action_param(
        siemplify,
        param_name="Organization IDs",
        is_mandatory=False,
        print_value=True,
    )
    debug = extract_action_param(
        siemplify,
        param_name="Debug",
        default_value=False,
        input_type=bool,
        print_value=True,
    )

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    is_success = True
    output_message = ""
    status = EXECUTION_STATE_COMPLETED

    detection_type = clean_input(detection_type) or CI_DETECTION_TYPE
    detection_sub_type = clean_input(detection_sub_type)
    detection_id = clean_input(detection_id)
    detection_name = clean_input(detection_name)
    incident_id = clean_input(incident_id)
    incident_name = clean_input(incident_name)
    incident_type = clean_input(incident_type)
    ioc_field = clean_input(ioc_field)
    ioc_source_type = clean_input(ioc_source_type)
    mitre_codes = split_csv(mitre_codes)
    malwares = split_csv(malwares)
    organization_ids = split_csv(organization_ids)

    # The source event timestamp is what Recorded Future records as the detection
    # time. Fall back to the action run time when the source tool did not supply one.
    timestamp = clean_input(timestamp) or datetime.now(timezone.utc).strftime(CI_TIMESTAMP_FORMAT)

    iocs, skipped = map_secops_entities_to_iocs(siemplify.target_entities)
    if skipped:
        siemplify.LOGGER.info(
            f"Skipping {len(skipped)} target entities with no Collective Insights IOC type: "
            f"{[entity['identifier'] for entity in skipped]}",
        )

    try:
        if not iocs:
            raise ValueError(
                "No supported target entities found in the case. Collective Insights "
                "accepts IP, domain, hostname, hash, URL and CVE entities.",
            )
        if detection_type == CI_DETECTION_TYPE_RULE and not (detection_id and detection_sub_type):
            raise ValueError(
                "Detection ID and Detection Sub Type are mandatory when Detection Type "
                "is 'detection_rule'.",
            )

        siemplify.LOGGER.info("Initializing psengine configuration")
        Config.init(
            client_verify_ssl=verify_ssl,
            rf_token=api_key,
            app_id=f"ps-google-soar/{version}",
        )
        siemplify.LOGGER.info("Initializing psengine CollectiveInsights")
        collective_insights = CollectiveInsights()

        siemplify.LOGGER.info(f"Building {len(iocs)} insights from case target entities")
        insights = [
            collective_insights.create(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                timestamp=timestamp,
                detection_type=detection_type,
                detection_sub_type=detection_sub_type,
                detection_id=detection_id,
                detection_name=detection_name,
                ioc_field=ioc_field,
                ioc_source_type=ioc_source_type,
                incident_id=incident_id,
                incident_name=incident_name,
                incident_type=incident_type,
                mitre_codes=mitre_codes,
                malwares=malwares,
            )
            for ioc_value, ioc_type in iocs
        ]

        siemplify.LOGGER.info(f"Submitting {len(insights)} insights to Recorded Future")
        submit_resp = collective_insights.submit(
            insight=insights,
            debug=debug,
            organization_ids=organization_ids,
        )
        siemplify.LOGGER.info(f"Collective Insights submission response: {submit_resp.result}")

        data = submit_resp.json()
        data["submitted_insights"] = [insight.json() for insight in insights]
        data["skipped_entities"] = skipped
        siemplify.result.add_result_json(data)

        output_message += (
            f"Successfully submitted {len(insights)} detections to Recorded Future "
            f"Collective Insights."
        )
        if debug:
            output_message += " Submission was sent in debug mode."
        if skipped:
            output_message += (
                f"\nSkipped {len(skipped)} target entities with an unsupported entity type."
            )

    except ValueError as err:
        output_message = f"Collective Insights ValueError: {err}"
        siemplify.LOGGER.error(output_message)
        is_success = False
        status = EXECUTION_STATE_FAILED
    except ValidationError as err:
        output_message = f"Error with Collective Insights parameters: {err}"
        siemplify.LOGGER.error(output_message)
        is_success = False
        status = EXECUTION_STATE_FAILED
    except CollectiveInsightsError as err:
        output_message = f"Error submitting to Collective Insights: {err}"
        siemplify.LOGGER.error(output_message)
        is_success = False
        status = EXECUTION_STATE_FAILED
    except Exception as err:
        output_message = f"Error executing Submit Collective Insights action: {err}"
        siemplify.LOGGER.error(output_message)
        is_success = False
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        f"\n  status: {status}\n  is_success: {is_success}\n  output_message: {output_message}",
    )
    siemplify.end(output_message, is_success, status)


if __name__ == "__main__":
    main()
