############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

from __future__ import annotations

from psengine.config import Config
from psengine.entity_match import EntityMatchMgr, MatchApiError
from pydantic import ValidationError
from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyUtils import output_handler
from TIPCommon.extraction import extract_action_param, extract_configuration_param
from TIPCommon.validation import ParameterValidator

from ..core.constants import (
    CSV_DELIMETER,
    ENTITY_MATCH_SCRIPT_NAME,
    PROVIDER_NAME,
)
from ..core.version import __version__ as version


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENTITY_MATCH_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    param_validator = ParameterValidator(siemplify=siemplify)

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
    entity_name = extract_action_param(
        siemplify,
        param_name="Entity Name",
        input_type=str,
        print_value=True,
    )
    entity_type = param_validator.validate_csv(
        param_name="playbook_alert_categories",
        csv_string=extract_action_param(
            siemplify,
            param_name="Entity Type",
            input_type=str,
            print_value=True,
        ),
        delimiter=CSV_DELIMETER,
    )
    limit = extract_action_param(
        siemplify,
        param_name="Limit",
        input_type=int,
    )

    is_success = False
    status = EXECUTION_STATE_FAILED
    output_message = "Failed running Entity Match action"

    try:
        Config.init(
            client_verify_ssl=verify_ssl,
            rf_token=api_key,
            app_id=f"ps-google-soar/{version}",
        )
        entity_match_mgr = EntityMatchMgr()
        results = entity_match_mgr.match(
            entity_name=entity_name, entity_type=entity_type, limit=int(limit)
        )

        matched = [entity.model_dump() for entity in results if entity.is_found]
        not_matched = [entity.model_dump() for entity in results if not entity.is_found]
        siemplify.LOGGER.info()
        siemplify.result.add_result_json({
            "matched": matched,
            "not_matched": not_matched,
        })

        is_success = True
        status = EXECUTION_STATE_COMPLETED
        output_message = (
            f"Successfully matched {len(matched)} entites."
            f"\nDid not match {len(not_matched)} entities."
        )
    except ValueError as err:
        siemplify.LOGGER.error(f"Error creating Entity Match Manager {err}")
        is_success = False
    except ValidationError as err:
        siemplify.LOGGER.error(f"Invalid parameters for Entity Match action {err}")
        is_success = False
    except MatchApiError as err:
        siemplify.LOGGER.error(f"Error calling Entity Match API {err}")
        is_success = False
    except Exception as e:
        siemplify.LOGGER.error(
            f"General error performing action {ENTITY_MATCH_SCRIPT_NAME}",
        )
        siemplify.LOGGER.exception(e)
        is_success = False

    siemplify.LOGGER.info("\n----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.LOGGER.info(f"Result: {is_success}")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.end(output_message, is_success, status)


if __name__ == "__main__":
    main()
