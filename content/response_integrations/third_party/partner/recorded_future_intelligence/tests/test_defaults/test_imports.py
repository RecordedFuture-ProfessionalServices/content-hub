############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Verifies that every job in the integration imports cleanly.

A job that fails to import fails at schedule time in Google SecOps with no
useful diagnostics, so this catches the mistake in CI instead.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest
from TIPCommon.utils import camel_to_snake_case

JOBS_DIR = Path(__file__).resolve().parents[2] / "jobs"
JOB_MODULES = sorted(path.stem for path in JOBS_DIR.glob("*.py") if path.stem != "__init__")


def test_jobs_directory_is_discovered() -> None:
    """Guard against the glob silently matching nothing."""
    assert JOB_MODULES


@pytest.mark.parametrize("module_name", JOB_MODULES)
def test_job_module_imports(module_name: str) -> None:
    """Each job module imports and exposes a `main` entry point."""
    module = importlib.import_module(
        f"recorded_future_intelligence.jobs.{module_name}",
    )

    assert callable(module.main)


@pytest.mark.parametrize("module_name", JOB_MODULES)
def test_job_module_has_a_definition_file(module_name: str) -> None:
    """Each job script has the YAML definition Google SecOps needs to install it."""
    assert (JOBS_DIR / f"{module_name}.yaml").is_file()


# PyYAML is not a dependency of this integration, and adding one just to read
# our own job definitions is not worth it. Parameter names are the only thing
# these tests need, and they are the sole users of a leading-dash "name:" key.
PARAMETER_NAME_PATTERN = re.compile(r"^-\s+name:\s*(\S.*?)\s*$", re.MULTILINE)


def declared_parameter_names(module_name: str) -> set[str]:
    """Read the parameter names out of a job definition.

    Args:
        module_name (str): The job module stem.

    Returns:
        set[str]: The parameter names the definition declares.

    """
    definition = (JOBS_DIR / f"{module_name}.yaml").read_text(encoding="utf-8")
    return set(PARAMETER_NAME_PATTERN.findall(definition))


@pytest.mark.parametrize("module_name", JOB_MODULES)
def test_parameter_names_are_discovered(module_name: str) -> None:
    """Guard against the pattern silently matching nothing."""
    assert declared_parameter_names(module_name)


@pytest.mark.parametrize("module_name", JOB_MODULES)
def test_sync_job_declares_the_parameters_the_base_class_reads(
    module_name: str,
) -> None:
    """`BaseSyncJob` reads these two parameters, so every sync job must declare them.

    Omitting either one fails only at runtime, inside Google SecOps.
    """
    assert {"Environment Name", "Max Hours Backwards"} <= declared_parameter_names(
        module_name,
    )


@pytest.mark.parametrize("module_name", JOB_MODULES)
def test_job_parameter_names_snake_case_as_expected(module_name: str) -> None:
    """Pin the attribute names `Job._extract_job_params` derives from the YAML.

    `camel_to_snake_case` strips spaces before splitting, so an all-caps name
    like "API URL" collapses to `apiurl` rather than `api_url`. Anything the
    job code reads off `self.params` has to match what this produces, and a
    mismatch is silent: the attribute is simply absent. The credentials are
    therefore read with an explicit `extract_job_param` call by display name
    rather than off `self.params`.
    """
    attributes = {camel_to_snake_case(name) for name in declared_parameter_names(module_name)}

    assert {
        "environment_name",
        "max_hours_backwards",
        "closed_alert_reason",
        "closed_alert_root_cause",
        "close_case_when_all_alerts_closed",
    } <= attributes
