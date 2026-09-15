############################## TERMS OF USE ################################### # noqa: E266
# The following code is provided for demonstration purposes only, and should  #
# not be used without independent verification. Recorded Future makes no      #
# representations or warranties, express, implied, statutory, or otherwise,   #
# regarding this code, and provides it strictly "as-is".                      #
# Recorded Future shall not be liable for, and you assume all risk of         #
# using the foregoing.                                                        #
###############################################################################

"""Pytest configuration for the Recorded Future integration test suite.

The modules inside `soar_sdk` import each other as top level modules, so that
directory has to be importable in its own right. `mp test` adds it to
PYTHONPATH before invoking pytest; this does the same when pytest is run
directly, so the suite behaves identically either way.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _ensure_soar_sdk_importable() -> None:
    """Add the bundled SOAR SDK directory to `sys.path` if it is not already."""
    try:
        import SiemplifyUtils  # noqa: F401, PLC0415
    except ModuleNotFoundError:
        for sdk_path in Path(sys.prefix).glob("lib/*/site-packages/soar_sdk"):
            sys.path.insert(0, str(sdk_path))
            return


_ensure_soar_sdk_importable()
