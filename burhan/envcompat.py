"""Legacy SENTINEL_* environment-variable detection (v5.0.0 rename).

The project was renamed Sen(tinel) -> Burhan in v5.0.0; every platform
configuration variable moved from SENTINEL_<NAME> to BURHAN_<NAME>. The
platform (Next.js) layer honors legacy names via src/lib/env.ts with a
warning. The engine itself reads no environment variables (all engine
configuration is CLI flags), so this module only WARNS on startup, so
operators with stale deployments notice immediately instead of the values
being silently ignored.
"""
from __future__ import annotations

import os
import sys

LEGACY_PREFIX = "SENTINEL_"


def warn_legacy_environment() -> list:
    """Print a clear warning for every legacy SENTINEL_* variable; return their names."""
    found = sorted(k for k in os.environ if k.startswith(LEGACY_PREFIX))
    for k in found:
        new = "BURHAN_" + k[len(LEGACY_PREFIX):]
        print(
            f"[burhan] WARNING: environment variable {k} is the pre-rename name; "
            f"use {new}. The legacy value is ignored by the engine (all engine "
            f"configuration is CLI flags).",
            file=sys.stderr,
        )
    return found
