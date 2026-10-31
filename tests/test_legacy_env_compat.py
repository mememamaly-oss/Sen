"""v5.0.0 rename compatibility (owner order, part 1.4): legacy SENTINEL_*
variables must be surfaced with a clear warning — never silently ignored."""
import os
import subprocess
import sys


def test_warn_legacy_environment_names_the_new_variable(capsys):
    from burhan.envcompat import warn_legacy_environment
    os.environ["SENTINEL_TESTPROBE"] = "1"
    try:
        found = warn_legacy_environment()
        assert "SENTINEL_TESTPROBE" in found
        err = capsys.readouterr().err
        assert "SENTINEL_TESTPROBE" in err
        assert "BURHAN_TESTPROBE" in err
        assert "WARNING" in err
    finally:
        del os.environ["SENTINEL_TESTPROBE"]


def test_cli_startup_warns_on_legacy_env():
    env = dict(os.environ)
    env["SENTINEL_DATA_DIR"] = "/tmp/legacy-data-dir-probe"
    env.pop("BURHAN_DATA_DIR", None)
    r = subprocess.run(
        [sys.executable, "-m", "burhan.cli", "doctor"],
        capture_output=True, text=True, env=env, timeout=180,
    )
    assert "SENTINEL_DATA_DIR" in r.stderr, r.stderr[-400:]
    assert "BURHAN_DATA_DIR" in r.stderr, r.stderr[-400:]
    assert "WARNING" in r.stderr, r.stderr[-400:]
