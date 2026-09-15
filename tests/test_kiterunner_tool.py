from pathlib import Path

import yaml

from scopeforgex.registry.tool_base import ToolContext
from scopeforgex.tools.stage2_enum_web import KiterunnerTool


PROFILE_CONFIG = Path("scopeforgex/config/profiles.yaml")


def _context(options=None):
    return ToolContext(
        target="warrantyindia.com",
        output_dir=Path("/tmp/scopeforgex-kiterunner-test"),
        options=options or {},
    )


def _active_profile_options(profile_name):
    data = yaml.safe_load(
        PROFILE_CONFIG.read_text()
    )

    return (
        data["profiles"][profile_name]["enumeration"]["kiterunner"]
        ["options"]
    )


def test_kiterunner_default_does_not_enable_full_scan():
    arguments = KiterunnerTool(
        _context()
    ).build_arguments()

    assert "--kitebuilder-full-scan" not in arguments


def test_kiterunner_explicit_full_scan_is_preserved():
    arguments = KiterunnerTool(
        _context({"full_scan": True})
    ).build_arguments()

    assert "--kitebuilder-full-scan" in arguments


def test_kiterunner_explicit_full_scan_false_is_preserved():
    arguments = KiterunnerTool(
        _context({"full_scan": False})
    ).build_arguments()

    assert "--kitebuilder-full-scan" not in arguments


def test_standard_active_profile_disables_full_scan():
    options = _active_profile_options("standard")

    assert options["full_scan"] is False


def test_full_active_profile_disables_full_scan():
    options = _active_profile_options("full")

    assert options["full_scan"] is False

def test_kiterunner_default_quiet_is_enabled():
    arguments = KiterunnerTool(
        _context()
    ).build_arguments()

    assert "-q" in arguments


def test_kiterunner_explicit_quiet_false_is_preserved():
    arguments = KiterunnerTool(
        _context({"quiet": False})
    ).build_arguments()

    assert "-q" not in arguments
