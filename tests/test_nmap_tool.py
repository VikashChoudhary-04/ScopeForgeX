from pathlib import Path

from scopeforgex.config import (
    PROFILE_FAST,
    PROFILE_FULL,
    PROFILE_STANDARD,
    get_profile,
)
from scopeforgex.registry.tool_base import ToolContext
from scopeforgex.tools.stage1_recon_network import NmapTool


def _nmap_context(
    target: str,
    options: dict,
    profile: str = PROFILE_STANDARD,
) -> ToolContext:
    return ToolContext(
        target=target,
        output_dir=Path("/tmp/scopeforgex-nmap-test"),
        profile=profile,
        options=options,
    )


def test_nmap_build_arguments_use_default_nse_profile():
    context = _nmap_context(
        "warrantyindia.com",
        {
            "service_detection": True,
            "os_detection": False,
            "timing": "T3",
            "nse_profile": "default",
        },
    )

    arguments = NmapTool(context).build_arguments()

    assert "--script" in arguments
    assert arguments[
        arguments.index("--script") + 1
    ] == "default"


def test_nmap_preserves_explicit_target_port():
    context = _nmap_context(
        "http://127.0.0.1:3000",
        {
            "service_detection": True,
            "os_detection": False,
            "timing": "T3",
            "nse_profile": "default",
        },
    )

    arguments = NmapTool(context).build_arguments()

    assert "-sV" in arguments
    assert "-T3" in arguments
    assert "--script" in arguments
    assert arguments[
        arguments.index("--script") + 1
    ] == "default"
    assert "-p" in arguments
    assert arguments[
        arguments.index("-p") + 1
    ] == "3000"
    assert arguments[-1] == "127.0.0.1"


def test_fast_profile_uses_default_nse_profile():
    profile = get_profile(PROFILE_FAST)

    nmap = profile.tools["nmap"]

    assert nmap.options["nse_profile"] == "default"
    assert nmap.options["service_detection"] is True
    assert nmap.options["os_detection"] is False
    assert nmap.options["timing"] == "T3"


def test_standard_profile_uses_default_nse_profile():
    profile = get_profile(PROFILE_STANDARD)

    nmap = profile.tools["nmap"]

    assert nmap.options["nse_profile"] == "default"
    assert nmap.options["service_detection"] is True
    assert nmap.options["os_detection"] is False
    assert nmap.options["timing"] == "T3"


def test_full_profile_keeps_default_nse_profile_and_full_detection():
    profile = get_profile(PROFILE_FULL)

    nmap = profile.tools["nmap"]

    assert nmap.options["nse_profile"] == "default"
    assert nmap.options["service_detection"] is True
    assert nmap.options["os_detection"] is True
    assert nmap.options["timing"] == "T4"
