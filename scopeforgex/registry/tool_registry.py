"""
ScopeForgeX Tool Registry
=========================

Central registry for all executable tools.

The registry preserves execution order. Stages are appended in the order they
should execute throughout the ScopeForgeX pipeline.

v0.4.0
"""

from scopeforgex.tools.stage1_recon_web import ALL_STAGE1_WEB_TOOLS
from scopeforgex.tools.stage1_recon_network import ALL_STAGE1_NET_TOOLS
from scopeforgex.tools.stage2_enum_web import ALL_STAGE2_WEB_ENUM_TOOLS
from scopeforgex.tools.stage2_enum_network import ALL_STAGE2_NET_ENUM_TOOLS
from scopeforgex.tools.stage3_vuln import ALL_STAGE3_VULN_TOOLS
from scopeforgex.tools.stage4_exploit import ALL_STAGE4_EXPLOIT_TOOLS
from scopeforgex.tools.stage5_post import ALL_STAGE5_POST_TOOLS


# Ordered stage collections.
#
# The order here determines the default execution order throughout
# the framework.
_STAGE_COLLECTIONS = (
    ALL_STAGE1_WEB_TOOLS,
    ALL_STAGE1_NET_TOOLS,
    ALL_STAGE2_WEB_ENUM_TOOLS,
    ALL_STAGE2_NET_ENUM_TOOLS,
    ALL_STAGE3_VULN_TOOLS,
    ALL_STAGE4_EXPLOIT_TOOLS,
    ALL_STAGE5_POST_TOOLS,
)


def build_registry():
    """
    Build and return the complete ordered tool registry.

    Returns:
        list: Ordered list of registered tool definitions.
    """

    registry = []

    for collection in _STAGE_COLLECTIONS:
        registry.extend(collection)

    return registry.copy()
