from scopeforgex.tools.stage1_recon_web import ALL_STAGE1_WEB_TOOLS
from scopeforgex.tools.stage1_recon_network import ALL_STAGE1_NET_TOOLS
from scopeforgex.tools.stage2_enum_web import ALL_STAGE2_WEB_ENUM_TOOLS
from scopeforgex.tools.stage2_enum_network import ALL_STAGE2_NET_ENUM_TOOLS
from scopeforgex.tools.stage3_vuln import ALL_STAGE3_VULN_TOOLS
from scopeforgex.tools.stage4_exploit import ALL_STAGE4_EXPLOIT_TOOLS
from scopeforgex.tools.stage5_post import ALL_STAGE5_POST_TOOLS

def build_registry():
    tools = []
    tools += ALL_STAGE1_WEB_TOOLS
    tools += ALL_STAGE1_NET_TOOLS
    tools += ALL_STAGE2_WEB_ENUM_TOOLS
    tools += ALL_STAGE2_NET_ENUM_TOOLS
    tools += ALL_STAGE3_VULN_TOOLS
    tools += ALL_STAGE4_EXPLOIT_TOOLS
    tools += ALL_STAGE5_POST_TOOLS
    return tools
