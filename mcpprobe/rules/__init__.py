from mcpprobe.rules.config import CONFIG_RULES
from mcpprobe.rules.execution import EXECUTION_RULES
from mcpprobe.rules.network import NETWORK_RULES
from mcpprobe.rules.permissions import PERMISSIONS_RULES
from mcpprobe.rules.secrets import SECRETS_RULES

ALL_RULES = SECRETS_RULES + PERMISSIONS_RULES + NETWORK_RULES + EXECUTION_RULES + CONFIG_RULES

__all__ = ["ALL_RULES"]
