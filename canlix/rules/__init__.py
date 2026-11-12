from canlix.rules.config import CONFIG_RULES
from canlix.rules.execution import EXECUTION_RULES
from canlix.rules.network import NETWORK_RULES
from canlix.rules.permissions import PERMISSIONS_RULES
from canlix.rules.secrets import SECRETS_RULES

ALL_RULES = SECRETS_RULES + PERMISSIONS_RULES + NETWORK_RULES + EXECUTION_RULES + CONFIG_RULES

__all__ = ["ALL_RULES"]
