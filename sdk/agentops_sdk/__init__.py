"""AgentOps SDK — the client agents embed to obtain governance decisions."""

from .client import (
    AgentOpsClient,
    AuthorizationDenied,
    Decision,
    DecisionResult,
    governed,
)
from .integrations import (
    GovernedToolRouter,
    govern_langchain_tool,
    govern_tool_fn,
)

__all__ = [
    "AgentOpsClient",
    "AuthorizationDenied",
    "Decision",
    "DecisionResult",
    "governed",
    "GovernedToolRouter",
    "govern_langchain_tool",
    "govern_tool_fn",
]
__version__ = "0.1.0"
