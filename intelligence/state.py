from importlib.metadata import Distribution
from typing import TypedDict, List, Dict, Any

class AgentState(TypedDict):
    """Represents the shared state of the Azure Security Intelligence graph."""
    subscription_id: str
    findings: List[Dict[str, Any]]
    risk_report: Dict[str, Any]
    remediation_plan: Dict[str, Any]