from langgraph.graph import StateGraph, END
from intelligence.state import AgentState
from intelligence.nodes.risk_analyst import risk_analyst_node
from intelligence.nodes.fix_generator import fix_generator_node

def create_security_graph():
    """
    Constructs and compiles the Azure Security Posture intelligence graph.
    """
    workflow = StateGraph(AgentState)

    workflow.add_node("risk_analyst", risk_analyst_node)
    workflow.add_node("fix_generator", fix_generator_node)

    workflow.set_entry_point("risk_analyst")
    workflow.add_edge("risk_analyst", "fix_generator")
    workflow.add_edge("fix_generator", END)
    return workflow.compile()
