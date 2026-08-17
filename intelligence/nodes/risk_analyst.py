import json
import os
from typing import cast
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate

from intelligence.schemas import RiskAnalysisReport
from intelligence.prompts import RISK_ANALYST_SYSTEM_PROMPT
from langchain_anthropic import ChatAnthropic

load_dotenv()

def risk_analyst_node(state: dict) -> dict:
    """
    Evaluates context, calculates CVSS scores, maps compliance, and drafts an executive SOC risk summary.
    """
    findings = state.get("findings", [])

    if not findings:
        return {
            "risk_report": {
                "executive_summary": "No security findings were detected in the target subscription.",
                "findings": []
            }
        }

    llm = ChatAnthropic(model=os.getenv("LLM_MODEL", "claude-haiku-4-5-20251001"), api_key=os.getenv("ANTHROPIC_API_KEY"), temperature=0.0,max_tokens=4096,max_retries=3,timeout=60)

    structured_llm = llm.with_structured_output(
        RiskAnalysisReport
    )

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", RISK_ANALYST_SYSTEM_PROMPT),
            ("human", "Analyze the following Azure security findings payload:\n\n{findings_json}")
        ]
    )

    chain = prompt | structured_llm
    report = cast(RiskAnalysisReport, chain.invoke({
        "findings_json": json.dumps(findings, indent=2)
    }))

    return {"risk_report": report.model_dump()}