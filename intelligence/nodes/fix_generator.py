import json
import os
from typing import cast
from dotenv import load_dotenv
from langchain_core.messages import SystemMessage
from langchain_core.prompts import ChatPromptTemplate, HumanMessagePromptTemplate
from langchain_anthropic import ChatAnthropic

from intelligence.schemas import RemediationPlan
from intelligence.prompts import FIX_GENERATOR_SYSTEM_PROMPT

load_dotenv()

def fix_generator_node(state: dict) -> dict:
    """
    Generates copy-paste Azure CLI commands and Terraform HCL remediation blocks.
    """
    findings =state.get("findings", [])
    risk_report = state.get("risk_report", {})

    if not findings:
        return {"remediation_plan": {"remediations": []}}

    findings_json = json.dumps(findings, indent=2)
    risk_json = json.dumps(risk_report, indent=2)

    llm = ChatAnthropic(model=os.getenv("LLM_MODEL", "claude-haiku-4-5-20251001"), api_key=os.getenv("ANTHROPIC_API_KEY"), temperature=0.0,max_tokens=4096,max_retries=3,timeout=60)

    structured_llm = llm.with_structured_output(
        RemediationPlan
    )

    prompt = ChatPromptTemplate(
        messages=[
            SystemMessage(content=FIX_GENERATOR_SYSTEM_PROMPT),
            HumanMessagePromptTemplate.from_template(
                "Raw Findings:\n{findings_json}\n\nEnriched Risk Analysis:\n{risk_json}"
            )
        ]
    )

    chain = prompt | structured_llm
    remediation_plan = cast(RemediationPlan, chain.invoke({
        "findings_json": findings_json,
        "risk_json": risk_json
    }))

    return {"remediation_plan": remediation_plan.model_dump()}