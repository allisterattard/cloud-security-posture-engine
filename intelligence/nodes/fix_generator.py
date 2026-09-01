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

    indexed_findings = []
    for idx, val in enumerate(findings, start=1):
        item = dict(val)
        item["finding_index"] = idx
        indexed_findings.append(item)

    llm = ChatAnthropic(
        model=os.getenv("LLM_MODEL", "claude-haiku-4-5-20251001"),
        api_key=os.getenv("ANTHROPIC_API_KEY"),
        temperature=0.0,
        max_tokens=8192,
        max_retries=3,
        timeout=120
    )

    structured_llm = llm.with_structured_output(
        RemediationPlan
    )

    batch_size = 6
    all_remediations = []

    for i in range(0, len(indexed_findings), batch_size):
        chunk = indexed_findings[i : i + batch_size]
        min_idx = chunk[0]["finding_index"]
        max_idx = chunk[-1]["finding_index"]

        prompt = ChatPromptTemplate(
            messages=[
                SystemMessage(
                    content=(
                        f"{FIX_GENERATOR_SYSTEM_PROMPT}\n\n"
                        f"CRITICAL: This batch contains findings with finding_index from {min_idx} to {max_idx}. "
                        f"You MUST preserve and output the EXACT `finding_index`, `check`, and `resource_name` provided in each item. "
                        f"Do NOT restart index counting from 1."
                    )
                ),
                HumanMessagePromptTemplate.from_template(
                    "Raw Findings Chunk:\n{findings_json}"
                ),
            ]
        )

        chain = prompt | structured_llm
        remediation_plan = cast(
            RemediationPlan,
            chain.invoke({"findings_json": json.dumps(chunk, indent=2)}),
        )

        # Force correct global index mapping if LLM reset the index to 1..N
        for local_idx, rem in enumerate(remediation_plan.remediations):
            expected_global_idx = chunk[local_idx]["finding_index"]
            rem_dict = rem.model_dump()
            # If the LLM restarted count at 1, correct it to the global index
            if (
                    rem_dict.get("finding_index")
                    != expected_global_idx
            ):
                rem_dict["finding_index"] = expected_global_idx
            all_remediations.append(rem_dict)

    return {"remediation_plan": {"remediations": all_remediations}}