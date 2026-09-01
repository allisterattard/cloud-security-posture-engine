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
        RiskAnalysisReport
    )

    batch_size = 8
    all_enriched = []
    exec_summary = ""

    for i in range(0, len(indexed_findings), batch_size):
        chunk = indexed_findings[i : i + batch_size]
        min_idx = chunk[0]["finding_index"]
        max_idx = chunk[-1]["finding_index"]

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    (
                        f"{RISK_ANALYST_SYSTEM_PROMPT}\n\n"
                        f"CRITICAL: Process findings with finding_index from {min_idx} to {max_idx}. "
                        f"Preserve the EXACT `finding_index`, `check`, and `resource_name`."
                    ),
                ),
                (
                    "human",
                    "Analyze the following Azure security findings payload:\n\n{findings_json}",
                ),
            ]
        )

        chain = prompt | structured_llm
        report = cast(
            RiskAnalysisReport,
            chain.invoke(
                {"findings_json": json.dumps(chunk, indent=2)}
            ),
        )

        for local_idx, enriched_item in enumerate(report.findings):
            expected_global_idx = chunk[local_idx]["finding_index"]
            item_dict = enriched_item.model_dump()
            if (
                    item_dict.get("finding_index")
                    != expected_global_idx
            ):
                item_dict["finding_index"] = expected_global_idx
            all_enriched.append(item_dict)

        if not exec_summary:
            exec_summary = report.executive_summary

    return {
        "risk_report": {
            "executive_summary": exec_summary,
            "findings": all_enriched,
        }
    }