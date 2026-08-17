from datetime import datetime, timezone


def generate_soc_markdown_report(state: dict, output_file: str = "azure_security_report.md") -> str:
    """
    Combines the deterministic findings, LLM risk analysis, and remediation code into an enterprise SOC Markdown report.
    """
    findings = state.get("findings", [])
    risk_report = state.get("risk_report", {})
    remediation_plan = state.get("remediation_plan", {})
    sub_id = state.get("subscription_id", "Unknown")

    exec_summary = risk_report.get("executive_summary", "No Summary Provided.")
    enriched_findings = {f["resource_id"]: f for f in risk_report.get("findings", [])}
    remediations = {r["resource_name"]: r for r in remediation_plan.get("remediations", [])}

    md = [
        "# 🛡️ Azure Cloud Security Posture Assessment Report",
        f"**Generated on:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Target Subscription ID:** `{sub_id}`",
        f"**Total Findings Detected:** {len(findings)}\n",
        "---",
        "## 1. Executive Summary",
        f"{exec_summary}\n",
        "---",
        "## 2. Enriched Findings & Actionable Remediations\n",
    ]

    for idx, raw in enumerate(findings, start=1):
        r_id = raw.get("resource_id", "")
        r_name = raw.get("resource_name", "Unknown")
        check_id = raw.get("check", "N/A")
        severity = raw.get("severity", "MEDIUM")
        issue = raw.get("issue", "Overly permissive access detected.")
        curr_val = raw.get("current_config") or raw.get("current_value") or "N/A"

        enriched = enriched_findings.get(r_id, {})
        remediation = remediations.get(r_name, {})

        cvss_score = enriched.get("cvss_score", "N/A")
        cvss_vec = enriched.get("cvss_vector", "N/A")
        compliance = ", ".join(enriched.get("compliance_mappings", ["N/A"]))
        threat_vector = enriched.get("threat_vector", "Analysis pending.")
        business_impact = enriched.get("business_impact", "No business impact documented.")

        cli_fix = remediation.get("azure_cli", "# Azure CLI command unavailable")
        tf_fix = remediation.get("terraform_hcl", "# Terraform code unavailable")
        rollback = remediation.get("rollback_plan", "No rollback documented.")

        md.append(f"### Finding #{idx}: [{check_id}] {r_name} ({severity})")
        md.append(f"- **Service:** `{raw.get('service', 'NSG')}`")
        md.append(f"- **Resource ID:** `{r_id}`")
        md.append(f"- **Identified Issue:** {issue}")
        md.append(f"- **Current Config:** `{curr_val}`")
        md.append(f"- **CVSS v3.1 Score:** **{cvss_score}** (`{cvss_vec}`)")
        md.append(f"- **Compliance Controls:** {compliance}\n")
        md.append("#### ⚔️ Threat Vector & Impact")
        md.append(f"**Attack Scenario:** {threat_vector}\n")
        md.append(f"**Business Impact:** {business_impact}")
        md.append("#### 🛠️ Remediation Instructions")
        md.append("**Azure CLI Command (Bash):**")
        md.append(f"```bash\n{cli_fix}\n```")
        md.append("**Terraform HCL Fix:**")
        md.append(f"```hcl\n{tf_fix}\n```")
        md.append(f"**Rollback Procedure:**\n> {rollback}\n")
        md.append("---\n")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    return output_file