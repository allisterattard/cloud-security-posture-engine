from datetime import datetime, timezone


def generate_soc_markdown_report(
        state: dict, output_file: str = "azure_security_report.md"
) -> str:
    findings = state.get("findings", [])
    risk_report = state.get("risk_report", {})
    remediation_plan = state.get("remediation_plan", {})
    sub_id = state.get("subscription_id", "Unknown")

    exec_summary = risk_report.get("executive_summary", "No Summary Provided.")

    enriched_by_idx = {
        f.get("finding_index"): f
        for f in risk_report.get("findings", [])
        if f.get("finding_index") is not None
    }
    remediation_by_idx = {
        r.get("finding_index"): r
        for r in remediation_plan.get("remediations", [])
        if r.get("finding_index") is not None
    }

    enriched_by_name = {
        (str(f.get("check", "")).strip().upper(), str(f.get("resource_name", "")).strip().lower()): f
        for f in risk_report.get("findings", [])
    }
    remediation_by_name = {
        (str(r.get("check", "")).strip().upper(), str(r.get("resource_name", "")).strip().lower()): r
        for r in remediation_plan.get("remediations", [])
    }

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
        check_id = str(raw.get("check", "N/A")).strip().upper()
        severity = raw.get("severity", "MEDIUM")
        issue = raw.get("issue", "Overly permissive access detected.")
        curr_val = raw.get("current_config") or raw.get("current_values") or "N/A"

        enriched = (
                enriched_by_idx.get(idx)
                or enriched_by_name.get((check_id, r_name.strip().lower()))
                or (risk_report.get("findings", [])[idx - 1] if idx - 1 < len(risk_report.get("findings", [])) else {})
        )

        remediation = (
                remediation_by_idx.get(idx)
                or remediation_by_name.get((check_id, r_name.strip().lower()))
                or (remediation_plan.get("remediations", [])[idx - 1] if idx - 1 < len(remediation_plan.get("remediations", [])) else {})
        )

        cvss_score = enriched.get("cvss_score", "N/A")
        cvss_vec = enriched.get("cvss_vector", "N/A")

        mcsb_ctrl = enriched.get("mcsb_control_id", "N/A")
        mcsb_domain = enriched.get("mcsb_domain", "Security Best Practices")

        raw_comp = enriched.get("compliance_mappings", [])
        compliance = ", ".join(raw_comp) if raw_comp else "N/A"

        threat_vector = enriched.get("threat_vector", "Analysis pending.")
        business_impact = enriched.get("business_impact", "No business impact documented.")

        checkov_id = remediation.get("checkov_id", "N/A")
        trivy_id = remediation.get("trivy_id", "N/A")
        iac_suppression = remediation.get("iac_suppression_comment", "# No suppression rule available")
        cli_fix = remediation.get("azure_cli", "# Azure CLI command unavailable")
        tf_fix = remediation.get("terraform_hcl", "# Terraform code unavailable")
        rollback = remediation.get("rollback_plan", "No rollback documented.")

        md.append(f"### Finding #{idx}: [{check_id}] {r_name} ({severity})")
        md.append(f"- **Service:** `{raw.get('service', 'Azure Service')}`")
        md.append(f"- **Resource ID:** `{r_id}`")
        md.append(f"- **Identified Issue:** {issue}")
        md.append(f"- **Current Config:** `{curr_val}`")
        md.append(f"- **CVSS v3.1 Score:** **{cvss_score}** (`{cvss_vec}`)")
        md.append(f"- **Microsoft Cloud Security Benchmark (MCSB):** `{mcsb_ctrl}` ({mcsb_domain})")
        md.append(f"- **Additional Compliance:** {compliance}")
        md.append(f"- **Static Analysis IDs:** Checkov: `{checkov_id}` | Trivy: `{trivy_id}`\n")
        md.append("#### ⚔️ Threat Vector & Impact")
        md.append(f"**Attack Scenario:** {threat_vector}\n")
        md.append(f"**Business Impact:** {business_impact}")
        md.append("#### 🛠️ Remediation & IaC Code")
        md.append("**Azure CLI Command (Bash):**")
        md.append(f"```bash\n{cli_fix}\n```")
        md.append("**Terraform HCL Fix:**")
        md.append(f"```hcl\n{tf_fix}\n```")
        md.append("**IaC Policy Exception / Suppression Syntax:**")
        md.append(f"```hcl\n{iac_suppression}\n```")
        md.append(f"**Rollback Procedure:**\n> {rollback}\n")
        md.append("---\n")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    return output_file