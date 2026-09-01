from pydantic import BaseModel, Field
from typing import List

class EnrichedFinding(BaseModel):
    finding_index: int = Field(description="The 1-based index matching the input finding (1, 2, 3...)")
    check: str = Field(description="The status rule ID, eg., AZ-NSG001 or AZ-STR-004")
    resource_name: str = Field(description="Name of the Azure resource")
    resource_id: str = Field(description="The full ARM resource ID")
    cvss_score: float = Field(description="CVSS v3.1 Base Score from 0.0 to 10.0")
    cvss_vector: str = Field( description="CVSS v3.1 Vector string, e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    mcsb_control_id: str = Field(description="The exact Microsoft Cloud Security Benchmark control ID (e.g., NS-1, NS-2, DP-3, DP-4, PA-1, IM-1, LT-1, BR-1)")
    mcsb_domain: str = Field(description="The MCSB security domain (e.g., Network Security, Data Protection, Privileged Access, Identity Management, Logging and Threat Detection, Backup and Recovery)")
    compliance_mappings: List[str] = Field(default_factory=list, description="Mapped compliance frameworks (e.g. CIS Azure 1.4, NIST SP 800-53 Rev 5 AC-4")
    threat_vector: str= Field(description="Technical explanation of how an attacker could exploit this vulnerability")
    business_impact: str = Field(description="Real-world organizational risk (data breach, ransomware, compliance fines")

class RiskAnalysisReport(BaseModel):
    executive_summary: str = Field(description="High-level SOC summary of security posture, key exposure trends, and critical risk drivers")
    findings: List[EnrichedFinding] = Field(default_factory=list)

class ResourceRemediation(BaseModel):
    finding_index: int = Field(description="The 1-based index matching the input finding (1, 2, 3...)")
    check: str = Field(description="The static rule ID")
    resource_name: str = Field(description="Target Azure resource name")
    checkov_id: str = Field(description="The official Checkov Policy ID corresponding to this misconfiguration (e.g., CKV_AZURE_160, CKV_AZURE_10, CKV_AZURE_109)")
    trivy_id: str = Field(description="The official Trivy/AVD Policy ID corresponding to this misconfiguration (e.g., AVD-AZU-0017, AVD-AZU-0016, AVD-AZU-0046)")
    iac_suppression_comment: str = Field(description="Exact Terraform inline code comment snippet to skip/suppress this rule in Checkov and Trivy")
    azure_cli: str = Field(description="Production-ready Azure CLI command(s) or script to remediate the vulnerability")
    terraform_hcl: str = Field(description=(
        "Complete, functional Terraform HCL resource snippet for this specific Azure resource type "
        "(e.g., azurerm_storage_account, azurerm_key_vault, azurerm_linux_virtual_machine, "
        "azurerm_network_security_rule, azurerm_mssql_server). NEVER return placeholders or 'unavailable'."
    ))
    rollback_plan: str = Field(description="Clear rollback procedure / command if the fix causes service disruption")

class RemediationPlan(BaseModel):
    remediations: List[ResourceRemediation] = Field(default_factory=list)