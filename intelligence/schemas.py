from pydantic import BaseModel, Field
from typing import List

class EnrichedFinding(BaseModel):
    check: str = Field(default="", description="The status rule ID, eg., AZ-NSG001 or AZ-STR-004")
    resource_name: str = Field(default="", description="Name of the Azure resource")
    resource_id: str = Field(default="", description="The full ARM resource ID")
    cvss_score: float = Field(default=7.5,  description="CVSS v3.1 Base Score from 0.0 to 10.0")
    cvss_vector: str = Field(default="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", description="CVSS v3.1 Vector string, e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    compliance_mappings: List[str] = Field(default_factory=List, description="Mapped compliance frameworks (e.g. CIS Azure 1.4, NIST SP 800-53 Rev 5 AC-4")
    threat_vector: str= Field(default="Potential unauthorized remote access access and lateral movement.", description="Technical explanation of how an attacker could exploit this vulnerability")
    business_impact: str = Field(default="Risk of data breach, compliance violation, or unauthorized system access.", description="Real-world organizational risk (data breach, ransomware, compliance fines")

class RiskAnalysisReport(BaseModel):
    executive_summary: str = Field(default="Security audit completed with critical perimeter exposure findings.", description="High-level SOC summary of security posture, key exposure trends, and critical risk drivers")
    findings: List[EnrichedFinding] = Field(default_factory=List)

class ResourceRemediation(BaseModel):
    check: str = Field(default="", description="The static rule ID")
    resource_name: str = Field(default="", description="Target Azure resource name")
    azure_cli: str = Field(default="# Run `az network nsg rule update` to restrict access.", description="Production-ready Azure CLI command(s) or script to remediate the vulnerability")
    terraform_hcl: str = Field(default="# Update security_rule resource block to restrict source_address_prefix.", description=(
        "Complete, functional Terraform HCL resource snippet for this specific Azure resource type "
        "(e.g., azurerm_storage_account, azurerm_key_vault, azurerm_linux_virtual_machine, "
        "azurerm_network_security_rule, azurerm_mssql_server). NEVER return placeholders or 'unavailable'."
    ))
    rollback_plan: str = Field(default="Re-apply the prior NSG security rule state if connectivity fails.", description="Clear rollback procedure / command if the fix causes service disruption")

class RemediationPlan(BaseModel):
    remediations: List[ResourceRemediation] = Field(default_factory=List)