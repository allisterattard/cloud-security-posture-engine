# 🛡 Agentic Azure Cloud Security Posture Management (CSPM) Engine️

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green.svg)

An automated, LLM-powered cloud security auditing and remediation pipeline built with **Python**, **LangGraph**, **Anthropic Claude**, and the **Azure SDK**.

The engine deterministically discovers cloud misconfigurations across Azure subscriptions, performs contextual risk modeling (CVSS v3.1 scoring, threat vector analysis, CIS/NIST mapping), and automatically generates copy-paste Azure CLI commands alongside production-ready Terraform HCL remediation blocks with built-in rollback plans.

---

## 🏗️ Architecture & Workflow

```
[ Azure Target Subscription ]
            │
            ▼  (Azure SDK - Deterministic Scanning)
[ Discovery Scanners ]
    ├── NSG Scanner (Exposed Management Ports: RDP, SSH)
    └── Storage Account Scanner (Public Blob Access, Outdated TLS)
            │
            ▼  (Structured Finding Payloads)
[ LangGraph AI Engine ]
    ├── 🧠 Risk Analyst Node (CVSS v3.1 Vector, Threat Path, Compliance)
    └── 🛠️ Fix Generator Node (Azure CLI Scripts & Terraform HCL Blocks)
            │
            ▼
[ Enterprise SOC Markdown Report ]
```
---

## ✨ Features

- **Deterministic Discovery:** Scans Network Security Groups and Azure Storage Accounts for perimeter and data protection vulnerabilities.
- **Contextual Threat Analysis:** Analyzes exploit feasibility, attacker pivot potential, and business blast radius.
- **Standards & Compliance Mapping:** Maps findings to CIS Microsoft Azure Foundations Benchmark (v1.4.0) and NIST SP 800-53 Rev. 5 controls.
- **Dual-Track Remediation:** Generates instant bash-executable Azure CLI remediation commands alongside declarative `azurerm_*` Terraform HCL snippets.
- **Safe Rollback Procedures:** Includes reversal commands for every fix to prevent unintended service disruption.

---

## 📋 Prerequisites

- **Python 3.10+**
- **Azure Role:** Minimum `Reader` role on the target Subscription
- **Anthropic API Key** (Claude 3.5 Haiku)

---

## 🚀 Quickstart & Setup

### 1. Clone the Repository

```bash
git clone git@github.com:allisterattard/cloud-security-posture-engine.git
cd cloud-security-posture-engine
```

### 2. Create and Activate a Virtual Environment

``` bash
uv venv --python 3.12
source .venv/bin/activate
```

### 3. Install Dependencies

``` bash
uv pip install -r requirements.txt
```

### 4. Configure Environment Variables

Copy the example environment template:

``` bash
cp .env.example .env
```

Open .env and fill in your credentials:

```
# Anthropic Claude Configuration
LLM_PROVIDER="claude"
LLM_MODEL="claude-haiku-4-5-20251001"
ANTHROPIC_API_KEY="<claude api key>"

# Azure Configuration
AZURE_TENANT_ID="<azure tenant id>"
AZURE_CLIENT_ID="<azure client id>"
AZURE_CLIENT_SECRET="<azure client_secret>"
AZURE_SUBSCRIPTION_ID="<azure subscription id>"
```

### 5. Run

``` bash
python3 main.py
```

The assessment report will be saved to azure_security_report.md.

## 📊 Sample Report Output

``` markdown
### Finding #1: [AZ-NSG-001] westeurope-business-vm-nsg (CRITICAL)
- **Service:** `NSG`
- **Resource ID:** `/subscriptions/.../networkSecurityGroups/westeurope-vm-nsg`
- **Identified Issue:** Inbound RDP (3389) allowed from public source *.
- **Current Config:** `rule=RDP, priority=300, ports=3389`
- **CVSS v3.1 Score:** **9.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Compliance Controls:** CIS Azure 1.4.0 6.1, NIST SP 800-53 AC-4

#### 🛠️ Remediation Instructions
**Azure CLI Command (Bash):**
az network nsg rule update --resource-group VM-Tools --nsg-name westeurope-vm-nsg --name RDP --access Deny

**Terraform HCL Fix:**
resource "azurerm_network_security_rule" "rdp" {
  name                        = "RDP"
  priority                    = 300
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "VM-Tools"
  network_security_group_name = "westeurope-vm-nsg"
}
```

## 🔌 Modular Plugin Architecture

All scanners implement a uniform contract returning standardized finding dictionaries:

``` python
{
    "check": "AZ-STR-002",
    "service": "StorageAccount",
    "resource_name": "<account_name>",
    "resource_id": "<arm_resource_id>",
    "resource_group": "<rg_name>",
    "severity": "HIGH",
    "issue": "Anonymous public blob access is permitted.",
    "current_config": "allowBlobPublicAccess=True, publicNetworkAccess=Enabled"
}
```

## Supported Scanners
- [x] Network Security Groups: Inbound internet access (0.0.0.0/0 or *) on management ports (RDP 3389, SSH 22), overly broad subnet rules.
- [x] Storage Accounts: Public blob access enabled, missing "Require Secure Transfer" (HTTPS), legacy TLS version (<1.2), soft-delete disabled, missing Private Endpoints.
- [ ] Key Vaults: Soft-delete / purge protection disabled, public network access enabled, using Vault Access Policies instead of Azure RBAC, unrotated secrets (In Progress).
- [ ] Azure SQL (MSSQL PaaS): Public IP exposure, missing Azure AD (Entra) authentication-only mode, Auditing / Defender for SQL turned off, unencrypted data in transit (enforce TLS) (Planned).
- [ ] Azure Firewall / Load Balancers: Missing WAF integration on App Gateways/Front Door, standard public LBs exposing).ng backends without outbound NAT rules or NSG filtering (Planned).
- [ ] Azure Kubernetes Service (AKS): Public API server endpoint exposed, missing Entra ID RBAC integration, non-system pods running as root, missing Azure Policy/OPA constraint enforcement (Planned).
- [ ] Azure Cache for Redis: Non-TLS port (6379) enabled, exposed to the public internet without Private Endpoints or VNet integration, weak access keys (Planned).

# 🛡️ Security & Disclaimers

This tool performs read-only audits using Azure SDK management APIs. It does not alter, mutate, or delete cloud infrastructure automatically unless remediation scripts are manually executed by an authorized administrator.

## 📄 License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.
