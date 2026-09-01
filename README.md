# 🛡 Agentic Azure Cloud Security Posture Management (CSPM) Engine️

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![LangGraph](https://img.shields.io/badge/Orchestration-LangGraph-orange)
![Anthropic](https://img.shields.io/badge/LLM-Anthropic%20Claude-purple)

An automated, LLM-powered cloud security auditing and remediation pipeline built with **Python**, **LangGraph**, **Anthropic Claude**, and the **Azure SDK**.

The engine deterministically discovers cloud misconfigurations across Azure subscriptions, performs contextual risk modeling (CVSS v3.1 scoring, threat vector analysis, CIS/NIST mapping), and automatically generates copy-paste Azure CLI commands alongside production-ready Terraform HCL remediation blocks with built-in rollback plans.

---

## 🏗️ Architecture & Workflow

```
[ Azure Target Subscription ]
            │
            ▼  (Azure SDK - Deterministic Scanning)
[ Discovery Scanners ]
    ├── 🌐 Network Security Groups (Management Ports: SSH, RDP, Port 9200)
    ├── 🔑 Azure Key Vault (Purge Protection, Public Access, RBAC Auth)
    ├── 🗄️ Storage Accounts & Containers (Public Blob Access, Container ACLs)
    └── ⚡ Azure Cache for Redis (TLS 1.2+, Public Access, Entra ID Auth, Diagnostics)
            │
            ▼  (Structured Finding Payloads)
[ LangGraph AI Engine (Batch-Aware & Token-Safe) ]
    ├── 🧠 Risk Analyst Node (CVSS v3.1 Scoring, Threat Scenario, Business Impact)
    │ └── Compliance Mapping: MCSB v1/v2, CIS Azure 1.4/2.0, NIST SP 800-53 Rev. 5
    │
    └── 🛠️ Fix Generator Node (Production-Grade Automated Remediation)
    ├── Azure CLI Scripts & Rollback Procedures
    ├── Terraform HCL (azurerm_* Provider Blocks)
    └── Static Analysis Codes: Checkov IDs, Trivy IDs & IaC Suppressions
            │
            ▼  (Deterministic Multi-Tier Join)
[ Enterprise SOC Markdown Report ]
```
---

## ✨ Features

- **Deterministic Discovery:** Read-only inspection using official Azure SDKs (`azure-mgmt-network`, `azure-mgmt-storage`, `azure-mgmt-keyvault`, `azure-mgmt-redis`, `azure-mgmt-resource`) with zero LLM hallucination during scanning.
- **Batch-Aware AI Pipeline:** Chunked node invocations (`batch_size = 6-8`) prevent output token truncation when handling dozens of findings across large cloud environments.
- **Standards & Benchmark Mapping:** Correlates every vulnerability with **Microsoft Cloud Security Benchmark (MCSB)** controls (`NS-1`, `DP-3`, `IM-1`, `LT-1`), CIS Azure Foundations Benchmarks, and NIST SP 800-53 controls.
- **Dual-Track Remediation:** Delivers bash-executable Azure CLI commands alongside declarative `azurerm_*` Terraform HCL blocks with built-in rollback commands.
- **DevSecOps & IaC Tooling Integration:** Emits official **Checkov** (`CKV_AZURE_*`) and **Trivy** (`AVD-AZU-*`) policy IDs with copy-paste HCL exception suppression comments.

## 📋 Audit Check Coverage

| Service Module | Check ID | Audit Rule Description | Severity |
| :--- | :--- | :--- | :--- |
| **Key Vault** | `AZ-KV-001` | Soft delete is disabled on Key Vault | `HIGH` |
| **Key Vault** | `AZ-KV-002` | Purge protection is disabled (vulnerable to permanent deletion) | `HIGH` |
| **Key Vault** | `AZ-KV-003` | Key Vault allows public network access instead of Private Endpoints | `HIGH` |
| **Key Vault** | `AZ-KV-004` | Key Vault firewall default action is set to `Allow` instead of `Deny` | `MEDIUM` |
| **Key Vault** | `AZ-KV-005` | Legacy Access Policies in use instead of Azure RBAC authorization | `MEDIUM` |
| **Network (NSG)** | `AZ-NSG-001` | Inbound RDP (`3389`) allowed from public source `*` / `0.0.0.0/0` | `CRITICAL` |
| **Network (NSG)** | `AZ-NSG-002` | Inbound SSH (`22`) allowed from public source `*` / `0.0.0.0/0` | `CRITICAL` |
| **Network (NSG)** | `AZ-NSG-003` | Inbound wildcard / ALL ports (`*`) unrestricted from public source | `CRITICAL` |
| **Network (NSG)** | `AZ-NSG-004` | Inbound custom ports (e.g., Elasticsearch `9200`) exposed to public Internet | `HIGH` |
| **Redis** | `AZ-REDIS-001` | Non-SSL unencrypted port (`6379`) enabled | `HIGH` |
| **Redis** | `AZ-REDIS-002` | Deprecated TLS protocol versions allowed (`< TLS 1.2`) | `HIGH` |
| **Redis** | `AZ-REDIS-003` | Public network access enabled allowing inbound Internet traffic | `HIGH` |
| **Redis** | `AZ-REDIS-004` | Redis instance lacks Private Endpoint and VNet subnet injection | `HIGH` |
| **Redis** | `AZ-REDIS-005` | Microsoft Entra ID (AAD) authentication disabled (using shared keys) | `MEDIUM` |
| **Redis** | `AZ-REDIS-006` | Premium Redis instance missing RDB/AOF data persistence | `MEDIUM` |
| **Redis** | `AZ-REDIS-007` | Azure Monitor diagnostic logs/metrics not configured with valid sink | `LOW` |
| **Storage Account** | `AZ-STR-001` | Storage account accessible from all public networks | `CRITICAL` |
| **Storage Account** | `AZ-STR-002` | Anonymous public blob access permitted at storage account level | `CRITICAL` / `HIGH` |
| **Storage Account** | `AZ-STR-003` | Outdated TLS version enforced (`< TLS 1.2`) | `MEDIUM` |
| **Storage Account** | `AZ-STR-004` | Storage blob container has anonymous read access actively enabled | `CRITICAL` |

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
### Finding #1: [AZ-REDIS-003] platform-redis (HIGH)
- **Service:** `Azure Cache for Redis`
- **Resource ID:** `/subscriptions/.../providers/Microsoft.Cache/Redis/platform-redis`
- **Identified Issue:** Azure Cache for Redis instance has public network access enabled.
- **Current Config:** `public_network_access=Enabled`
- **CVSS v3.1 Score:** **8.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`)
- **Microsoft Cloud Security Benchmark (MCSB):** `NS-1` (Network Security)
- **Additional Compliance:** CIS Azure 1.4.1, NIST SP 800-53 Rev. 5 SC-7, PCI-DSS 1.3
- **Static Analysis IDs:** Checkov: `CKV_AZURE_31` | Trivy: `AVD-AZU-0047`

#### ⚔️ Threat Vector & Impact
**Attack Scenario:** An unauthenticated attacker discovers the public endpoint on port 6379, attempts credential brute-forcing, and directly targets the Redis instance without traversing firewalls.

**Business Impact:** Unauthorized access to cached user tokens, API keys, and session state, leading to potential cache poisoning, session hijacking, and regulatory fines under GDPR / PCI-DSS.

#### 🛠️ Remediation & IaC Code
**Azure CLI Command (Bash):**

az redis update --name platform-redis --resource-group ztg_rcg_storage --public-network-access-enabled false


**Terraform HCL Fix:**
resource "azurerm_redis_cache" "platform_redis" {
  name                          = "platform-redis"
  location                      = "westeurope"
  resource_group_name           = "ztg_rcg_storage"
  capacity                      = 2
  family                        = "C"
  sku_name                      = "Standard"
  enable_non_ssl_port           = false
  minimum_tls_version           = "1.2"
  public_network_access_enabled = false
}

#### IaC Policy Exception / Suppression Syntax:

# checkov:skip=CKV_AZURE_31:Disabling public network access for Redis cache
# trivy:ignore:AVD-AZU-0047:Approved network isolation via Private Endpoint

#### Rollback Procedure:

az redis update --name platform-redis --resource-group ztg_rcg_storage --public-network-access-enabled true
```

## 🔌 Modular Plugin Architecture

All discovery scanners implement a uniform contract returning standardized, JSON-serializable finding payloads:

```python
{
    "check": "AZ-REDIS-003",
    "service": "Azure Cache for Redis",
    "resource_name": "platform-redis",
    "resource_id": "/subscriptions/.../providers/Microsoft.Cache/Redis/platform-redis",
    "resource_group": "ztg_rcg_storage",
    "severity": "HIGH",
    "issue": "Azure Cache for Redis instance has public network access enabled.",
    "current_config": "public_network_access=Enabled"
}
```

## Supported Scanners
- [x] Network Security Groups: Inbound internet access (0.0.0.0/0 or *) on management ports (RDP 3389, SSH 22), overly broad subnet rules.
- [x] Storage Accounts: Public blob access enabled, missing "Require Secure Transfer" (HTTPS), legacy TLS version (<1.2), soft-delete disabled, missing Private Endpoints.
- [x] Key Vaults: Soft-delete / purge protection disabled, public network access enabled, using Vault Access Policies instead of Azure RBAC, unrotated secrets.
- [x] Azure Cache for Redis: Non-TLS port (6379) enabled, exposed to the public internet without Private Endpoints or VNet integration, weak access keys.
- [ ] Azure SQL (MSSQL PaaS): Public IP exposure, missing Azure AD (Entra) authentication-only mode, Auditing / Defender for SQL turned off, unencrypted data in transit (enforce TLS) (In Progress).
- [ ] Azure Firewall / Load Balancers: Missing WAF integration on App Gateways/Front Door, standard public LBs exposing backends without outbound NAT rules or NSG filtering (Planned).
- [ ] Azure Kubernetes Service (AKS): Public API server endpoint exposed, missing Entra ID RBAC integration, non-system pods running as root, missing Azure Policy/OPA constraint enforcement (Planned).

# 🛡️ Security & Disclaimers

This tool performs read-only audits using Azure SDK management APIs. It does not alter, mutate, or delete cloud infrastructure automatically unless remediation scripts are manually executed by an authorized administrator.

## 📄 License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.
