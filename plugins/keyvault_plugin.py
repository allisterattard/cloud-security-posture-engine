from azure.mgmt.keyvault import KeyVaultManagementClient

def run_scan(credential, subscription_id):
    print(f"  [+] Running KeyVault Scanner...")
    findings = []
    keyvault_client = KeyVaultManagementClient(credential=credential, subscription_id=subscription_id)

    try:
        vaults = keyvault_client.vaults.list_by_subscription()
        for vault_ref in vaults:
            rg_name = vault_ref.id.split("/")[4]
            vault_name = vault_ref.name
            vault_id = vault_ref.id

            enable_soft_delete = getattr(vault_ref.properties, "enable_soft_delete", None)
            if enable_soft_delete is False:
                findings.append({
                    "service": "KeyVault",
                    "resource_name": vault_name,
                    "resource_id": vault_id,
                    "resource_group": rg_name,
                    "check": "AZ-KV-001",
                    "severity": "HIGH",
                    "issue": f"Key Vault {vault_name} soft delete is disabled",
                    "current_config": f"enable_soft_delete={enable_soft_delete}"
                })

            enable_purge_protection = getattr(vault_ref.properties, "enable_purge_protection", None)
            if not enable_purge_protection:
                findings.append({
                    "service": "KeyVault",
                    "resource_name": vault_name,
                    "resource_id": vault_id,
                    "resource_group": rg_name,
                    "check": "AZ-KV-002",
                    "severity": "HIGH",
                    "issue": f"Key Vault {vault_name} purge protection is disabled, leaving keys/secrets vulnerable to permanent deletion.",
                    "current_config": f"enable_purge_protection={enable_purge_protection}"
                })

            public_network_access = getattr(vault_ref.properties, "public_network_access", "Enabled")
            if str(public_network_access).lower() == "enabled":
                findings.append({
                    "service": "KeyVault",
                    "resource_name": vault_name,
                    "resource_id": vault_id,
                    "resource_group": rg_name,
                    "check": "AZ-KV-003",
                    "severity": "HIGH",
                    "issue": f"Key Vault {vault_name} allows public network access instead of relying exclusively on Private Endpoints.",
                    "current_config": f"public_network_access={public_network_access}"
                })

            network_rule_set = getattr(vault_ref.properties, "network_acls", None)
            if network_rule_set:
                default_action = getattr(network_rule_set, "default_action", "Allow")
                if str(default_action).lower() == "allow":
                    findings.append({
                        "service": "KeyVault",
                        "resource_name": vault_name,
                        "resource_id": vault_id,
                        "resource_group": rg_name,
                        "check": "AZ-KV-004",
                        "severity": "MEDIUM",
                        "issue": f"Key Vault {vault_name} firewall default action is set to Allow instead of Deny.",
                        "current_config": f"default_action={default_action}"
                    })

            enable_rbac = getattr(vault_ref.properties, "enable_rbac_authorization", False)
            if not enable_rbac:
                findings.append({
                    "service": "KeyVault",
                    "resource_name": vault_name,
                    "resource_id": vault_id,
                    "resource_group": rg_name,
                    "check": "AZ-KV-005",
                    "severity": "MEDIUM",
                    "issue": f"Key Vault {vault_name} is using legacy Access Policies instead of Azure RBAC authorization.",
                    "current_config": f"enable_rbac={enable_rbac}"
                })



    except Exception as e:
        print(f"  [!] Exception in KeyVault Plugin: {e}")

    return findings