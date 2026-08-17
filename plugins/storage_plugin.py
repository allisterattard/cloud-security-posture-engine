import json
from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlobServiceClient

def run_scan(credential, subscription_id):
    print(f"  [+] Running Storage Account Scanner...")
    findings = []
    try:
        storage_client = StorageManagementClient(credential, subscription_id)
        storage_accounts = storage_client.storage_accounts.list()
        for account in storage_accounts:
            public_network_access = getattr(account, "public_network_access", "Enabled") or "Enabled"
            allow_blob_public_access = getattr(account, "allow_blob_public_access", True)
            minimum_tls_version = getattr(account, "minimum_tls_version", "TLS1_0")
            resource_group = account.id.split("/")[4] if (account.id and len(account.id.split("/")) > 4) else "Unknown"
            if str(public_network_access).lower() in ["enabled", "true"]:
                findings.append({
                    "service": "StorageAccount",
                    "resource_name": account.name,
                    "resource_id": account.id,
                    "resource_group": resource_group,
                    "check": "AZ-STR-001",
                    "severity": "CRITICAL",
                    "issue": "Storage account is accessible from all public networks.",
                    "current_config": f"publicNetworkAccess={public_network_access}"
                })
            if allow_blob_public_access is True or allow_blob_public_access is None:
                is_network_open = str(public_network_access).lower() in ["enabled", "true"]
                severity = "CRITICAL" if is_network_open else "HIGH"

                findings.append({
                    "service": "StorageAccount",
                    "resource_name": account.name,
                    "resource_id": account.id,
                    "resource_group": resource_group,
                    "check": "AZ-STR-002",
                    "severity": severity,
                    "issue": "Anonymous public blob access is permitted at the storage account level.",
                    "current_config": f"allowBlobPublicAccess={allow_blob_public_access}, publicNetworkAccess={public_network_access}"
                })

                try:
                    account_url = f"{account.properties.primary_endpoints["blob"]}"
                    blob_service_client = BlobServiceClient(account_url=account_url, credential=credential)
                    containers = blob_service_client.list_containers()

                    for container in containers:

                        pub_access = container.public_access
                        if pub_access and str(pub_access).lower() not in ["none", "off"]:
                            findings.append({
                                "service": "StorageContainer",
                                "resource_name": f"{account.name}/{container.name}",
                                "resource_id": f"{account.id}/containers/{container.name}",
                                "resource_group": resource_group,
                                "check": "AZ-STR-004",
                                "severity": "CRITICAL",
                                "issue": f"Container '{container.name}' has anonymous read access actively enabled!",
                                "current_config": f"publicAccess={pub_access}"
                            })
                except Exception as c_err:
                    pass
            if minimum_tls_version != "TLS1_2":
                findings.append({
                    "service": "StorageAccount",
                    "resource_name": account.name,
                    "resource_id": account.id,
                    "resource_group": resource_group,
                    "check": "AZ-STR-003",
                    "severity": "MEDIUM",
                    "issue": f"Outdated TLS version enforced: {minimum_tls_version}. Expected TLS1_2.",
                    "current_config": f"minimumTlsVersion={minimum_tls_version}"
                })

    except Exception as e:
        print(f"  [!] Exception in Storage Account Plugin: {e}")

    return findings