from azure.mgmt.redis import RedisManagementClient
from azure.mgmt.resource import resources
from azure.core.rest import HttpRequest
import json

def run_scan(credential, subscription_id):

    print(f"  [+] Running Azure Cache for Redis Scanner...")
    findings = []

    try:

        redis_client = RedisManagementClient(credential,subscription_id)
        resource_client = resources.ResourceManagementClient(credential, subscription_id)
        redis_caches = list(redis_client.redis.list_by_subscription())

        for redis in redis_caches:

            resource_group = redis.id.split("/")[4] if (redis.id and len(redis.id.split("/")) > 4) else "Unknown"
            if redis.enable_non_ssl_port is True:
                findings.append({
                    "service": "Azure Cache for Redis",
                    "resource_name": redis.name,
                    "resource_id": redis.id,
                    "resource_group": resource_group,
                    "check": "AZ-REDIS-001",
                    "severity": "HIGH",
                    "issue": "Azure Cache for Redis allows unencrypted connections over port 6379.",
                    "current_values": f"enable_non_ssl_port={redis.enable_non_ssl_port}"
                })

            tls_version = str(getattr(redis, "minimum_tls_version", "") or "")
            if tls_version not in ["1.2", "1.3"]:
                findings.append({
                    "service": "Azure Cache for Redis",
                    "resource_name": redis.name,
                    "resource_id": redis.id,
                    "resource_group": resource_group,
                    "check": "AZ-REDIS-002",
                    "severity": "HIGH",
                    "issue": "Susceptibility to downgrade attacks and deprecated cryptographic ciphers (TLS 1.0/1.1).",
                    "current_values": f"minimum_tls_version={redis.minimum_tls_version}"
                })

            pna = str(getattr(redis, "public_network_access", "")).strip().lower()
            if pna == "enabled":
                findings.append({
                    "service": "Azure Cache for Redis",
                    "resource_name": redis.name,
                    "resource_id": redis.id,
                    "resource_group": resource_group,
                    "check": "AZ-REDIS-003",
                    "severity": "HIGH",
                    "issue": "Azure Cache for Redis instance has public network access enabled, allowing inbound traffic from the public Internet.",
                    "current_values": f"public_network_access={redis.public_network_access}"
                })

            private_endpoints = []
            for endpoint in (redis.private_endpoint_connections or []):
                if endpoint.private_link_service_connection_state and endpoint.private_link_service_connection_state.status == "Approved":
                    private_endpoints.append(endpoint)

            if not redis.subnet_id and not private_endpoints:
                findings.append({
                    "service": "Azure Cache for Redis",
                    "resource_name": redis.name,
                    "resource_id": redis.id,
                    "resource_group": resource_group,
                    "check": "AZ-REDIS-004",
                    "severity": "HIGH",
                    "issue": "Azure Cache for Redis instance has no active Private Endpoint or VNet subnet injection.",
                    "current_values": f"subnet_id={redis.subnet_id} private_endpoints_count={len(private_endpoints)}"
                })

            aad_value = getattr(getattr(redis, "redis_configuration", None), "aad_enabled", None)
            is_aad_enabled = str(aad_value).strip().lower() == "true" or aad_value is True
            if not is_aad_enabled:
                findings.append({
                    "service": "Azure Cache for Redis",
                    "resource_name": redis.name,
                    "resource_id": redis.id,
                    "resource_group": resource_group,
                    "check": "AZ-REDIS-005",
                    "severity": "MEDIUM",
                    "issue": "Microsoft Entra ID (AAD) authentication is disabled. Redis is using legacy shared access keys.",
                    "current_values": f"redis_configuration.aad_enabled={aad_value}"
                })

            sku_name = getattr(getattr(redis, "sku", None), "name", "")
            rdb_value = getattr(getattr(redis, "redis_configuration", None), "rdb_backup_enabled", "")
            aof_value = getattr(getattr(redis, "redis_configuration", None), "aof_backup_enabled", "")

            if (
                    str(sku_name).strip().lower() == "premium"
                    and str(rdb_value).strip().lower() != "true"
                    and str(aof_value).strip().lower() != "true"
            ):
                findings.append({
                    "service": "Azure Cache for Redis",
                    "resource_name": redis.name,
                    "resource_id": redis.id,
                    "resource_group": resource_group,
                    "check": "AZ-REDIS-006",
                    "severity": "MEDIUM",
                    "issue": "Premium Azure Cache for Redis does not have RDB or AOF data persistence enabled.",
                    "current_values": f"sku={sku_name}, rdb_backup_enabled={rdb_value}, aof_backup_enabled={aof_value}"
                })

            api_version = "2021-05-01-preview"
            url = f"https://management.azure.com{redis.id}/providers/Microsoft.Insights/diagnosticSettings?api-version={api_version}"

            request = HttpRequest("GET", url)
            response = resource_client._client.send_request(request)

            if response.status_code == 200:
                diagnostic_settings = response.json().get("value", [])
                has_active_diagnostics = False

                for setting in diagnostic_settings:
                    properties = setting.get("properties", {}) or {}

                    destination_targets = bool(
                        properties.get("workspaceId")
                        or properties.get("storageAccountId")
                        or properties.get("eventHubAuthorizationRuleId")
                    )

                    logs = properties.get("logs", []) or []
                    metrics = properties.get("metrics", []) or []

                    has_logs_or_metrics_enabled = any(
                        log.get("enabled") is True for log in logs
                    ) or any(
                        metric.get("enabled") is True for metric in metrics
                    )

                    if destination_targets and has_logs_or_metrics_enabled:
                        has_active_diagnostics = True
                        break

                if not has_active_diagnostics:
                    findings.append({
                        "service": "Azure Cache for Redis",
                        "resource_name": redis.name,
                        "resource_id": redis.id,
                        "resource_group": resource_group,
                        "check": "AZ-REDIS-007",
                        "severity": "LOW",
                        "issue": "Azure Cache for Redis instance does not have an active Azure Monitor diagnostic setting configured with enabled logs/metrics and a valid destination.",
                        "current_values": f"has_active_diagnostics={has_active_diagnostics}, total_settings_found={len(diagnostic_settings)}"
                    })
            else:
                print(f"  [!] Azure Cache for Redis - Failed to fetch diagnostic settings: {response.status_code} - {response.text()}")


    except Exception as e:
        print(f"  [!] Exception in Azure Cache for Redis Plugin: {e}")

    return findings