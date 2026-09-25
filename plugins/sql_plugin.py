from azure.mgmt.sql import SqlManagementClient
from azure.core.rest import HttpRequest
import json

def run_scan(credential, subscription_id):
    print(f"  [+] Running Azure SQL Server & Database Scanner...")
    findings = []
    try:
        sql_client = SqlManagementClient(credential, subscription_id)

        servers = list(sql_client.servers.list())
        for server in servers:

            resource_group = server.id.split("/")[4] if (server.id and len(server.id.split("/")) > 4) else "Unkown"

            raw_pna = getattr(server, "public_network_access", "")
            pna_str = str(raw_pna).strip().upper()
            if "ENABLED" in pna_str or pna_str == "TRUE":
                findings.append({
                    "service": "Azure SQL Server",
                    "resource_name": server.name,
                    "resource_id": server.id,
                    "resource_group": resource_group,
                    "check": "AZ-SQL-001",
                    "severity": "HIGH",
                    "issue": "Azure SQL Server has public network access enabled, exposing endpoints to the public internet.",
                    "current_values": f"public_network_access={server.public_network_access}"
                })

            raw_tls = getattr(server, "minimal_tls_version", "")
            min_tls_str = str(raw_tls).strip()

            if "ONE2" in min_tls_str.upper() or min_tls_str == "1.2":
                normalized_tls = "1.2"
            elif "ONE3" in min_tls_str.upper() or min_tls_str == "1.3":
                normalized_tls = "1.3"
            else:
                normalized_tls = min_tls_str
            if normalized_tls not in ["1.2", "1.3"]:
                findings.append({
                    "service": "Azure SQL Server",
                    "resource_name": server.name,
                    "resource_id": server.id,
                    "resource_group": resource_group,
                    "check": "AZ-SQL-002",
                    "severity": "MEDIUM",
                    "issue": "Azure SQL Server is configured with a weak or deprecated minimum TLS version.",
                    "current_values": f"minimal_tls_version={server.minimal_tls_version}"
                })

            try:
                va_list = list(sql_client.server_vulnerability_assessments.list_by_server(resource_group, server.name))
                recurring_enabled = False
                if va_list:
                    va_dict = va_list[0].as_dict() if hasattr(va_list[0], "as_dict") else va_list[0]
                    props = va_dict.get("properties", {}) or {}
                    recurring_scans = props.get("recurring_scans", {}) or {}

                    recurring_enabled = bool(
                        recurring_scans.get("is_enabled", False)
                        or recurring_scans.get("isEnabled", False)
                    )
                if not va_list or not recurring_enabled:
                    findings.append({
                        "service": "Azure SQL Server",
                        "resource_name": server.name,
                        "resource_id": server.id,
                        "resource_group": resource_group,
                        "check": "AZ-SQL-003",
                        "severity": "HIGH",
                        "issue": "Azure SQL Server does not have a Server Vulnerability Assessment configured.",
                        "current_values": "vulnerability_assessments_configured=False"
                    })
            except Exception as e:
                findings.append({
                    "service": "Azure SQL Server",
                    "resource_name": server.name,
                    "resource_id": server.id,
                    "resource_group": resource_group,
                    "check": "AZ-SQL-003",
                    "severity": "HIGH",
                    "issue": "Failed to retrieve or verify Azure SQL vulnerability assessment settings.",
                    "current_values": f"error={str(e)}"
                })

            api_version = "2021-05-01-preview"
            url = f"https://management.azure.com{server.id}/providers/Microsoft.Insights/diagnosticSettings?api-version={api_version}"

            request = HttpRequest("GET", url)
            response = sql_client._client.send_request(request)

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
                            "service": "Azure SQL Server",
                            "resource_name": server.name,
                            "resource_id": server.id,
                            "resource_group": resource_group,
                            "check": "AZ-SQL-004",
                            "severity": "LOW",
                            "issue": "Azure SQL Server instance does not have an active Azure Monitor diagnostic setting configured.",
                            "current_values": f"has_active_diagnostics={has_active_diagnostics}, total_settings_found={len(diagnostic_settings)}"
                        })

    except Exception as e:
        print(f"  [!] Exception in Azure SQL Scanner Plugin: {e}")

    return findings