from azure.mgmt.network import NetworkManagementClient
import json

def is_port_exposed(rule, target_port):
    ports = []
    if rule.destination_port_range:
        ports.append(rule.destination_port_range)
    if rule.destination_port_ranges:
        ports.extend(rule.destination_port_ranges)

    for port in ports:
        if port == "*":
            return True
        elif port == str(target_port):
            return True
        elif "-" in port and str(target_port) != "*":
            try:
                start, end = map(int, port.split("-"))
                if start <= int(target_port) <= end:
                    return True
            except ValueError:
                pass
    return False

def is_open_to_connect(rule):
    sources = []
    if rule.source_address_prefix:
        sources.append(rule.source_address_prefix)
    if rule.source_address_prefixes:
        sources.extend(rule.source_address_prefixes)

    open_prefixes = ["*", "0.0.0.0/0", "internet"]
    return any(s.lower() in open_prefixes for s in sources)
    

def run_scan(credential, subscription_id):
    print("  [+] Running NSG Scanner...")
    findings = []
    try:
        network_client = NetworkManagementClient(credential, subscription_id)
        nsgs = network_client.network_security_groups.list_all()
        for nsg in nsgs:
            resource_group = nsg.id.split("/")[4] if (nsg.id and len(nsg.id.split("/")) > 4) else "Unknown"
            if nsg.security_rules:
                for rule in nsg.security_rules:
                    if rule.access == "Allow" and rule.direction == "Inbound":
                        if is_open_to_connect(rule):
                            is_ssh = is_port_exposed(rule, "22")
                            is_rdp = is_port_exposed(rule, "3389")
                            is_wildcard = is_port_exposed(rule, "*")
                            if is_ssh:
                                rule_id = "AZ-NSG-002"
                                severity = "CRITICAL"
                                port_desc = "SSH (22)"
                            elif is_rdp:
                                rule_id = "AZ-NSG-001"
                                severity = "CRITICAL"
                                port_desc = "RDP (3389)"
                            elif is_wildcard:
                                rule_id = "AZ-NSG-003"
                                severity = "CRITICAL"
                                port_desc = "ALL Ports (*)"
                            else:
                                if rule.destination_port_range in ["80", "443"] or rule.destination_port_ranges in [["80", "443"], ["443", "80"]]:
                                    continue
                                rule_id = "AZ-NSG-004"
                                severity = "HIGH"
                                port_desc = rule.destination_port_range or ",".join(rule.destination_port_ranges or [])

                            dest_port = rule.destination_port_range or rule.destination_port_ranges
                            source_src = rule.source_address_prefix or rule.source_address_prefixes
                            
                            findings.append({
                                "service": "NSG",
                                "resource_name": nsg.name,
                                "resource_id": nsg.id,
                                "resource_group": resource_group,
                                "check": rule_id,
                                "severity": severity,
                                "issue": f"Inbound {port_desc} allowed from public source {source_src}.",
                                "current_config": f"rule={rule.name}, priority={rule.priority}, ports={dest_port}"

                            })

    except Exception as e:
        print(f"  [!] Exception in NSG Plugin: {e}")
    
    return findings