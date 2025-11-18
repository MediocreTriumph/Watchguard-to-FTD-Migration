#!/usr/bin/env python3

import sys
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import defaultdict

def parse_watchguard_config(xml_file):
    """Parse WatchGuard XML config and return structured JSON"""
    
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    config = {
        "metadata": {
            "parsed_date": datetime.now().isoformat(),
            "source_file": xml_file
        },
        "addresses": {
            "hosts": {},
            "networks": {},
            "ranges": {},
            "fqdns": {}
        },
        "address_groups": [],
        "interface_aliases": [],
        "services": {
            "tcp": {},
            "udp": {},
            "icmp": {},
            "other": {}
        },
        "service_groups": [],
        "routes": [],
        "interfaces": [],
        "policies": [],
        "nat_rules": [],
        "sdwan_actions": [],
        "app_actions": [],
        "geo_actions": []
    }
    
    # Protocol number to name mapping
    PROTOCOLS = {
        "0": "HOPOPT", "1": "ICMP", "2": "IGMP", "6": "TCP",
        "17": "UDP", "47": "GRE", "50": "ESP", "51": "AH", "89": "OSPFIGP"
    }
    
    # Parse Routes
    for route in root.findall("./system-parameters/route/route-entry"):
        route_obj = {}
        for elem in route:
            if elem.tag == "dest-address":
                route_obj["destination"] = elem.text
            elif elem.tag == "mask":
                route_obj["mask"] = elem.text
            elif elem.tag == "gateway-ip":
                route_obj["gateway"] = elem.text
        if route_obj:
            config["routes"].append(route_obj)
    
    # Parse Address Objects - using dict to deduplicate by name
    for addr_group in root.findall("./address-group-list/address-group"):
        name = ""
        description = ""
        
        for elem in addr_group:
            if elem.tag == "name":
                name = elem.text
            elif elem.tag == "description":
                description = elem.text if elem.text else ""
            elif elem.tag == "addr-group-member":
                for member in elem:
                    # Determine type based on what fields exist
                    host_ip = network_addr = mask = start_addr = end_addr = fqdn = None
                    
                    for field in member:
                        if field.tag == "host-ip-addr":
                            host_ip = field.text
                        elif field.tag == "ip-network-addr":
                            network_addr = field.text
                        elif field.tag == "ip-mask":
                            mask = field.text
                        elif field.tag == "start-ip-addr":
                            start_addr = field.text
                        elif field.tag == "end-ip-addr":
                            end_addr = field.text
                        elif field.tag == "domain":
                            fqdn = field.text
                    
                    # Categorize by type - store in dict to deduplicate
                    if host_ip:
                        if name not in config["addresses"]["hosts"]:
                            config["addresses"]["hosts"][name] = {
                                "name": name,
                                "description": description,
                                "ip": host_ip
                            }
                    elif network_addr and mask:
                        if name not in config["addresses"]["networks"]:
                            config["addresses"]["networks"][name] = {
                                "name": name,
                                "description": description,
                                "network": network_addr,
                                "mask": mask
                            }
                    elif start_addr and end_addr:
                        if name not in config["addresses"]["ranges"]:
                            config["addresses"]["ranges"][name] = {
                                "name": name,
                                "description": description,
                                "start": start_addr,
                                "end": end_addr
                            }
                    elif fqdn:
                        if name not in config["addresses"]["fqdns"]:
                            config["addresses"]["fqdns"][name] = {
                                "name": name,
                                "description": description,
                                "fqdn": fqdn
                            }
    
    # Parse Aliases - capture both direct members and alias references
    for alias in root.findall("./alias-list/alias"):
        alias_obj = {
            "name": "",
            "description": "",
            "member_types": [],
            "member_users": [],
            "members": [],  # Direct address object references
            "alias_references": [],  # References to other aliases
            "member_interfaces": []
        }
        
        for elem in alias:
            if elem.tag == "name":
                alias_obj["name"] = elem.text
            elif elem.tag == "description":
                alias_obj["description"] = elem.text if elem.text else ""
            elif elem.tag == "alias-member-list":
                for alias_member in elem.findall("alias-member"):
                    for field in alias_member:
                        if field.tag == "type":
                            alias_obj["member_types"].append(field.text)
                        elif field.tag == "user":
                            alias_obj["member_users"].append(field.text)
                        elif field.tag == "address":
                            alias_obj["members"].append(field.text)
                        elif field.tag == "alias-name":  # NEW: capture alias references
                            alias_obj["alias_references"].append(field.text)
                        elif field.tag == "interface":
                            alias_obj["member_interfaces"].append(field.text)
        
        # Deduplicate
        alias_obj["member_types"] = list(dict.fromkeys(alias_obj["member_types"]))
        alias_obj["member_users"] = list(dict.fromkeys(alias_obj["member_users"]))
        alias_obj["members"] = list(dict.fromkeys(alias_obj["members"]))
        alias_obj["alias_references"] = list(dict.fromkeys(alias_obj["alias_references"]))
        alias_obj["member_interfaces"] = list(dict.fromkeys(alias_obj["member_interfaces"]))
        
        # Special case: if only 'Any', keep just one
        if alias_obj["members"] and all(m == "Any" for m in alias_obj["members"]):
            alias_obj["members"] = ["Any"]
        
        # Separate interface aliases from address groups
        is_interface_alias = (
            len(alias_obj["member_interfaces"]) > 0 and 
            len(alias_obj["members"]) == 0 and
            len(alias_obj["alias_references"]) == 0
        ) or alias_obj["name"] in ["Any", "Firebox", "Any-External", "Any-Trusted", "Any-Optional"]
        
        if is_interface_alias:
            config["interface_aliases"].append(alias_obj)
        else:
            config["address_groups"].append(alias_obj)
    
    # Parse Services - using dict to deduplicate
    for service in root.findall("./service-list/service"):
        name = ""
        description = ""
        
        for elem in service:
            if elem.tag == "name":
                name = elem.text
            elif elem.tag == "description":
                description = elem.text if elem.text else ""
            elif elem.tag == "service-item":
                for item in elem:
                    protocol = None
                    port = None
                    
                    for field in item:
                        if field.tag == "protocol":
                            protocol = PROTOCOLS.get(field.text, field.text)
                        elif field.tag == "server-port":
                            port = field.text
                    
                    if protocol:
                        obj = {
                            "name": name,
                            "description": description,
                            "port": port
                        }
                        
                        # Deduplicate by storing in dict
                        if protocol == "TCP":
                            if name not in config["services"]["tcp"]:
                                config["services"]["tcp"][name] = obj
                        elif protocol == "UDP":
                            if name not in config["services"]["udp"]:
                                config["services"]["udp"][name] = obj
                        elif protocol == "ICMP":
                            obj.pop("port")
                            if name not in config["services"]["icmp"]:
                                config["services"]["icmp"][name] = obj
                        else:
                            obj["protocol"] = protocol
                            if name not in config["services"]["other"]:
                                config["services"]["other"][name] = obj
    
    # Parse Interfaces
    for interface in root.findall("./interface-list/interface"):
        intf = {
            "name": "",
            "description": "",
            "device_name": "",
            "enabled": "",
            "node_type": "",
            "ip": "",
            "gateway": "",
            "mask": "",
            "secondary_ips": []
        }
        
        for elem in interface:
            if elem.tag == "name":
                intf["name"] = elem.text
            elif elem.tag == "description":
                intf["description"] = elem.text if elem.text else ""
            elif elem.tag == "if-item-list":
                for item in elem:
                    for physif in item:
                        for field in physif:
                            if field.tag == "if-dev-name":
                                intf["device_name"] = field.text
                            elif field.tag == "enabled":
                                intf["enabled"] = field.text
                            elif field.tag == "ip-node-type":
                                intf["node_type"] = field.text
                            elif field.tag == "ip":
                                intf["ip"] = field.text
                            elif field.tag == "default-gateway":
                                intf["gateway"] = field.text
                            elif field.tag == "netmask":
                                intf["mask"] = field.text
                            elif field.tag == "secondary-ip-list":
                                for sec_ip in field:
                                    for ip_elem in sec_ip:
                                        if ip_elem.text:
                                            intf["secondary_ips"].append(ip_elem.text)
        
        config["interfaces"].append(intf)
    
    # Build alias lookup map
    alias_map = {}
    for alias in config["address_groups"] + config["interface_aliases"]:
        alias_map[alias["name"]] = alias
    
    # Recursive function to resolve alias to all final address objects
    def resolve_alias_members(alias_name, visited=None):
        """Recursively resolve an alias to all its final address object members"""
        if visited is None:
            visited = set()
        
        # Prevent infinite recursion
        if alias_name in visited:
            return []
        visited.add(alias_name)
        
        # Special cases
        if alias_name == "Any":
            return ["Any"]
        
        if alias_name not in alias_map:
            return []
        
        alias = alias_map[alias_name]
        resolved = []
        
        # Add direct members
        resolved.extend(alias["members"])
        
        # Recursively resolve alias references
        for ref in alias["alias_references"]:
            resolved.extend(resolve_alias_members(ref, visited))
        
        return resolved
    
    # Parse Policies with proper resolution
    for policy in root.findall("./abs-policy-list/abs-policy"):
        pol = {
            "name": "",
            "source_aliases": [],
            "destination_aliases": [],
            "source_members": [],
            "destination_members": [],
            "service": "",
            "enabled": "",
            "action": "",
            "nat_policy": "",
            "description": "",
            "reject_action": "",
            "tag": "",
            "schedule": "",
            "log_enabled": "",
            "route_policy": "",
            "proxy": "",
            "sdwan_action": "",
            "app_action": ""
        }
        
        for elem in policy:
            if elem.tag == "name":
                pol["name"] = elem.text
            elif elem.tag == "from-alias-list":
                for alias_ref in elem:
                    alias_name = alias_ref.text
                    pol["source_aliases"].append(alias_name)
                    # Recursively resolve to final members
                    resolved = resolve_alias_members(alias_name)
                    pol["source_members"].extend(resolved)
            elif elem.tag == "to-alias-list":
                for alias_ref in elem:
                    alias_name = alias_ref.text
                    pol["destination_aliases"].append(alias_name)
                    # Recursively resolve to final members
                    resolved = resolve_alias_members(alias_name)
                    pol["destination_members"].extend(resolved)
            elif elem.tag == "service":
                pol["service"] = elem.text
            elif elem.tag == "enabled":
                pol["enabled"] = elem.text
            elif elem.tag == "firewall":
                pol["action"] = elem.text
            elif elem.tag == "policy-nat":
                pol["nat_policy"] = elem.text
            elif elem.tag == "description":
                pol["description"] = elem.text if elem.text else ""
            elif elem.tag == "reject-action":
                pol["reject_action"] = elem.text
            elif elem.tag == "tag-list":
                pol["tag"] = ",".join([a.text for a in elem])
            elif elem.tag == "settings":
                for setting in elem:
                    if setting.tag == "schedule":
                        pol["schedule"] = setting.text
                    elif setting.tag == "log-enabled":
                        pol["log_enabled"] = setting.text
                    elif setting.tag == "policy-routing":
                        pol["route_policy"] = setting.text
                    elif setting.tag == "proxy":
                        pol["proxy"] = setting.text
                    elif setting.tag == "sdwan-action":
                        pol["sdwan_action"] = setting.text
            elif elem.tag == "app-action":
                pol["app_action"] = elem.text if elem.text else ""
        
        # Deduplicate members
        pol["source_members"] = list(dict.fromkeys(pol["source_members"]))
        pol["destination_members"] = list(dict.fromkeys(pol["destination_members"]))
        
        config["policies"].append(pol)
    
    # Parse NAT Rules
    for nat in root.findall("./nat-list/nat"):
        nat_rule = {
            "name": "",
            "type": "",
            "algorithm": "",
            "proxy_arp": "",
            "address_type": "",
            "port": "",
            "external_address": "",
            "interface": "",
            "internal_address": ""
        }
        
        for elem in nat:
            if elem.tag == "name":
                nat_rule["name"] = elem.text
            elif elem.tag == "type":
                nat_rule["type"] = elem.text
            elif elem.tag == "algorithm":
                nat_rule["algorithm"] = elem.text
            elif elem.tag == "proxy-arp":
                nat_rule["proxy_arp"] = elem.text
            elif elem.tag == "nat-item":
                for item in elem:
                    for field in item:
                        if field.tag == "addr-type":
                            nat_rule["address_type"] = field.text
                        elif field.tag == "port":
                            nat_rule["port"] = field.text
                        elif field.tag == "ext-addr-name":
                            nat_rule["external_address"] = field.text
                        elif field.tag == "interface":
                            nat_rule["interface"] = field.text
                        elif field.tag == "addr-name":
                            nat_rule["internal_address"] = field.text
        
        config["nat_rules"].append(nat_rule)
    
    # Parse SDWAN Actions
    SDWAN_ALGORITHMS = {
        "1": "Global",
        "2": "Failover (Immediate Failback)"
    }
    
    for sdwan in root.findall("./sdwan-action-list/sdwan-action"):
        action = {
            "name": "",
            "description": "",
            "algorithm": "",
            "algorithm_description": "",
            "interfaces": [],
            "primary_interface": "",
            "secondary_interface": "",
            "failback_grace_period": ""
        }
        
        for elem in sdwan:
            if elem.tag == "name":
                action["name"] = elem.text
            elif elem.tag == "description":
                action["description"] = elem.text if elem.text else ""
            elif elem.tag == "algorithm":
                action["algorithm"] = elem.text
                action["algorithm_description"] = SDWAN_ALGORITHMS.get(elem.text, f"Unknown ({elem.text})")
            elif elem.tag == "failback-grace-period":
                action["failback_grace_period"] = elem.text
            elif elem.tag == "if-list":
                for if_name in elem.findall("if-name"):
                    action["interfaces"].append(if_name.text)
                if len(action["interfaces"]) >= 1:
                    action["primary_interface"] = action["interfaces"][0]
                if len(action["interfaces"]) >= 2:
                    action["secondary_interface"] = action["interfaces"][1]
        
        config["sdwan_actions"].append(action)
    
    # Parse Application Control
    for app in root.findall("./app-action-list/app-action"):
        app_action = {
            "name": "",
            "description": "",
            "allowed_apps": [],
            "blocked_apps": [],
            "fallthrough_action": ""
        }
        
        for elem in app:
            if elem.tag == "name":
                app_action["name"] = elem.text
            elif elem.tag == "description":
                app_action["description"] = elem.text if elem.text else ""
            elif elem.tag == "fallthrough":
                app_action["fallthrough_action"] = elem.text
            elif elem.tag == "allow-list":
                for app_elem in elem.findall("app"):
                    for field in app_elem:
                        if field.tag == "name":
                            app_action["allowed_apps"].append(field.text)
            elif elem.tag == "block-list":
                for app_elem in elem.findall("app"):
                    for field in app_elem:
                        if field.tag == "name":
                            app_action["blocked_apps"].append(field.text)
        
        config["app_actions"].append(app_action)
    
    # Parse Geo Blocking
    for geo in root.findall(".//geo-action-list/geo-action"):
        geo_action = {
            "name": "",
            "description": "",
            "blocked_countries": []
        }
        
        for elem in geo:
            if elem.tag == "name":
                geo_action["name"] = elem.text
            elif elem.tag == "description":
                geo_action["description"] = elem.text if elem.text else ""
            elif elem.tag == "geo-list":
                for geo_elem in elem.findall("geo"):
                    for field in geo_elem:
                        if field.tag == "country":
                            geo_action["blocked_countries"].append(field.text)
        
        config["geo_actions"].append(geo_action)
    
    # Convert dicts back to lists for final output
    config["addresses"]["hosts"] = list(config["addresses"]["hosts"].values())
    config["addresses"]["networks"] = list(config["addresses"]["networks"].values())
    config["addresses"]["ranges"] = list(config["addresses"]["ranges"].values())
    config["addresses"]["fqdns"] = list(config["addresses"]["fqdns"].values())
    config["services"]["tcp"] = list(config["services"]["tcp"].values())
    config["services"]["udp"] = list(config["services"]["udp"].values())
    config["services"]["icmp"] = list(config["services"]["icmp"].values())
    config["services"]["other"] = list(config["services"]["other"].values())
    
    return config


def analyze_group_dependencies(config):
    """Analyze address group dependencies to determine creation order"""
    
    # Build dependency graph
    dependencies = {}
    for group in config["address_groups"]:
        deps = set()
        for ref in group["alias_references"]:
            # Only track dependencies on other address groups, not interface aliases
            if any(g["name"] == ref for g in config["address_groups"]):
                deps.add(ref)
        dependencies[group["name"]] = deps
    
    # Find groups with no dependencies (can be created first)
    no_deps = [name for name, deps in dependencies.items() if len(deps) == 0]
    
    # Find groups with dependencies
    with_deps = [name for name, deps in dependencies.items() if len(deps) > 0]
    
    # Find max dependency depth
    def get_depth(name, visited=None):
        if visited is None:
            visited = set()
        if name in visited:
            return 0
        visited.add(name)
        
        if name not in dependencies or len(dependencies[name]) == 0:
            return 0
        
        return 1 + max(get_depth(dep, visited.copy()) for dep in dependencies[name])
    
    max_depth = max([get_depth(name) for name in dependencies.keys()]) if dependencies else 0
    
    return {
        "total_groups": len(config["address_groups"]),
        "groups_with_no_dependencies": len(no_deps),
        "groups_with_dependencies": len(with_deps),
        "max_nesting_depth": max_depth,
        "dependencies": dependencies
    }


def validate_references(config):
    """Validate that group members reference existing objects"""
    
    # Build set of all address object names
    all_addresses = set()
    for addr_type in ["hosts", "networks", "ranges", "fqdns"]:
        for obj in config["addresses"][addr_type]:
            all_addresses.add(obj["name"])
    
    # Add interface alias names
    for alias in config["interface_aliases"]:
        all_addresses.add(alias["name"])
    
    # Add address group names
    all_group_names = set()
    for group in config["address_groups"]:
        all_group_names.add(group["name"])
    
    # Build set of all service names
    all_services = set()
    for svc_type in ["tcp", "udp", "icmp", "other"]:
        for obj in config["services"][svc_type]:
            all_services.add(obj["name"])
    
    issues = {
        "broken_address_references": [],
        "broken_alias_references": [],
        "interface_aliases_count": len(config["interface_aliases"])
    }
    
    # Check address groups
    for group in config["address_groups"]:
        # Check direct members
        for member in group["members"]:
            if member != "Any" and member not in all_addresses and member not in all_group_names:
                issues["broken_address_references"].append({
                    "group": group["name"],
                    "missing_member": member
                })
        
        # Check alias references
        for ref in group["alias_references"]:
            if ref not in all_group_names and ref not in [a["name"] for a in config["interface_aliases"]]:
                issues["broken_alias_references"].append({
                    "group": group["name"],
                    "missing_alias": ref
                })
    
    return issues


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./watchparse.py <config.xml>")
        sys.exit(1)
    
    xml_file = sys.argv[1]
    
    # Parse config
    config = parse_watchguard_config(xml_file)
    
    # Analyze dependencies
    dep_analysis = analyze_group_dependencies(config)
    
    # Validate references
    issues = validate_references(config)
    
    # Generate output filename
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M')
    json_file = f"watchguard_config_{timestamp}.json"
    
    # Write JSON output
    with open(json_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    # Print summary
    print(f"✓ Parsed configuration from {xml_file}")
    print(f"✓ Output written to {json_file}")
    print("\n=== Summary ===")
    print(f"Hosts:           {len(config['addresses']['hosts'])}")
    print(f"Networks:        {len(config['addresses']['networks'])}")
    print(f"Ranges:          {len(config['addresses']['ranges'])}")
    print(f"FQDNs:           {len(config['addresses']['fqdns'])}")
    print(f"Address Groups:  {len(config['address_groups'])}")
    print(f"  - No dependencies:   {dep_analysis['groups_with_no_dependencies']}")
    print(f"  - With dependencies: {dep_analysis['groups_with_dependencies']}")
    print(f"  - Max nesting depth: {dep_analysis['max_nesting_depth']}")
    print(f"Interface Aliases: {len(config['interface_aliases'])}")
    print(f"TCP Services:    {len(config['services']['tcp'])}")
    print(f"UDP Services:    {len(config['services']['udp'])}")
    print(f"ICMP Services:   {len(config['services']['icmp'])}")
    print(f"Other Services:  {len(config['services']['other'])}")
    print(f"Policies:        {len(config['policies'])}")
    print(f"NAT Rules:       {len(config['nat_rules'])}")
    print(f"Interfaces:      {len(config['interfaces'])}")
    
    # Report validation issues
    if issues["broken_address_references"]:
        print(f"\n⚠ Warning: {len(issues['broken_address_references'])} broken address references")
        for issue in issues["broken_address_references"][:3]:
            print(f"  - Group '{issue['group']}' → missing '{issue['missing_member']}'")
        if len(issues["broken_address_references"]) > 3:
            print(f"  ... and {len(issues['broken_address_references']) - 3} more")
    
    if issues["broken_alias_references"]:
        print(f"\n⚠ Warning: {len(issues['broken_alias_references'])} broken alias references")
        for issue in issues["broken_alias_references"][:3]:
            print(f"  - Group '{issue['group']}' → missing alias '{issue['missing_alias']}'")
        if len(issues["broken_alias_references"]) > 3:
            print(f"  ... and {len(issues['broken_alias_references']) - 3} more")
    
    print(f"\nℹ Separated {issues['interface_aliases_count']} interface aliases from address groups")