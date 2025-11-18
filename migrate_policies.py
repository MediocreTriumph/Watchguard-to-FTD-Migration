#!/usr/bin/env python3

import json
import sys
import time
import ipaddress
from pathlib import Path
from datetime import datetime

# Import your existing FMC client
from fmc_migrate_4 import FMCClient, MigrationStateManager
from service_lookup import get_fmc_service_for_migration


def is_rfc1918(ip_str):
    """Check if IP is RFC1918 private address"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except:
        return False


def determine_zone_from_members(members, state, address_objects):
    """
    Determine if members are inside or outside based on IP addresses.
    Returns 'inside' or 'outside'
    """
    # Check actual IP addresses of members
    for member_name in members:
        if member_name == "Any":
            continue
        
        # Look up the address object
        for addr_type in ['hosts', 'networks', 'ranges', 'fqdns']:
            if member_name in address_objects.get(addr_type, []):
                addr_obj = next((obj for obj in address_objects[addr_type] 
                               if obj['name'] == member_name), None)
                
                if addr_obj:
                    # Check IP address
                    ip = addr_obj.get('ip') or addr_obj.get('network') or addr_obj.get('start')
                    if ip and is_rfc1918(ip):
                        return 'inside'
                    elif ip:
                        return 'outside'
    
    # Default to inside if can't determine
    return 'inside'


def resolve_members_to_uuids(members, state):
    """
    Resolve member names to FMC UUIDs.
    Returns list of dicts with 'type' and 'id' keys.
    """
    resolved = []
    
    for member in members:
        if member == "Any":
            # FMC built-in any-ipv4 object
            resolved.append({
                "type": "Network",
                "id": "cb7116e8-66a6-480b-8f9b-295191a0940a",
                "name": "any-ipv4"
            })
            continue
        
        # Try to find UUID in migration state
        uuid = None
        obj_type = None
        
        # Check all address object types
        for addr_type in ['hosts', 'networks', 'ranges', 'fqdns']:
            uuid = state.get_uuid(addr_type, member)
            if uuid:
                obj_type = "Network"  # FMC uses generic Network type for all
                break
        
        # Check address groups
        if not uuid:
            uuid = state.get_uuid('address_groups', member)
            if uuid:
                obj_type = "NetworkGroup"
        
        if uuid:
            resolved.append({
                "type": obj_type,
                "id": uuid,
                "name": member
            })
        else:
            # Object not found - log warning but continue
            print(f"\n    ⚠ Member '{member}' not found in migration state")
    
    return resolved


def translate_policy_to_fmc_rule(wg_policy, state, address_objects, zone_map):
    """
    Translate a WatchGuard policy to FMC access rule format.
    
    Returns dict with FMC rule data or None if can't translate.
    """
    
    # Skip proxy policies for now (disable them)
    if wg_policy.get('action') == 'Proxy':
        return {
            'skip': True,
            'reason': 'Proxy action not supported',
            'policy_name': wg_policy['name']
        }
    
    # Map action
    action_map = {
        'Allow': 'ALLOW',
        'Deny': 'BLOCK',
        'Drop': 'BLOCK'
    }
    
    action = action_map.get(wg_policy.get('action'), 'BLOCK')
    
    # Resolve source members
    source_networks = resolve_members_to_uuids(
        wg_policy.get('source_members', []), 
        state
    )
    
    # Resolve destination members
    dest_networks = resolve_members_to_uuids(
        wg_policy.get('destination_members', []), 
        state
    )
    
    # Determine zones
    source_zone = determine_zone_from_members(
        wg_policy.get('source_members', []),
        state,
        address_objects
    )
    dest_zone = determine_zone_from_members(
        wg_policy.get('destination_members', []),
        state,
        address_objects
    )
    
    # Get zone UUIDs
    source_zone_obj = zone_map.get(source_zone)
    dest_zone_obj = zone_map.get(dest_zone)
    
    if not source_zone_obj or not dest_zone_obj:
        return {
            'skip': True,
            'reason': f'Missing zone mapping: {source_zone} or {dest_zone}',
            'policy_name': wg_policy['name']
        }
    
    # Lookup service
    service_name = wg_policy.get('service', 'Any')
    service_lookup = None
    
    if service_name != 'Any':
        service_lookup = get_fmc_service_for_migration(service_name)
        
        if not service_lookup.get('found'):
            return {
                'skip': True,
                'reason': f'Service not found: {service_name}',
                'policy_name': wg_policy['name']
            }
    
    # Build FMC rule
    rule = {
        "name": wg_policy['name'][:50],  # FMC has name length limits
        "action": action,
        "enabled": wg_policy.get('enabled', 'true') == 'true',
        "type": "AccessRule",
        "sendEventsToFMC": wg_policy.get('log_enabled', 'false') == 'true',
        "logBegin": False,
        "logEnd": True,
    }
    
    # Add source zones
    if source_zone_obj:
        rule["sourceZones"] = {
            "objects": [{
                "type": source_zone_obj['type'],
                "id": source_zone_obj['id'],
                "name": source_zone_obj['name']
            }]
        }
    
    # Add destination zones
    if dest_zone_obj:
        rule["destinationZones"] = {
            "objects": [{
                "type": dest_zone_obj['type'],
                "id": dest_zone_obj['id'],
                "name": dest_zone_obj['name']
            }]
        }
    
    # Add source networks
    if source_networks:
        rule["sourceNetworks"] = {
            "objects": source_networks
        }
    
    # Add destination networks
    if dest_networks:
        rule["destinationNetworks"] = {
            "objects": dest_networks
        }
    
    # Add service
    if service_lookup and service_lookup.get('found'):
        rule["destinationPorts"] = {
            "objects": [{
                "type": service_lookup['fmc_type'],
                "id": service_lookup['fmc_id'],
                "name": service_lookup['fmc_name']
            }]
        }
    
    # Add description
    desc = wg_policy.get('description', '')
    if wg_policy.get('tag'):
        desc = f"[{wg_policy['tag']}] {desc}"
    if desc:
        rule["description"] = desc[:500]
    
    return rule


def migrate_policies(config_file, fmc_host, fmc_user, fmc_pass, acp_id):
    """Main policy migration function"""
    
    print("="*80)
    print("POLICY MIGRATION TO CISCO FMC")
    print("="*80)
    
    # Load WatchGuard config
    print(f"\nLoading configuration from {config_file}...")
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    policies = config.get('policies', [])
    print(f"Found {len(policies)} policies to migrate")
    
    # Load migration state
    state = MigrationStateManager()
    
    # Initialize FMC client
    print(f"\nConnecting to FMC at {fmc_host}...")
    fmc = FMCClient(fmc_host, fmc_user, fmc_pass)
    if not fmc.authenticate():
        print("✗ Failed to authenticate")
        return False
    
    # Get zones
    print("\nGetting security zones...")
    zones = fmc.get_security_zones()
    print(f"Found {len(zones)} zones")
    
    # Build zone map
    zone_map = {}
    for zone in zones:
        zone_name = zone['name'].lower()
        if 'inside' in zone_name:
            zone_map['inside'] = zone
        elif 'outside' in zone_name:
            zone_map['outside'] = zone
    
    if 'inside' not in zone_map or 'outside' not in zone_map:
        print("✗ Could not find 'inside' and 'outside' zones")
        print("Available zones:")
        for zone in zones:
            print(f"  - {zone['name']}")
        return False
    
    print(f"✓ Using zones:")
    print(f"  Inside:  {zone_map['inside']['name']}")
    print(f"  Outside: {zone_map['outside']['name']}")
    
    # Migration tracking
    migrated = []
    skipped = []
    failed = []
    
    print("\n" + "="*80)
    print("MIGRATING POLICIES")
    print("="*80)
    
    for i, policy in enumerate(policies, 1):
        policy_name = policy['name']
        print(f"\n[{i}/{len(policies)}] {policy_name[:60]}...")
        
        # Translate policy
        rule = translate_policy_to_fmc_rule(
            policy,
            state,
            config.get('addresses', {}),
            zone_map
        )
        
        # Check if skipped
        if rule and rule.get('skip'):
            print(f"  ⊘ SKIPPED: {rule['reason']}")
            skipped.append({
                'policy': policy_name,
                'reason': rule['reason']
            })
            continue
        
        # Create rule in FMC
        print(f"  Creating rule...", end='', flush=True)
        result = fmc.create_access_rule(acp_id, rule)
        
        if 'error' in result:
            print(f" ✗ FAILED")
            print(f"    {result['error'][:100]}")
            failed.append({
                'policy': policy_name,
                'error': result['error']
            })
        else:
            print(f" ✓")
            migrated.append({
                'policy': policy_name,
                'fmc_rule_id': result.get('id')
            })
        
        time.sleep(0.5)  # Rate limiting
    
    # Generate report
    print("\n" + "="*80)
    print("MIGRATION COMPLETE")
    print("="*80)
    
    print(f"\nResults:")
    print(f"  Migrated: {len(migrated)}")
    print(f"  Skipped:  {len(skipped)}")
    print(f"  Failed:   {len(failed)}")
    
    # Save detailed report
    report = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "config_file": config_file,
            "acp_id": acp_id,
            "total_policies": len(policies)
        },
        "summary": {
            "migrated": len(migrated),
            "skipped": len(skipped),
            "failed": len(failed)
        },
        "migrated": migrated,
        "skipped": skipped,
        "failed": failed
    }
    
    report_file = f"policy_migration_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n✓ Report saved to {report_file}")
    
    if skipped:
        print(f"\n⚠  {len(skipped)} policies were skipped:")
        for item in skipped[:10]:
            print(f"  - {item['policy']}: {item['reason']}")
        if len(skipped) > 10:
            print(f"  ... and {len(skipped) - 10} more (see report)")
    
    if failed:
        print(f"\n✗ {len(failed)} policies failed:")
        for item in failed[:10]:
            print(f"  - {item['policy']}: {item['error'][:80]}")
        if len(failed) > 10:
            print(f"  ... and {len(failed) - 10} more (see report)")
    
    return True


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python migrate_policies.py <config.json> <fmc_host> <username> <password> [acp_id]")
        print("\nExample:")
        print("  python migrate_policies.py watchguard_config.json 192.168.255.122 admin password123")
        print("  python migrate_policies.py watchguard_config.json 192.168.255.122 admin password123 525400C1-7EB6-0ed3-0000-004294969435")
        sys.exit(1)
    
    config_file = sys.argv[1]
    fmc_host = sys.argv[2]
    username = sys.argv[3]
    password = sys.argv[4]
    acp_id = sys.argv[5] if len(sys.argv) > 5 else "525400C1-7EB6-0ed3-0000-004294969435"
    
    success = migrate_policies(config_file, fmc_host, username, password, acp_id)
    sys.exit(0 if success else 1)