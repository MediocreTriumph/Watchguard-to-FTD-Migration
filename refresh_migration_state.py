#!/usr/bin/env python3
"""
Refresh migration_state.json with current FMC object UUIDs.
Queries FMC for all objects by name and updates the state file.
"""

import json
import sys
import time
from fmc_migrate_4 import FMCClient, MigrationStateManager


def get_all_objects_by_type(fmc, object_type, limit=1000):
    """Get all objects of a specific type from FMC"""
    endpoint = f"{fmc.base_url}/domain/{fmc.domain_uuid}/object/{object_type}"
    all_objects = []
    offset = 0
    
    while True:
        params = {'offset': offset, 'limit': limit}
        try:
            response = fmc._make_request('GET', endpoint, params=params)
            
            if isinstance(response, dict) and 'error' in response:
                break
            
            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])
                all_objects.extend(items)
                
                # Check pagination
                paging = data.get('paging', {})
                if offset + len(items) >= paging.get('count', 0):
                    break
                offset += limit
            else:
                break
        except Exception as e:
            print(f"  Error getting {object_type}: {e}")
            break
    
    return all_objects


def refresh_state(fmc_host, fmc_user, fmc_pass):
    """Refresh migration state with current FMC UUIDs"""
    
    print("="*80)
    print("REFRESH MIGRATION STATE")
    print("="*80)
    
    # Load existing state
    state = MigrationStateManager()
    
    # Initialize FMC client
    print(f"\nConnecting to FMC at {fmc_host}...")
    fmc = FMCClient(fmc_host, fmc_user, fmc_pass)
    if not fmc.authenticate():
        print("✗ Failed to authenticate")
        return False
    
    # Mapping of state object types to FMC API endpoints
    object_type_map = {
        'hosts': 'hosts',
        'networks': 'networks',
        'ranges': 'ranges',
        'fqdns': 'fqdns',
        'tcp_services': 'protocolportobjects',
        'udp_services': 'protocolportobjects',
        'icmp_services': 'icmpv4objects',
        'address_groups': 'networkgroups'
    }
    
    stats = {
        'found': 0,
        'not_found': 0,
        'updated': 0
    }
    
    print("\n" + "="*80)
    print("QUERYING FMC OBJECTS")
    print("="*80)
    
    # Build name-to-UUID lookup from FMC
    fmc_objects = {}
    
    for state_type, api_endpoint in object_type_map.items():
        if api_endpoint in fmc_objects:
            continue  # Already queried this endpoint
        
        print(f"\nQuerying {api_endpoint}...")
        objects = get_all_objects_by_type(fmc, api_endpoint)
        print(f"  Found {len(objects)} objects")
        
        # Build lookup by name
        if api_endpoint not in fmc_objects:
            fmc_objects[api_endpoint] = {}
        
        for obj in objects:
            name = obj['name']
            fmc_objects[api_endpoint][name] = {
                'id': obj['id'],
                'type': obj['type']
            }
        
        time.sleep(0.5)
    
    print("\n" + "="*80)
    print("UPDATING MIGRATION STATE")
    print("="*80)
    
    # Update state with current UUIDs
    for state_type, api_endpoint in object_type_map.items():
        if state_type not in state.state['objects']:
            continue
        
        print(f"\nUpdating {state_type}...")
        
        for obj_name, obj_data in state.state['objects'][state_type].items():
            # Skip failed objects
            if not obj_data.get('created'):
                continue
            
            # Look up current UUID in FMC
            # Handle sanitized names
            sanitized_name = obj_data.get('sanitized_name', obj_name)
            
            current_obj = fmc_objects[api_endpoint].get(sanitized_name)
            if not current_obj:
                # Try original name
                current_obj = fmc_objects[api_endpoint].get(obj_name)
            
            if current_obj:
                old_uuid = obj_data.get('uuid')
                new_uuid = current_obj['id']
                
                if old_uuid != new_uuid:
                    print(f"  ✓ {obj_name}: {old_uuid[:8]}... → {new_uuid[:8]}...")
                    obj_data['uuid'] = new_uuid
                    stats['updated'] += 1
                
                stats['found'] += 1
            else:
                print(f"  ✗ {obj_name}: NOT FOUND IN FMC")
                stats['not_found'] += 1
    
    # Save updated state
    state.save_state()
    
    print("\n" + "="*80)
    print("REFRESH COMPLETE")
    print("="*80)
    
    print(f"\nResults:")
    print(f"  Found in FMC:    {stats['found']}")
    print(f"  Not found:       {stats['not_found']}")
    print(f"  UUIDs updated:   {stats['updated']}")
    
    print(f"\n✓ State saved to migration_state.json")
    
    if stats['not_found'] > 0:
        print(f"\n⚠  {stats['not_found']} objects not found in FMC")
        print("   These objects may have been deleted or failed to create")
        print("   Re-run fmc_migrate_4.py to recreate missing objects")
    
    return True


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python refresh_migration_state.py <fmc_host> <username> <password>")
        print("\nExample:")
        print("  python refresh_migration_state.py 192.168.255.122 admin Cisc01@3")
        sys.exit(1)
    
    fmc_host = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    
    success = refresh_state(fmc_host, username, password)
    sys.exit(0 if success else 1)