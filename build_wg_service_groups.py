#!/usr/bin/env python3
"""
Build FMC service groups from WatchGuard services.
Creates groups with well-known objects where possible, custom objects for others.
"""

import requests
import json
import os
import sys
from urllib3.exceptions import InsecureRequestWarning
from typing import Dict, List, Optional, Set
from collections import defaultdict

# Suppress SSL warnings for self-signed certs
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class FMCClient:
    def __init__(self, host: str, username: str, password: str, domain_uuid: str):
        self.host = host
        self.username = username
        self.password = password
        self.domain_uuid = domain_uuid
        self.base_url = f"https://{host}/api/fmc_config/v1"
        self.headers = {}
        self.auth_token = None
        
    def authenticate(self) -> bool:
        """Authenticate to FMC and get access token."""
        url = f"https://{self.host}/api/fmc_platform/v1/auth/generatetoken"
        try:
            response = requests.post(
                url,
                auth=(self.username, self.password),
                verify=False
            )
            if response.status_code == 204:
                self.auth_token = response.headers.get('X-auth-access-token')
                self.headers = {
                    'Content-Type': 'application/json',
                    'X-auth-access-token': self.auth_token
                }
                print(f"✓ Authenticated to FMC at {self.host}")
                return True
            else:
                print(f"✗ Authentication failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"✗ Authentication error: {e}")
            return False
    
    def create_port_object(self, name: str, protocol: str, port: str, description: str = "") -> Optional[Dict]:
        """Create a single port object on FMC."""
        url = f"{self.base_url}/domain/{self.domain_uuid}/object/protocolportobjects"
        
        payload = {
            "name": name,
            "protocol": protocol,
            "port": port,
            "type": "ProtocolPortObject"
        }
        
        if description:
            payload["description"] = description
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, verify=False)
            if response.status_code == 201:
                return response.json()
            else:
                # Check if object already exists
                if response.status_code == 400 and "already exists" in response.text.lower():
                    print(f"⊘ Object {name} already exists")
                    return None
                print(f"✗ Failed to create {name}: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"✗ Error creating {name}: {e}")
            return None
    
    def create_port_group(self, name: str, objects: List[Dict], description: str = "") -> Optional[Dict]:
        """Create a port group on FMC."""
        url = f"{self.base_url}/domain/{self.domain_uuid}/object/portobjectgroups"
        
        payload = {
            "name": name,
            "objects": objects,
            "type": "PortObjectGroup"
        }
        
        if description:
            payload["description"] = description
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, verify=False)
            if response.status_code == 201:
                return response.json()
            else:
                # Check if group already exists
                if response.status_code == 400 and "already exists" in response.text.lower():
                    print(f"⊘ Group {name} already exists")
                    return None
                print(f"✗ Failed to create group {name}: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"✗ Error creating group {name}: {e}")
            return None
    
    def get_object_by_name(self, name: str) -> Optional[Dict]:
        """Get a port object by name."""
        url = f"{self.base_url}/domain/{self.domain_uuid}/object/protocolportobjects"
        params = {'filter': f'name:{name}', 'limit': 1}
        
        try:
            response = requests.get(url, headers=self.headers, params=params, verify=False)
            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])
                if items:
                    return items[0]
            return None
        except Exception as e:
            print(f"✗ Error getting object {name}: {e}")
            return None


def load_deduplication_map(filename: str) -> Dict:
    """Load the deduplication map created by analyze_fmc_services.py."""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"✗ Error: {filename} not found. Run analyze_fmc_services.py first.")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Error loading {filename}: {e}")
        sys.exit(1)


def load_watchguard_services(filename: str) -> Dict:
    """Load WatchGuard services JSON."""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"✗ Error: {filename} not found")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Error loading {filename}: {e}")
        sys.exit(1)


def normalize_name(name: str) -> str:
    """Normalize service name by replacing spaces with underscores."""
    return name.replace(' ', '_')


def protocol_number_to_name(proto_num: int) -> str:
    """Convert protocol number to name."""
    protocol_map = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        47: "GRE",
        50: "ESP",
        51: "AH",
        58: "ICMPv6"
    }
    return protocol_map.get(proto_num, str(proto_num))


def group_wg_services_by_name(wg_services: Dict) -> Dict[str, List[Dict]]:
    """Group WatchGuard services by name across TCP/UDP/ICMP/other."""
    grouped = defaultdict(list)
    
    for proto_type in ['tcp', 'udp', 'icmp', 'other']:
        for service in wg_services.get('services', {}).get(proto_type, []):
            name = service.get('name')
            port = service.get('port')
            
            # Skip services with null ports
            if port is None:
                continue
            
            # Determine protocol
            if proto_type == 'tcp':
                protocol = 'TCP'
            elif proto_type == 'udp':
                protocol = 'UDP'
            elif proto_type == 'icmp':
                protocol = 'ICMP'
            elif proto_type == 'other':
                # Use the protocol field from the service
                protocol = service.get('protocol', 'UNKNOWN')
            else:
                protocol = 'UNKNOWN'
            
            grouped[name].append({
                'protocol': protocol,
                'port': port,
                'description': service.get('description', '')
            })
    
    return grouped


def main():
    # Get FMC connection details from environment variables
    fmc_host = os.getenv('FMC_HOST', '192.168.255.11')
    fmc_username = os.getenv('FMC_USERNAME', 'admin')
    fmc_password = os.getenv('FMC_PASSWORD')
    fmc_domain = os.getenv('FMC_DOMAIN_UUID', 'e276abec-e0f2-11e3-8169-6d9ed49b625f')
    
    if not fmc_password:
        print("Error: FMC_PASSWORD environment variable not set")
        sys.exit(1)
    
    # Get input filenames
    wg_services_file = sys.argv[1] if len(sys.argv) > 1 else "watchguard_services.json"
    dedup_map_file = "port_deduplication_map.json"
    
    print("=" * 80)
    print("Building FMC Service Groups from WatchGuard Services")
    print("=" * 80)
    
    # Load data
    print("\nLoading input files...")
    wg_services = load_watchguard_services(wg_services_file)
    dedup_map = load_deduplication_map(dedup_map_file)
    
    # Initialize FMC client
    client = FMCClient(fmc_host, fmc_username, fmc_password, fmc_domain)
    
    # Authenticate
    if not client.authenticate():
        sys.exit(1)
    
    # Group WatchGuard services by name
    print("\nGrouping WatchGuard services by name...")
    wg_grouped = group_wg_services_by_name(wg_services)
    print(f"✓ Found {len(wg_grouped)} unique WatchGuard service names")
    
    # Track results
    groups_created = []
    objects_created = []
    groups_skipped = []
    errors = []
    mapping = {}
    
    print("\nProcessing WatchGuard services...")
    print("-" * 80)
    
    for wg_name, entries in wg_grouped.items():
        normalized_name = normalize_name(wg_name)
        
        # Skip if only one entry - no need for a group
        if len(entries) == 1:
            entry = entries[0]
            protocol = entry['protocol']
            port = entry['port']
            key = f"{protocol}_{port}"
            
            # Check if canonical object exists in dedup map
            canonical_info = None
            for dup_key, dup_data in dedup_map.get('duplicates', {}).items():
                if dup_key == key:
                    canonical_info = dup_data['canonical']
                    break
            
            if canonical_info:
                # Use existing canonical object
                mapping[wg_name] = {
                    'type': 'single_object',
                    'fmc_object_name': canonical_info['canonical_name'],
                    'fmc_object_id': canonical_info['canonical_id'],
                    'protocol': protocol,
                    'port': port
                }
                print(f"✓ Mapped {wg_name} → {canonical_info['canonical_name']} (existing)")
            else:
                # Check if object exists by name lookup
                if normalized_name in dedup_map.get('name_lookup', {}):
                    obj_info = dedup_map['name_lookup'][normalized_name]
                    mapping[wg_name] = {
                        'type': 'single_object',
                        'fmc_object_name': normalized_name,
                        'fmc_object_id': obj_info['id'],
                        'protocol': protocol,
                        'port': port
                    }
                    print(f"✓ Mapped {wg_name} → {normalized_name} (existing)")
                else:
                    # Create new object
                    result = client.create_port_object(
                        normalized_name,
                        protocol,
                        port,
                        entry.get('description', f"Migrated from WatchGuard: {wg_name}")
                    )
                    if result:
                        objects_created.append(result)
                        mapping[wg_name] = {
                            'type': 'single_object',
                            'fmc_object_name': normalized_name,
                            'fmc_object_id': result['id'],
                            'protocol': protocol,
                            'port': port
                        }
                        print(f"✓ Created {normalized_name} ({protocol}/{port})")
            continue
        
        # Multiple entries - need to create a group
        group_members = []
        custom_objects_for_group = []
        
        for entry in entries:
            protocol = entry['protocol']
            port = entry['port']
            key = f"{protocol}_{port}"
            
            # Check if canonical object exists
            canonical_info = None
            for dup_key, dup_data in dedup_map.get('duplicates', {}).items():
                if dup_key == key:
                    canonical_info = dup_data['canonical']
                    break
            
            if canonical_info:
                # Use existing canonical object
                group_members.append({
                    'type': 'ProtocolPortObject',
                    'id': canonical_info['canonical_id'],
                    'name': canonical_info['canonical_name']
                })
            else:
                # Check name lookup for existing object
                found_existing = False
                for obj_name, obj_info in dedup_map.get('name_lookup', {}).items():
                    if obj_info['protocol'] == protocol and obj_info['port'] == port:
                        group_members.append({
                            'type': 'ProtocolPortObject',
                            'id': obj_info['id'],
                            'name': obj_name
                        })
                        found_existing = True
                        break
                
                if not found_existing:
                    # Create custom object with naming convention
                    if '-' in port:
                        port_suffix = port.replace('-', '-')
                    else:
                        port_suffix = port
                    
                    custom_name = f"{normalized_name}_{protocol}_{port_suffix}"
                    
                    result = client.create_port_object(
                        custom_name,
                        protocol,
                        port,
                        f"Custom port for {wg_name}"
                    )
                    
                    if result:
                        objects_created.append(result)
                        custom_objects_for_group.append(custom_name)
                        group_members.append({
                            'type': 'ProtocolPortObject',
                            'id': result['id'],
                            'name': custom_name
                        })
                        print(f"  ✓ Created custom object {custom_name}")
                    else:
                        errors.append({
                            'service': wg_name,
                            'action': 'create_custom_object',
                            'object_name': custom_name,
                            'error': 'Failed to create'
                        })
        
        # Create the group
        if group_members:
            group_desc = f"Migrated from WatchGuard: {wg_name}"
            result = client.create_port_group(normalized_name, group_members, group_desc)
            
            if result:
                groups_created.append({
                    'name': normalized_name,
                    'id': result['id'],
                    'member_count': len(group_members)
                })
                mapping[wg_name] = {
                    'type': 'group',
                    'fmc_group_name': normalized_name,
                    'fmc_group_id': result['id'],
                    'members': [m['name'] for m in group_members],
                    'custom_objects_created': custom_objects_for_group
                }
                print(f"✓ Created group {normalized_name} with {len(group_members)} members")
            else:
                groups_skipped.append({
                    'name': normalized_name,
                    'reason': 'Failed to create or already exists'
                })
    
    # Write results
    output = {
        'summary': {
            'watchguard_services_processed': len(wg_grouped),
            'fmc_groups_created': len(groups_created),
            'fmc_objects_created': len(objects_created),
            'groups_skipped': len(groups_skipped),
            'errors': len(errors)
        },
        'groups_created': groups_created,
        'objects_created': objects_created,
        'groups_skipped': groups_skipped,
        'errors': errors,
        'wg_to_fmc_mapping': mapping
    }
    
    output_file = "wg_to_fmc_mapping.json"
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    # Print summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"WatchGuard Services Processed: {len(wg_grouped)}")
    print(f"FMC Groups Created:            {len(groups_created)}")
    print(f"FMC Objects Created:           {len(objects_created)}")
    print(f"Groups Skipped:                {len(groups_skipped)}")
    print(f"Errors:                        {len(errors)}")
    print(f"\nResults written to: {output_file}")
    
    if errors:
        print(f"\n⚠ WARNING: {len(errors)} errors occurred during processing")
        print("Check the output file for details")


if __name__ == "__main__":
    main()