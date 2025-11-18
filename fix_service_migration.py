#!/usr/bin/env python3

import json
import sys
import time
import requests
import re
from datetime import datetime
from collections import defaultdict

# Import the service lookup module
from service_lookup import lookup_service_by_protocol_port, get_fmc_service_for_migration

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FMCClient:
    """Client for interacting with Cisco FMC API"""
    
    def __init__(self, host, username, password, domain_uuid=None):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.domain_uuid = domain_uuid
        self.base_url = f"https://{self.host}/api/fmc_config/v1"
        self.platform_url = f"https://{self.host}/api/fmc_platform/v1"
        self.headers = {}
        self.auth_token = None
        self.refresh_token = None
        
    def authenticate(self):
        """Authenticate and get access token"""
        auth_url = f"{self.platform_url}/auth/generatetoken"
        
        try:
            response = requests.post(
                auth_url,
                auth=(self.username, self.password),
                verify=False,
                timeout=30
            )
            
            if response.status_code == 204:
                self.auth_token = response.headers.get('X-auth-access-token')
                self.refresh_token = response.headers.get('X-auth-refresh-token')
                self.domain_uuid = response.headers.get('DOMAIN_UUID')
                
                self.headers = {
                    'Content-Type': 'application/json',
                    'X-auth-access-token': self.auth_token
                }
                
                print(f"✓ Authenticated successfully")
                print(f"  Domain UUID: {self.domain_uuid}")
                return True
            else:
                print(f"✗ Authentication failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"✗ Authentication error: {e}")
            return False
    
    def refresh_auth_token(self):
        """Refresh the authentication token"""
        auth_url = f"{self.platform_url}/auth/refreshtoken"
        
        try:
            response = requests.post(
                auth_url,
                headers={'X-auth-refresh-token': self.refresh_token},
                verify=False,
                timeout=30
            )
            
            if response.status_code == 204:
                self.auth_token = response.headers.get('X-auth-access-token')
                self.refresh_token = response.headers.get('X-auth-refresh-token')
                self.headers['X-auth-access-token'] = self.auth_token
                return True
            else:
                return self.authenticate()
        except Exception as e:
            return self.authenticate()
    
    def _make_request(self, method, endpoint, **kwargs):
        """Make API request with automatic token refresh"""
        kwargs['verify'] = False
        kwargs['timeout'] = 30
        kwargs['headers'] = self.headers
        
        response = requests.request(method, endpoint, **kwargs)
        
        if response.status_code == 401:
            if self.refresh_auth_token():
                kwargs['headers'] = self.headers
                response = requests.request(method, endpoint, **kwargs)
        
        return response
    
    def sanitize_name(self, name):
        """Sanitize object name for FMC"""
        sanitized = name.replace(' ', '_')
        sanitized = re.sub(r'[^a-zA-Z0-9_\-.]', '_', sanitized)
        sanitized = sanitized[:128]
        if sanitized and not re.match(r'^[a-zA-Z0-9_]', sanitized):
            sanitized = 'svc_' + sanitized
        if not sanitized:
            sanitized = f"Service_{hash(name) % 100000}"
        return sanitized
    
    def create_tcp_port(self, name, port, description=""):
        """Create a TCP port object"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/protocolportobjects"
        
        name = self.sanitize_name(name)
        
        payload = {
            "name": name,
            "type": "ProtocolPortObject",
            "protocol": "TCP",
            "port": port,
            "description": description[:500] if description else ""
        }
        
        try:
            response = self._make_request('POST', endpoint, json=payload)
            
            if isinstance(response, dict) and 'error' in response:
                return response
            
            if response.status_code == 201:
                return response.json()
            else:
                return {"error": response.text, "status_code": response.status_code}
        except Exception as e:
            return {"error": str(e)}
    
    def create_udp_port(self, name, port, description=""):
        """Create a UDP port object"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/protocolportobjects"
        
        name = self.sanitize_name(name)
        
        payload = {
            "name": name,
            "type": "ProtocolPortObject",
            "protocol": "UDP",
            "port": port,
            "description": description[:500] if description else ""
        }
        
        try:
            response = self._make_request('POST', endpoint, json=payload)
            
            if isinstance(response, dict) and 'error' in response:
                return response
            
            if response.status_code == 201:
                return response.json()
            else:
                return {"error": response.text, "status_code": response.status_code}
        except Exception as e:
            return {"error": str(e)}
    
    def create_port_group(self, name, member_ids, description=""):
        """Create a port object group"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/portobjectgroups"
        
        name = self.sanitize_name(name)
        
        objects = [{"type": "ProtocolPortObject", "id": obj_id} for obj_id in member_ids]
        
        payload = {
            "name": name,
            "type": "PortObjectGroup",
            "objects": objects,
            "description": description[:500] if description else ""
        }
        
        try:
            response = self._make_request('POST', endpoint, json=payload)
            
            if isinstance(response, dict) and 'error' in response:
                return response
            
            if response.status_code == 201:
                return response.json()
            else:
                return {"error": response.text, "status_code": response.status_code}
        except Exception as e:
            return {"error": str(e)}


def strip_suffix(name):
    """Strip .N suffix from service name to get base name"""
    # Match pattern like .1, .2, .10, etc at the end
    match = re.match(r'^(.+?)\.(\d+)$', name)
    if match:
        return match.group(1), match.group(2)
    return name, None


def migrate_services(wg_config_file, fmc_host, fmc_user, fmc_pass, dry_run=True):
    """Migrate WatchGuard services to FMC with proper deduplication and grouping"""
    
    print("="*60)
    print("WATCHGUARD SERVICE MIGRATION FIXER")
    print("="*60)
    print("\nUsing service_lookup.py for canonical port mappings")
    
    # Load WatchGuard config
    print(f"\nLoading WatchGuard configuration from {wg_config_file}...")
    try:
        with open(wg_config_file, 'r') as f:
            wg_config = json.load(f)
        tcp_services = wg_config.get('services', {}).get('tcp', [])
        udp_services = wg_config.get('services', {}).get('udp', [])
        print(f"✓ Found {len(tcp_services)} TCP and {len(udp_services)} UDP services")
    except Exception as e:
        print(f"✗ Failed to load config: {e}")
        return False
    
    # Analyze services and build migration plan
    print("\nAnalyzing services...")
    
    # Group services by base name and protocol/port
    tcp_by_base = defaultdict(list)
    udp_by_base = defaultdict(list)
    
    for svc in tcp_services:
        base_name, suffix = strip_suffix(svc['name'])
        tcp_by_base[base_name].append({
            'original_name': svc['name'],
            'port': svc['port'],
            'description': svc.get('description', ''),
            'suffix': suffix
        })
    
    for svc in udp_services:
        base_name, suffix = strip_suffix(svc['name'])
        udp_by_base[base_name].append({
            'original_name': svc['name'],
            'port': svc['port'],
            'description': svc.get('description', ''),
            'suffix': suffix
        })
    
    # Build migration plan
    migration_plan = {
        'use_builtin': [],  # Services that map to FMC built-ins
        'create_custom': [],  # Custom port objects to create
        'create_groups': [],  # Groups to create for multi-port services
        'skipped': []  # Services skipped (port 0, null, etc)
    }
    
    service_mapping = {}  # Original name -> FMC object info
    
    print("\nBuilding migration plan using canonical mappings...")
    
    # Process TCP services
    for base_name, services in tcp_by_base.items():
        # Deduplicate by port
        unique_ports = {}
        for svc in services:
            port = svc['port']
            if port not in unique_ports:
                unique_ports[port] = svc
        
        services_to_create = []
        
        for port, svc in unique_ports.items():
            # Skip invalid ports
            if port is None or port == '' or port == '0':
                migration_plan['skipped'].append({
                    'name': svc['original_name'],
                    'reason': f'Invalid port: {port}'
                })
                for orig_svc in services:
                    if orig_svc['port'] == port:
                        service_mapping[orig_svc['original_name']] = {
                            'type': 'skipped',
                            'reason': f'Invalid port: {port}'
                        }
                continue
            
            # Use service lookup to get canonical mapping
            canonical = lookup_service_by_protocol_port('TCP', str(port))
            if canonical:
                migration_plan['use_builtin'].append({
                    'wg_base_name': base_name,
                    'wg_port': port,
                    'fmc_name': canonical['name'],
                    'fmc_id': canonical['id']
                })
                
                # Map all variants with this port to the canonical object
                for orig_svc in services:
                    if orig_svc['port'] == port:
                        service_mapping[orig_svc['original_name']] = {
                            'type': 'builtin',
                            'fmc_name': canonical['name'],
                            'fmc_id': canonical['id'],
                            'protocol': 'TCP',
                            'port': port
                        }
            else:
                # Custom port - need to create
                custom_name = f"{base_name}_TCP_{port}"
                services_to_create.append({
                    'custom_name': custom_name,
                    'port': port,
                    'description': svc['description']
                })
                
                # Map all variants with this port to the custom object
                for orig_svc in services:
                    if orig_svc['port'] == port:
                        service_mapping[orig_svc['original_name']] = {
                            'type': 'custom',
                            'custom_name': custom_name,
                            'protocol': 'TCP',
                            'port': port,
                            'needs_creation': True
                        }
        
        # Add custom services to plan
        for svc_info in services_to_create:
            migration_plan['create_custom'].append({
                'name': svc_info['custom_name'],
                'protocol': 'TCP',
                'port': svc_info['port'],
                'description': svc_info['description']
            })
        
        # If multiple custom ports for same base name, create a group
        if len(services_to_create) > 1:
            migration_plan['create_groups'].append({
                'name': f"{base_name}_Group",
                'base_name': base_name,
                'protocol': 'TCP',
                'members': [s['custom_name'] for s in services_to_create]
            })
    
    # Process UDP services (same logic with canonical lookup)
    for base_name, services in udp_by_base.items():
        unique_ports = {}
        for svc in services:
            port = svc['port']
            if port not in unique_ports:
                unique_ports[port] = svc
        
        services_to_create = []
        
        for port, svc in unique_ports.items():
            if port is None or port == '' or port == '0':
                migration_plan['skipped'].append({
                    'name': svc['original_name'],
                    'reason': f'Invalid port: {port}'
                })
                for orig_svc in services:
                    if orig_svc['port'] == port:
                        service_mapping[orig_svc['original_name']] = {
                            'type': 'skipped',
                            'reason': f'Invalid port: {port}'
                        }
                continue
            
            # Use service lookup to get canonical mapping
            canonical = lookup_service_by_protocol_port('UDP', str(port))
            if canonical:
                migration_plan['use_builtin'].append({
                    'wg_base_name': base_name,
                    'wg_port': port,
                    'fmc_name': canonical['name'],
                    'fmc_id': canonical['id']
                })
                
                for orig_svc in services:
                    if orig_svc['port'] == port:
                        service_mapping[orig_svc['original_name']] = {
                            'type': 'builtin',
                            'fmc_name': canonical['name'],
                            'fmc_id': canonical['id'],
                            'protocol': 'UDP',
                            'port': port
                        }
            else:
                custom_name = f"{base_name}_UDP_{port}"
                services_to_create.append({
                    'custom_name': custom_name,
                    'port': port,
                    'description': svc['description']
                })
                
                for orig_svc in services:
                    if orig_svc['port'] == port:
                        service_mapping[orig_svc['original_name']] = {
                            'type': 'custom',
                            'custom_name': custom_name,
                            'protocol': 'UDP',
                            'port': port,
                            'needs_creation': True
                        }
        
        for svc_info in services_to_create:
            migration_plan['create_custom'].append({
                'name': svc_info['custom_name'],
                'protocol': 'UDP',
                'port': svc_info['port'],
                'description': svc_info['description']
            })
        
        if len(services_to_create) > 1:
            migration_plan['create_groups'].append({
                'name': f"{base_name}_Group",
                'base_name': base_name,
                'protocol': 'UDP',
                'members': [s['custom_name'] for s in services_to_create]
            })
    
    # Print migration plan summary
    print("\n" + "="*60)
    print("MIGRATION PLAN SUMMARY")
    print("="*60)
    print(f"\nBuilt-in mappings:     {len(migration_plan['use_builtin'])}")
    print(f"Custom objects:        {len(migration_plan['create_custom'])}")
    print(f"Groups to create:      {len(migration_plan['create_groups'])}")
    print(f"Skipped services:      {len(migration_plan['skipped'])}")
    print(f"\nTotal WG services:     {len(tcp_services) + len(udp_services)}")
    print(f"Total mappings:        {len(service_mapping)}")
    
    # Show sample canonical mappings
    print("\nSample canonical mappings:")
    sample_count = 0
    for mapping in migration_plan['use_builtin'][:5]:
        print(f"  {mapping['wg_base_name']} (port {mapping['wg_port']}) → {mapping['fmc_name']}")
        sample_count += 1
    if len(migration_plan['use_builtin']) > 5:
        print(f"  ... and {len(migration_plan['use_builtin']) - 5} more")
    
    # Save migration plan
    plan_file = f"service_migration_plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(plan_file, 'w') as f:
        json.dump(migration_plan, f, indent=2)
    print(f"\n✓ Migration plan saved to: {plan_file}")
    
    # Save service mapping
    mapping_file = f"service_mapping_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(mapping_file, 'w') as f:
        json.dump({
            'metadata': {
                'generated': datetime.now().isoformat(),
                'total_services': len(service_mapping)
            },
            'mappings': service_mapping
        }, f, indent=2)
    print(f"✓ Service mapping saved to: {mapping_file}")
    
    if dry_run:
        print("\n⚠  DRY RUN MODE - No objects will be created in FMC")
        print("  Review the migration plan and run with --execute to create objects")
        return True
    
    # Execute migration
    print("\n" + "="*60)
    print("EXECUTING MIGRATION")
    print("="*60)
    
    fmc = FMCClient(fmc_host, fmc_user, fmc_pass)
    if not fmc.authenticate():
        print("\n✗ Failed to authenticate with FMC")
        return False
    
    created_objects = {}  # custom_name -> FMC ID
    
    # Create custom port objects
    print(f"\nCreating {len(migration_plan['create_custom'])} custom port objects...")
    for i, svc in enumerate(migration_plan['create_custom'], 1):
        print(f"  [{i}/{len(migration_plan['create_custom'])}] {svc['name']}...", end='', flush=True)
        
        if svc['protocol'] == 'TCP':
            result = fmc.create_tcp_port(svc['name'], svc['port'], svc['description'])
        else:
            result = fmc.create_udp_port(svc['name'], svc['port'], svc['description'])
        
        if 'error' in result:
            print(f" ✗ FAILED: {result['error'][:60]}")
        else:
            print(f" ✓")
            created_objects[svc['name']] = result['id']
            
            # Update service mapping with created ID
            for orig_name, mapping in service_mapping.items():
                if mapping.get('custom_name') == svc['name']:
                    mapping['fmc_id'] = result['id']
                    mapping['needs_creation'] = False
        
        time.sleep(0.3)
    
    # Create groups
    print(f"\nCreating {len(migration_plan['create_groups'])} service groups...")
    for i, group in enumerate(migration_plan['create_groups'], 1):
        print(f"  [{i}/{len(migration_plan['create_groups'])}] {group['name']}...", end='', flush=True)
        
        # Get member IDs
        member_ids = []
        for member_name in group['members']:
            if member_name in created_objects:
                member_ids.append(created_objects[member_name])
        
        if not member_ids:
            print(f" ⊘ SKIPPED (no valid members)")
            continue
        
        result = fmc.create_port_group(
            group['name'],
            member_ids,
            f"Group for {group['base_name']} services"
        )
        
        if 'error' in result:
            print(f" ✗ FAILED: {result['error'][:60]}")
        else:
            print(f" ✓")
            # Optionally store group ID for reference
        
        time.sleep(0.3)
    
    # Save final mapping with FMC IDs
    final_mapping_file = f"service_mapping_final_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(final_mapping_file, 'w') as f:
        json.dump({
            'metadata': {
                'generated': datetime.now().isoformat(),
                'total_services': len(service_mapping),
                'created_customs': len(created_objects),
                'created_groups': len(migration_plan['create_groups'])
            },
            'mappings': service_mapping
        }, f, indent=2)
    print(f"\n✓ Final service mapping saved to: {final_mapping_file}")
    
    print("\n" + "="*60)
    print("MIGRATION COMPLETE")
    print("="*60)
    print(f"\nCustom objects created: {len(created_objects)}")
    print(f"Groups created:         {len(migration_plan['create_groups'])}")
    print(f"Built-in mappings:      {len(migration_plan['use_builtin'])}")
    
    return True


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python fix_service_migration.py <wg_config.json> <fmc_host> <username> <password> [--execute]")
        print("\nExample:")
        print("  # Dry run (default)")
        print("  python fix_service_migration.py watchguard_services.json 192.168.1.100 admin pass")
        print("\n  # Execute migration")
        print("  python fix_service_migration.py watchguard_services.json 192.168.1.100 admin pass --execute")
        sys.exit(1)
    
    wg_config = sys.argv[1]
    fmc_host = sys.argv[2]
    username = sys.argv[3]
    password = sys.argv[4]
    dry_run = '--execute' not in sys.argv
    
    success = migrate_services(wg_config, fmc_host, username, password, dry_run)
    sys.exit(0 if success else 1)