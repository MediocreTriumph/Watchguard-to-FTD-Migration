#!/usr/bin/env python3

import json
import sys
import requests
from datetime import datetime

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FMCClient:
    """Client for interacting with Cisco FMC API"""
    
    def __init__(self, host, username, password):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.domain_uuid = None
        self.base_url = f"https://{self.host}/api/fmc_config/v1"
        self.platform_url = f"https://{self.host}/api/fmc_platform/v1"
        self.headers = {}
        self.auth_token = None
        
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
    
    def _make_request(self, method, endpoint, **kwargs):
        """Make API request"""
        kwargs['verify'] = False
        kwargs['timeout'] = 30
        kwargs['headers'] = self.headers
        
        try:
            response = requests.request(method, endpoint, **kwargs)
            return response
        except Exception as e:
            return {"error": str(e)}
    
    def get_all_port_objects(self, protocol=None):
        """Fetch all protocol port objects with pagination"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/protocolportobjects"
        
        all_ports = []
        offset = 0
        limit = 1000
        
        protocol_filter = f" ({protocol})" if protocol else ""
        print(f"\nFetching{protocol_filter} port objects from FMC...")
        
        while True:
            params = {
                'offset': offset,
                'limit': limit,
                'expanded': True
            }
            
            response = self._make_request('GET', endpoint, params=params)
            
            if isinstance(response, dict) and 'error' in response:
                print(f"✗ Error fetching port objects: {response['error']}")
                return None
            
            if response.status_code != 200:
                print(f"✗ Failed: {response.status_code}")
                return None
            
            data = response.json()
            items = data.get('items', [])
            
            if not items:
                break
            
            # Filter by protocol if specified
            if protocol:
                items = [item for item in items if item.get('protocol') == protocol]
            
            all_ports.extend(items)
            print(f"  Fetched {len(all_ports)} objects...", end='\r', flush=True)
            
            paging = data.get('paging', {})
            if not paging.get('next'):
                break
            
            offset += limit
        
        print(f"  Fetched {len(all_ports)} objects... ✓")
        return all_ports
    
    def get_all_icmp_objects(self):
        """Fetch all ICMP objects"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/icmpv4objects"
        
        all_icmp = []
        offset = 0
        limit = 1000
        
        print(f"\nFetching ICMP objects from FMC...")
        
        while True:
            params = {
                'offset': offset,
                'limit': limit,
                'expanded': True
            }
            
            response = self._make_request('GET', endpoint, params=params)
            
            if isinstance(response, dict) and 'error' in response:
                print(f"✗ Error fetching ICMP objects: {response['error']}")
                return None
            
            if response.status_code != 200:
                print(f"✗ Failed: {response.status_code}")
                return None
            
            data = response.json()
            items = data.get('items', [])
            
            if not items:
                break
            
            all_icmp.extend(items)
            print(f"  Fetched {len(all_icmp)} objects...", end='\r', flush=True)
            
            paging = data.get('paging', {})
            if not paging.get('next'):
                break
            
            offset += limit
        
        print(f"  Fetched {len(all_icmp)} objects... ✓")
        return all_icmp


def build_port_database(fmc_host, username, password, output_file="fmc_builtin_ports.json"):
    """Main function to fetch and save FMC built-in port objects"""
    
    print("="*60)
    print("FMC BUILT-IN PORT OBJECTS FETCHER")
    print("="*60)
    
    # Connect to FMC
    print(f"\nConnecting to FMC at {fmc_host}...")
    fmc = FMCClient(fmc_host, username, password)
    
    if not fmc.authenticate():
        print("\n✗ Failed to authenticate with FMC")
        return False
    
    # Fetch all port objects
    all_ports = fmc.get_all_port_objects()
    if all_ports is None:
        print("\n✗ Failed to fetch port objects")
        return False
    
    # Fetch ICMP objects
    all_icmp = fmc.get_all_icmp_objects()
    if all_icmp is None:
        print("\n✗ Failed to fetch ICMP objects")
        return False
    
    # Build structured database
    print("\nBuilding port object database...")
    
    database = {
        "metadata": {
            "fetched_date": datetime.now().isoformat(),
            "fmc_host": fmc_host,
            "domain_uuid": fmc.domain_uuid,
            "total_port_objects": len(all_ports),
            "total_icmp_objects": len(all_icmp)
        },
        "port_objects": {},
        "icmp_objects": {},
        "lookup_index": {}  # protocol_port -> object for fast lookup
    }
    
    # Process port objects
    for port_obj in all_ports:
        obj_id = port_obj.get('id')
        obj_name = port_obj.get('name')
        protocol = port_obj.get('protocol', 'UNKNOWN')
        port = port_obj.get('port', '0')
        
        # Store full object data
        database["port_objects"][obj_id] = {
            "id": obj_id,
            "name": obj_name,
            "type": port_obj.get('type'),
            "protocol": protocol,
            "port": port,
            "description": port_obj.get('description', ''),
            "overridable": port_obj.get('overridable', False)
        }
        
        # Build lookup index: TCP_80, UDP_53, etc.
        lookup_key = f"{protocol}_{port}"
        if lookup_key not in database["lookup_index"]:
            database["lookup_index"][lookup_key] = []
        database["lookup_index"][lookup_key].append({
            "id": obj_id,
            "name": obj_name
        })
    
    # Process ICMP objects
    for icmp_obj in all_icmp:
        obj_id = icmp_obj.get('id')
        obj_name = icmp_obj.get('name')
        
        database["icmp_objects"][obj_id] = {
            "id": obj_id,
            "name": obj_name,
            "type": icmp_obj.get('type'),
            "icmpType": icmp_obj.get('icmpType', 'ANY'),
            "code": icmp_obj.get('code'),
            "description": icmp_obj.get('description', ''),
            "overridable": icmp_obj.get('overridable', False)
        }
    
    # Save to file
    print(f"\nSaving database to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(database, f, indent=2)
    
    print("\n" + "="*60)
    print("DATABASE BUILD COMPLETE")
    print("="*60)
    print(f"\n✓ {len(all_ports)} port objects indexed")
    print(f"✓ {len(all_icmp)} ICMP objects indexed")
    print(f"✓ {len(database['lookup_index'])} unique protocol/port combinations")
    print(f"\n✓ Database saved to: {output_file}")
    
    # Print sample lookups
    print("\nSample protocol/port lookups available:")
    sample_keys = sorted(list(database["lookup_index"].keys()))[:15]
    for key in sample_keys:
        objects = database["lookup_index"][key]
        print(f"  {key}: {len(objects)} object(s) - {objects[0]['name']}")
    
    if len(database["lookup_index"]) > 15:
        print(f"  ... and {len(database['lookup_index']) - 15} more")
    
    return True


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python fetch_fmc_builtin_ports.py <fmc_host> <username> <password> [output_file]")
        print("\nExample:")
        print("  python fetch_fmc_builtin_ports.py 192.168.1.100 admin Cisco123!")
        print("  python fetch_fmc_builtin_ports.py 192.168.1.100 admin Cisco123! my_ports.json")
        sys.exit(1)
    
    fmc_host = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    output_file = sys.argv[4] if len(sys.argv) > 4 else "fmc_builtin_ports.json"
    
    success = build_port_database(fmc_host, username, password, output_file)
    sys.exit(0 if success else 1)