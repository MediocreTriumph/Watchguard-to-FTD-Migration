#!/usr/bin/env python3
"""
Analyze all FMC service objects and create deduplication mapping.
Groups services by protocol+port and identifies canonical names.
"""

import requests
import json
import os
import sys
from urllib3.exceptions import InsecureRequestWarning
from typing import Dict, List, Set
from collections import defaultdict

# Suppress SSL warnings for self-signed certs
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Well-known port names (preferred canonical names)
WELLKNOWN_NAMES = {
    "TCP_20": "FTP-DATA",
    "TCP_21": "FTP",
    "TCP_22": "SSH",
    "TCP_23": "TELNET",
    "TCP_25": "SMTP",
    "TCP_53": "DNS",
    "UDP_53": "DNS",
    "TCP_67": "DHCP-Server",
    "UDP_67": "DHCP-Server",
    "UDP_68": "DHCP-Client",
    "UDP_69": "TFTP",
    "TCP_80": "HTTP",
    "TCP_88": "Kerberos",
    "UDP_88": "Kerberos",
    "TCP_110": "POP3",
    "TCP_123": "NTP",
    "UDP_123": "NTP",
    "TCP_135": "MSRPC",
    "UDP_137": "NetBIOS-NS",
    "UDP_138": "NetBIOS-DGM",
    "TCP_139": "NetBIOS-SSN",
    "TCP_143": "IMAP",
    "UDP_161": "SNMP",
    "UDP_162": "SNMP-Trap",
    "TCP_179": "BGP",
    "TCP_389": "LDAP",
    "TCP_443": "HTTPS",
    "TCP_445": "SMB",
    "UDP_445": "SMB",
    "TCP_465": "SMTPS",
    "UDP_514": "SYSLOG",
    "TCP_515": "LPR",
    "UDP_520": "RIP",
    "TCP_587": "SMTP-Submission",
    "TCP_636": "LDAPS",
    "TCP_993": "IMAPS",
    "TCP_995": "POP3S",
    "UDP_1194": "OpenVPN",
    "TCP_1433": "MSSQL",
    "UDP_1433": "MSSQL",
    "TCP_1434": "MSSQL-Monitor",
    "UDP_1434": "MSSQL-Monitor",
    "TCP_1521": "Oracle",
    "UDP_1701": "L2TP",
    "TCP_1723": "PPTP",
    "UDP_1812": "RADIUS",
    "UDP_1813": "RADIUS-Acct",
    "TCP_2049": "NFS",
    "UDP_2049": "NFS",
    "TCP_3268": "LDAP-GC",
    "TCP_3269": "LDAP-GC-SSL",
    "TCP_3306": "MySQL",
    "TCP_3389": "RDP",
    "TCP_5060": "SIP",
    "UDP_5060": "SIP",
    "TCP_5061": "SIP-TLS",
    "UDP_5061": "SIP-TLS",
    "TCP_5432": "PostgreSQL",
    "UDP_5500": "VNC",
    "TCP_5900": "VNC",
    "TCP_5985": "WinRM-HTTP",
    "TCP_5986": "WinRM-HTTPS",
    "TCP_6379": "Redis",
    "TCP_8080": "HTTP-Alt",
    "TCP_8443": "HTTPS-Alt",
    "TCP_9000": "SonarQube",
    "TCP_27017": "MongoDB",
}


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
    
    def get_all_port_objects(self) -> List[Dict]:
        """Get all port objects from FMC with pagination."""
        url = f"{self.base_url}/domain/{self.domain_uuid}/object/protocolportobjects"
        all_objects = []
        offset = 0
        limit = 100
        
        while True:
            params = {'offset': offset, 'limit': limit, 'expanded': True}
            try:
                response = requests.get(url, headers=self.headers, params=params, verify=False)
                if response.status_code == 200:
                    data = response.json()
                    items = data.get('items', [])
                    all_objects.extend(items)
                    
                    # Check if there are more pages
                    paging = data.get('paging', {})
                    if offset + len(items) >= paging.get('count', 0):
                        break
                    offset += limit
                else:
                    print(f"✗ Failed to get port objects: {response.status_code}")
                    break
            except Exception as e:
                print(f"✗ Error getting port objects: {e}")
                break
        
        print(f"✓ Retrieved {len(all_objects)} port objects from FMC")
        return all_objects
    
    def get_all_port_groups(self) -> List[Dict]:
        """Get all port group objects from FMC with pagination."""
        url = f"{self.base_url}/domain/{self.domain_uuid}/object/portobjectgroups"
        all_groups = []
        offset = 0
        limit = 100
        
        while True:
            params = {'offset': offset, 'limit': limit, 'expanded': True}
            try:
                response = requests.get(url, headers=self.headers, params=params, verify=False)
                if response.status_code == 200:
                    data = response.json()
                    items = data.get('items', [])
                    all_groups.extend(items)
                    
                    # Check if there are more pages
                    paging = data.get('paging', {})
                    if offset + len(items) >= paging.get('count', 0):
                        break
                    offset += limit
                else:
                    print(f"✗ Failed to get port groups: {response.status_code}")
                    break
            except Exception as e:
                print(f"✗ Error getting port groups: {e}")
                break
        
        print(f"✓ Retrieved {len(all_groups)} port groups from FMC")
        return all_groups


def parse_port_range(port_str: str) -> List[int]:
    """Parse port string (e.g., '80' or '8000-8010') into list of ports."""
    if '-' in port_str:
        start, end = port_str.split('-')
        return list(range(int(start), int(end) + 1))
    else:
        return [int(port_str)]


def determine_canonical_name(objects: List[Dict], protocol: str, port: str) -> Dict:
    """
    Determine the canonical name for a protocol+port combination.
    Priority: well-known name > shortest name > alphabetical
    """
    key = f"{protocol}_{port}"
    
    # Check if there's a well-known name
    if key in WELLKNOWN_NAMES:
        wellknown = WELLKNOWN_NAMES[key]
        # Find the object with this name
        for obj in objects:
            if obj['name'] == wellknown:
                return {
                    'canonical_name': wellknown,
                    'canonical_id': obj['id'],
                    'reason': 'well-known',
                    'all_names': [o['name'] for o in objects]
                }
    
    # If no well-known name, use shortest name
    shortest = min(objects, key=lambda x: len(x['name']))
    
    # If multiple objects have the same shortest length, use alphabetical
    shortest_length = len(shortest['name'])
    shortest_objects = [o for o in objects if len(o['name']) == shortest_length]
    canonical = min(shortest_objects, key=lambda x: x['name'])
    
    return {
        'canonical_name': canonical['name'],
        'canonical_id': canonical['id'],
        'reason': 'shortest_alphabetical',
        'all_names': [o['name'] for o in objects]
    }


def main():
    # Get FMC connection details from environment variables
    fmc_host = os.getenv('FMC_HOST', '192.168.255.11')
    fmc_username = os.getenv('FMC_USERNAME', 'admin')
    fmc_password = os.getenv('FMC_PASSWORD')
    fmc_domain = os.getenv('FMC_DOMAIN_UUID', 'e276abec-e0f2-11e3-8169-6d9ed49b625f')
    
    if not fmc_password:
        print("Error: FMC_PASSWORD environment variable not set")
        sys.exit(1)
    
    print("=" * 80)
    print("Analyzing FMC Service Objects for Deduplication")
    print("=" * 80)
    
    # Initialize FMC client
    client = FMCClient(fmc_host, fmc_username, fmc_password, fmc_domain)
    
    # Authenticate
    if not client.authenticate():
        sys.exit(1)
    
    # Get all port objects and groups
    port_objects = client.get_all_port_objects()
    port_groups = client.get_all_port_groups()
    
    # Group port objects by protocol+port
    protocol_port_map = defaultdict(list)
    
    print("\nGrouping services by protocol+port...")
    print("-" * 80)
    
    for obj in port_objects:
        protocol = obj.get('protocol', 'UNKNOWN')
        port = obj.get('port', '0')
        
        # Handle port ranges by creating entries for each port
        try:
            ports = parse_port_range(port)
            for p in ports:
                key = f"{protocol}_{p}"
                protocol_port_map[key].append(obj)
        except Exception as e:
            print(f"⚠ Warning: Could not parse port '{port}' for {obj['name']}: {e}")
    
    # Find duplicates and determine canonical names
    duplicates = {}
    canonical_map = {}
    
    for key, objects in protocol_port_map.items():
        if len(objects) > 1:
            # Multiple objects for same protocol+port
            protocol, port = key.split('_')
            canonical_info = determine_canonical_name(objects, protocol, port)
            
            duplicates[key] = {
                'protocol': protocol,
                'port': port,
                'count': len(objects),
                'canonical': canonical_info
            }
            
            # Map each object to its canonical
            for obj in objects:
                canonical_map[obj['id']] = {
                    'object_name': obj['name'],
                    'object_id': obj['id'],
                    'protocol': protocol,
                    'port': port,
                    'canonical_name': canonical_info['canonical_name'],
                    'canonical_id': canonical_info['canonical_id'],
                    'is_canonical': obj['id'] == canonical_info['canonical_id']
                }
            
            print(f"✓ {key}: {len(objects)} duplicates → canonical: {canonical_info['canonical_name']}")
    
    # Create lookup by name
    name_lookup = {}
    for obj in port_objects:
        name_lookup[obj['name']] = {
            'id': obj['id'],
            'protocol': obj.get('protocol'),
            'port': obj.get('port')
        }
    
    # Create output
    output = {
        'summary': {
            'total_port_objects': len(port_objects),
            'total_port_groups': len(port_groups),
            'unique_protocol_ports': len(protocol_port_map),
            'duplicate_protocol_ports': len(duplicates),
            'total_duplicate_objects': sum(d['count'] for d in duplicates.values())
        },
        'duplicates': duplicates,
        'canonical_map': canonical_map,
        'name_lookup': name_lookup,
        'port_groups': {g['name']: {'id': g['id'], 'objects': g.get('objects', [])} for g in port_groups}
    }
    
    output_file = "port_deduplication_map.json"
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    # Print summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total Port Objects:           {len(port_objects)}")
    print(f"Total Port Groups:            {len(port_groups)}")
    print(f"Unique Protocol+Port Combos:  {len(protocol_port_map)}")
    print(f"Duplicate Protocol+Ports:     {len(duplicates)}")
    print(f"Total Duplicate Objects:      {sum(d['count'] for d in duplicates.values())}")
    print(f"\nResults written to: {output_file}")
    
    if duplicates:
        print(f"\n⚠ Found {len(duplicates)} protocol+port combinations with duplicates")
        print("Review the output file to see canonical mappings")


if __name__ == "__main__":
    main()