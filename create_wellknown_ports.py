#!/usr/bin/env python3
"""
Create well-known port objects on Cisco FMC based on IANA registry.
Covers well-known ports (0-1023) and common registered ports (1024-49151).
"""

import requests
import json
import os
import sys
from urllib3.exceptions import InsecureRequestWarning
from typing import Dict, List, Optional

# Suppress SSL warnings for self-signed certs
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# IANA Well-Known and Common Registered Ports
# Format: (port, protocol, name, description)
IANA_PORTS = [
    # Well-Known Ports (0-1023)
    (20, "TCP", "FTP-DATA", "File Transfer Protocol (Data)"),
    (21, "TCP", "FTP", "File Transfer Protocol (Control)"),
    (22, "TCP", "SSH", "Secure Shell"),
    (23, "TCP", "TELNET", "Telnet"),
    (25, "TCP", "SMTP", "Simple Mail Transfer Protocol"),
    (53, "TCP", "DNS", "Domain Name System"),
    (53, "UDP", "DNS", "Domain Name System"),
    (67, "UDP", "DHCP-Server", "Dynamic Host Configuration Protocol Server"),
    (68, "UDP", "DHCP-Client", "Dynamic Host Configuration Protocol Client"),
    (69, "UDP", "TFTP", "Trivial File Transfer Protocol"),
    (80, "TCP", "HTTP", "Hypertext Transfer Protocol"),
    (88, "TCP", "Kerberos", "Kerberos Authentication"),
    (88, "UDP", "Kerberos", "Kerberos Authentication"),
    (110, "TCP", "POP3", "Post Office Protocol v3"),
    (123, "TCP", "NTP", "Network Time Protocol"),
    (123, "UDP", "NTP", "Network Time Protocol"),
    (135, "TCP", "MSRPC", "Microsoft RPC"),
    (137, "UDP", "NetBIOS-NS", "NetBIOS Name Service"),
    (138, "UDP", "NetBIOS-DGM", "NetBIOS Datagram Service"),
    (139, "TCP", "NetBIOS-SSN", "NetBIOS Session Service"),
    (143, "TCP", "IMAP", "Internet Message Access Protocol"),
    (161, "UDP", "SNMP", "Simple Network Management Protocol"),
    (162, "UDP", "SNMP-Trap", "SNMP Trap"),
    (179, "TCP", "BGP", "Border Gateway Protocol"),
    (389, "TCP", "LDAP", "Lightweight Directory Access Protocol"),
    (443, "TCP", "HTTPS", "HTTP over TLS/SSL"),
    (445, "TCP", "SMB", "Server Message Block"),
    (445, "UDP", "SMB", "Server Message Block"),
    (465, "TCP", "SMTPS", "SMTP over TLS/SSL"),
    (514, "UDP", "SYSLOG", "Syslog"),
    (515, "TCP", "LPR", "Line Printer Daemon"),
    (520, "UDP", "RIP", "Routing Information Protocol"),
    (587, "TCP", "SMTP-Submission", "SMTP Message Submission"),
    (636, "TCP", "LDAPS", "LDAP over TLS/SSL"),
    (993, "TCP", "IMAPS", "IMAP over TLS/SSL"),
    (995, "TCP", "POP3S", "POP3 over TLS/SSL"),
    
    # Common Registered Ports (1024-49151)
    (1194, "UDP", "OpenVPN", "OpenVPN"),
    (1433, "TCP", "MSSQL", "Microsoft SQL Server"),
    (1433, "UDP", "MSSQL", "Microsoft SQL Server"),
    (1434, "TCP", "MSSQL-Monitor", "Microsoft SQL Monitor"),
    (1434, "UDP", "MSSQL-Monitor", "Microsoft SQL Monitor"),
    (1521, "TCP", "Oracle", "Oracle Database"),
    (1701, "UDP", "L2TP", "Layer 2 Tunneling Protocol"),
    (1723, "TCP", "PPTP", "Point-to-Point Tunneling Protocol"),
    (1812, "UDP", "RADIUS", "RADIUS Authentication"),
    (1813, "UDP", "RADIUS-Acct", "RADIUS Accounting"),
    (2049, "TCP", "NFS", "Network File System"),
    (2049, "UDP", "NFS", "Network File System"),
    (3268, "TCP", "LDAP-GC", "LDAP Global Catalog"),
    (3269, "TCP", "LDAP-GC-SSL", "LDAP Global Catalog over SSL"),
    (3306, "TCP", "MySQL", "MySQL Database"),
    (3389, "TCP", "RDP", "Remote Desktop Protocol"),
    (5060, "TCP", "SIP", "Session Initiation Protocol"),
    (5060, "UDP", "SIP", "Session Initiation Protocol"),
    (5061, "TCP", "SIP-TLS", "SIP over TLS"),
    (5061, "UDP", "SIP-TLS", "SIP over TLS"),
    (5432, "TCP", "PostgreSQL", "PostgreSQL Database"),
    (5500, "UDP", "VNC", "Virtual Network Computing"),
    (5900, "TCP", "VNC", "Virtual Network Computing"),
    (5985, "TCP", "WinRM-HTTP", "Windows Remote Management over HTTP"),
    (5986, "TCP", "WinRM-HTTPS", "Windows Remote Management over HTTPS"),
    (6379, "TCP", "Redis", "Redis Database"),
    (8080, "TCP", "HTTP-Alt", "HTTP Alternate"),
    (8443, "TCP", "HTTPS-Alt", "HTTPS Alternate"),
    (9000, "TCP", "SonarQube", "SonarQube Server"),
    (27017, "TCP", "MongoDB", "MongoDB Database"),
]


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
    
    def get_existing_port_objects(self) -> Dict[str, Dict]:
        """Get all existing port objects from FMC."""
        url = f"{self.base_url}/domain/{self.domain_uuid}/object/protocolportobjects"
        params = {'limit': 1000}
        existing_ports = {}
        
        try:
            response = requests.get(url, headers=self.headers, params=params, verify=False)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('items', []):
                    key = f"{item.get('protocol')}_{item.get('port')}"
                    existing_ports[key] = item
                print(f"✓ Found {len(existing_ports)} existing port objects")
            else:
                print(f"✗ Failed to get existing ports: {response.status_code}")
        except Exception as e:
            print(f"✗ Error getting existing ports: {e}")
        
        return existing_ports
    
    def create_port_object(self, name: str, protocol: str, port: str, description: str) -> Optional[Dict]:
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
                print(f"✗ Failed to create {name}: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"✗ Error creating {name}: {e}")
            return None


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
    print("Creating Well-Known Port Objects on FMC")
    print("=" * 80)
    
    # Initialize FMC client
    client = FMCClient(fmc_host, fmc_username, fmc_password, fmc_domain)
    
    # Authenticate
    if not client.authenticate():
        sys.exit(1)
    
    # Get existing port objects
    existing_ports = client.get_existing_port_objects()
    
    # Track results
    created = []
    skipped = []
    failed = []
    
    print(f"\nProcessing {len(IANA_PORTS)} IANA port definitions...")
    print("-" * 80)
    
    # Create port objects
    for port_num, protocol, name, description in IANA_PORTS:
        key = f"{protocol}_{port_num}"
        
        # Check if port already exists
        if key in existing_ports:
            skipped.append({
                "name": name,
                "protocol": protocol,
                "port": port_num,
                "reason": "Already exists"
            })
            print(f"⊘ Skipped {name} ({protocol}/{port_num}) - already exists")
            continue
        
        # Create the port object
        result = client.create_port_object(name, protocol, str(port_num), description)
        
        if result:
            created.append({
                "name": name,
                "protocol": protocol,
                "port": port_num,
                "id": result.get('id'),
                "description": description
            })
            print(f"✓ Created {name} ({protocol}/{port_num})")
        else:
            failed.append({
                "name": name,
                "protocol": protocol,
                "port": port_num,
                "description": description
            })
    
    # Write results to file
    output = {
        "summary": {
            "total_processed": len(IANA_PORTS),
            "created": len(created),
            "skipped": len(skipped),
            "failed": len(failed)
        },
        "created": created,
        "skipped": skipped,
        "failed": failed
    }
    
    output_file = "wellknown_ports_created.json"
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    # Print summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total Processed: {len(IANA_PORTS)}")
    print(f"Created:         {len(created)}")
    print(f"Skipped:         {len(skipped)}")
    print(f"Failed:          {len(failed)}")
    print(f"\nResults written to: {output_file}")
    
    if failed:
        print(f"\n⚠ WARNING: {len(failed)} port objects failed to create")
        print("Check the output file for details")


if __name__ == "__main__":
    main()