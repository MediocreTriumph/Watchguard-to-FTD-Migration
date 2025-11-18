#!/usr/bin/env python3

import json
import sys
import time
import requests
import re
from datetime import datetime
from pathlib import Path

# Disable SSL warnings for self-signed certs (common in FMC)
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
        self.headers = {}
        self.auth_token = None
        self.refresh_token = None
        self.token_expiry = None
        
    def authenticate(self):
        """Authenticate and get access token"""
        auth_url = f"https://{self.host}/api/fmc_platform/v1/auth/generatetoken"
        
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
                print(f"  {response.text}")
                return False
                
        except Exception as e:
            print(f"✗ Authentication error: {e}")
            return False
    
    def refresh_auth_token(self):
        """Refresh the authentication token"""
        auth_url = f"https://{self.host}/api/fmc_platform/v1/auth/refreshtoken"
        
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
                
                print("  ⟳ Token refreshed")
                return True
            else:
                print(f"  ✗ Token refresh failed: {response.status_code}")
                # If refresh fails, re-authenticate
                return self.authenticate()
                
        except Exception as e:
            print(f"  ✗ Token refresh error: {e}")
            return self.authenticate()
    
    def _make_request(self, method, endpoint, **kwargs):
        """Make API request with automatic token refresh on 401"""
        kwargs['verify'] = False
        kwargs['timeout'] = 30
        kwargs['headers'] = self.headers
        
        response = requests.request(method, endpoint, **kwargs)
        
        # If token expired, refresh and retry once
        if response.status_code == 401:
            print("  ⟳ Token expired, refreshing...", end='', flush=True)
            if self.refresh_auth_token():
                kwargs['headers'] = self.headers
                response = requests.request(method, endpoint, **kwargs)
            else:
                return {"error": "Failed to refresh token", "status_code": 401}
        
        return response
    
    def sanitize_name(self, name):
        """Sanitize object name for FMC API compatibility"""
        # FMC API rules (stricter than UI):
        # - Max 128 characters
        # - Must start with alphanumeric or underscore
        # - Allowed: alphanumeric, underscore, hyphen, period
        # - NO spaces, NO special chars like ()[]{}:
        
        # Replace spaces with underscores
        sanitized = name.replace(' ', '_')
        
        # Replace all other invalid characters with underscore
        sanitized = re.sub(r'[^a-zA-Z0-9_\-.]', '_', sanitized)
        
        # Trim to 128 chars
        sanitized = sanitized[:128]
        
        # Ensure it starts with alphanumeric or underscore
        if sanitized and not re.match(r'^[a-zA-Z0-9_]', sanitized):
            sanitized = 'obj_' + sanitized
        
        # If name is now empty, generate a default
        if not sanitized:
            sanitized = f"Object_{hash(name) % 100000}"
        
        return sanitized
    
    def sanitize_fqdn(self, fqdn):
        """Sanitize FQDN value"""
        # Remove leading/trailing whitespace and wildcards in wrong positions
        fqdn = fqdn.strip()
        
        # FMC accepts wildcards only at the beginning: *.example.com
        # Remove any spaces
        fqdn = fqdn.replace(' ', '')
        
        return fqdn
    
    def get_object_by_name(self, object_type, name):
        """Check if an object exists by name"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/{object_type}"
        
        try:
            response = self._make_request(
                'GET',
                endpoint,
                params={'filter': f'name:{name}'}
            )
            
            if isinstance(response, dict) and 'error' in response:
                return None
            
            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])
                if items:
                    return items[0]
            
            return None
            
        except Exception as e:
            print(f"  Error checking object: {e}")
            return None
    
    def create_host(self, name, ip, description=""):
        """Create a host object"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/hosts"
        
        name = self.sanitize_name(name)
        
        payload = {
            "name": name,
            "type": "Host",
            "value": ip,
            "description": description[:500] if description else ""
        }
        
        try:
            response = self._make_request('POST', endpoint, json=payload)
            
            if isinstance(response, dict) and 'error' in response:
                return response
            
            if response.status_code == 201:
                return response.json()
            else:
                error_msg = response.text
                return {"error": error_msg, "status_code": response.status_code}
                
        except Exception as e:
            return {"error": str(e)}
    
    def create_network(self, name, network, mask, description=""):
        """Create a network object"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/networks"
        
        name = self.sanitize_name(name)
        
        # Convert mask to CIDR if needed
        cidr = self._mask_to_cidr(mask)
        value = f"{network}/{cidr}"
        
        payload = {
            "name": name,
            "type": "Network",
            "value": value,
            "description": description[:500] if description else ""
        }
        
        try:
            response = self._make_request('POST', endpoint, json=payload)
            
            if isinstance(response, dict) and 'error' in response:
                return response
            
            if response.status_code == 201:
                return response.json()
            else:
                error_msg = response.text
                return {"error": error_msg, "status_code": response.status_code}
                
        except Exception as e:
            return {"error": str(e)}
    
    def create_range(self, name, start, end, description=""):
        """Create a range object"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/ranges"
        
        name = self.sanitize_name(name)
        
        payload = {
            "name": name,
            "type": "Range",
            "value": f"{start}-{end}",
            "description": description[:500] if description else ""
        }
        
        try:
            response = self._make_request('POST', endpoint, json=payload)
            
            if isinstance(response, dict) and 'error' in response:
                return response
            
            if response.status_code == 201:
                return response.json()
            else:
                error_msg = response.text
                return {"error": error_msg, "status_code": response.status_code}
                
        except Exception as e:
            return {"error": str(e)}
    
    def create_fqdn(self, name, fqdn, description=""):
        """Create an FQDN object"""
        
        # Skip wildcards - not supported in FMC
        if '*' in fqdn:
            return {"error": "Wildcard FQDNs not supported in FMC", "skipped": True, "fqdn_value": fqdn}
        
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/fqdns"
        
        name = self.sanitize_name(name)
        fqdn = self.sanitize_fqdn(fqdn)
        
        payload = {
            "name": name,
            "type": "FQDN",
            "value": fqdn,
            "dnsResolution": "IPV4_AND_IPV6",
            "description": description[:500] if description else ""
        }
        
        try:
            response = self._make_request('POST', endpoint, json=payload)
            
            if isinstance(response, dict) and 'error' in response:
                return response
            
            if response.status_code == 201:
                return response.json()
            else:
                error_msg = response.text
                return {"error": error_msg, "status_code": response.status_code}
                
        except Exception as e:
            return {"error": str(e)}
    
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
                error_msg = response.text
                return {"error": error_msg, "status_code": response.status_code}
                
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
                error_msg = response.text
                return {"error": error_msg, "status_code": response.status_code}
                
        except Exception as e:
            return {"error": str(e)}
    
    def create_icmp(self, name, description=""):
        """Create an ICMP object"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/icmpv4objects"
        
        name = self.sanitize_name(name)
        
        payload = {
            "name": name,
            "type": "ICMPV4Object",
            "icmpType": "ANY",
            "description": description[:500] if description else ""
        }
        
        try:
            response = self._make_request('POST', endpoint, json=payload)
            
            if isinstance(response, dict) and 'error' in response:
                return response
            
            if response.status_code == 201:
                return response.json()
            else:
                error_msg = response.text
                return {"error": error_msg, "status_code": response.status_code}
                
        except Exception as e:
            return {"error": str(e)}
    
    def create_network_group(self, name, members_uuids, description=""):
        """Create a network group object"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/networkgroups"
        
        name = self.sanitize_name(name)
        
        # Build objects list from UUIDs - FMC needs proper type for each
        # We'll use generic "Network" type which works for hosts, networks, ranges
        objects = [{"type": "Network", "id": uuid} for uuid in members_uuids]
        
        payload = {
            "name": name,
            "type": "NetworkGroup",
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
                error_msg = response.text
                return {"error": error_msg, "status_code": response.status_code}
                
        except Exception as e:
            return {"error": str(e)}
        
    def get_security_zones(self):
        """Get all security zones"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/securityzones"
        
        try:
            response = self._make_request('GET', endpoint, params={'limit': 1000})
            
            if isinstance(response, dict) and 'error' in response:
                return []
            
            if response.status_code == 200:
                data = response.json()
                return data.get('items', [])
            
            return []
        except Exception as e:
            print(f"  Error getting zones: {e}")
            return []

    def get_zone_by_name(self, zone_name):
        """Get zone UUID by name"""
        zones = self.get_security_zones()
        for zone in zones:
            if zone['name'].lower() == zone_name.lower():
                return zone
        return None

    def create_access_rule(self, acp_id, rule_data):
        """Create an access control rule"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/policy/accesspolicies/{acp_id}/accessrules"
        
        try:
            response = self._make_request('POST', endpoint, json=rule_data)
            
            if isinstance(response, dict) and 'error' in response:
                return response
            
            if response.status_code == 201:
                return response.json()
            else:
                error_msg = response.text
                return {"error": error_msg, "status_code": response.status_code}
        except Exception as e:
            return {"error": str(e)}        
        
    def _mask_to_cidr(self, mask):
        """Convert netmask to CIDR notation"""
        return sum([bin(int(x)).count('1') for x in mask.split('.')])
        
    def get_security_zones(self):
        """Get all security zones"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/securityzones"
        
        try:
            response = self._make_request('GET', endpoint, params={'limit': 1000})
            
            if isinstance(response, dict) and 'error' in response:
                return []
            
            if response.status_code == 200:
                data = response.json()
                return data.get('items', [])
            
            return []
        except Exception as e:
            print(f"  Error getting zones: {e}")
            return []

    def get_zone_by_name(self, zone_name):
        """Get zone UUID by name"""
        zones = self.get_security_zones()
        for zone in zones:
            if zone['name'].lower() == zone_name.lower():
                return zone
        return None

    def create_access_rule(self, acp_id, rule_data):
        """Create an access control rule"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/policy/accesspolicies/{acp_id}/accessrules"
        
        try:
            response = self._make_request('POST', endpoint, json=rule_data)
            
            if isinstance(response, dict) and 'error' in response:
                return response
            
            if response.status_code == 201:
                return response.json()
            else:
                error_msg = response.text
                return {"error": error_msg, "status_code": response.status_code}
        except Exception as e:
            return {"error": str(e)}    


class MigrationStateManager:
    """Manages migration state and checkpointing"""
    
    def __init__(self, state_file="migration_state.json"):
        self.state_file = state_file
        self.state = self._load_state()
    
    def _load_state(self):
        """Load existing state or create new"""
        if Path(self.state_file).exists():
            with open(self.state_file, 'r') as f:
                return json.load(f)
        else:
            return {
                "metadata": {
                    "started": datetime.now().isoformat(),
                    "last_update": None
                },
                "objects": {
                    "hosts": {},
                    "networks": {},
                    "ranges": {},
                    "fqdns": {},
                    "tcp_services": {},
                    "udp_services": {},
                    "icmp_services": {},
                    "address_groups": {}
                },
                "name_mapping": {},  # Track original -> sanitized name mappings
                "skipped_wildcards": []  # Track skipped wildcard FQDNs
            }
    
    def save_state(self):
        """Save current state to file"""
        self.state["metadata"]["last_update"] = datetime.now().isoformat()
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=2)
    
    def is_created(self, object_type, name):
        """Check if object has been created"""
        return name in self.state["objects"].get(object_type, {})
    
    def mark_created(self, object_type, name, uuid, response=None, sanitized_name=None):
        """Mark object as created"""
        if object_type not in self.state["objects"]:
            self.state["objects"][object_type] = {}
        
        self.state["objects"][object_type][name] = {
            "uuid": uuid,
            "created": True,
            "timestamp": datetime.now().isoformat(),
            "sanitized_name": sanitized_name,
            "response": response
        }
        
        # Track name mapping if sanitized
        if sanitized_name and sanitized_name != name:
            if "name_mapping" not in self.state:
                self.state["name_mapping"] = {}
            self.state["name_mapping"][name] = sanitized_name
        
        self.save_state()
    
    def mark_failed(self, object_type, name, error):
        """Mark object creation as failed"""
        if object_type not in self.state["objects"]:
            self.state["objects"][object_type] = {}
        
        self.state["objects"][object_type][name] = {
            "uuid": None,
            "created": False,
            "timestamp": datetime.now().isoformat(),
            "error": str(error)
        }
        self.save_state()
    
    def mark_skipped_wildcard(self, name, fqdn_value, description=""):
        """Mark wildcard FQDN as skipped"""
        if "skipped_wildcards" not in self.state:
            self.state["skipped_wildcards"] = []
        
        self.state["skipped_wildcards"].append({
            "name": name,
            "fqdn": fqdn_value,
            "description": description,
            "timestamp": datetime.now().isoformat()
        })
        self.save_state()
    
    def get_uuid(self, object_type, name):
        """Get UUID for a created object"""
        obj = self.state["objects"].get(object_type, {}).get(name, {})
        return obj.get("uuid")
    
    def get_stats(self):
        """Get migration statistics"""
        stats = {}
        for obj_type, objects in self.state["objects"].items():
            created = sum(1 for o in objects.values() if o.get("created"))
            failed = sum(1 for o in objects.values() if not o.get("created"))
            stats[obj_type] = {"created": created, "failed": failed, "total": len(objects)}
        return stats


def migrate_objects(config_file, fmc_host, fmc_user, fmc_pass, resume=False):
    """Main migration orchestrator"""
    
    # Load WatchGuard config
    print(f"Loading configuration from {config_file}...")
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    # Initialize FMC client
    print(f"\nConnecting to FMC at {fmc_host}...")
    fmc = FMCClient(fmc_host, fmc_user, fmc_pass)
    if not fmc.authenticate():
        print("✗ Failed to authenticate with FMC")
        return False
    
    # Initialize state manager
    state = MigrationStateManager()
    
    if resume:
        print("\n📋 Resuming from previous state...")
        stats = state.get_stats()
        for obj_type, s in stats.items():
            if s["total"] > 0:
                print(f"  {obj_type}: {s['created']} created, {s['failed']} failed, {s['total']} total")
    
    print("\n" + "="*60)
    print("STARTING MIGRATION")
    print("="*60)
    
    # Phase 1: Create address objects
    print("\n[Phase 1] Creating Address Objects")
    print("-" * 60)
    
    # Hosts
    print(f"\nCreating {len(config['addresses']['hosts'])} host objects...")
    for i, host in enumerate(config['addresses']['hosts'], 1):
        name = host['name']
        
        if state.is_created('hosts', name):
            continue
        
        sanitized = fmc.sanitize_name(name)
        display_name = sanitized if sanitized != name else name
        print(f"  [{i}/{len(config['addresses']['hosts'])}] {display_name[:50]}...", end='', flush=True)
        
        result = fmc.create_host(name, host['ip'], host.get('description', ''))
        
        if 'error' in result:
            print(f" ✗ FAILED: {result['error'][:80]}")
            state.mark_failed('hosts', name, result['error'])
        else:
            print(f" ✓")
            state.mark_created('hosts', name, result['id'], sanitized_name=sanitized)
        
        time.sleep(0.5)  # Rate limiting
    
    # Networks - with /32 detection
    print(f"\nCreating {len(config['addresses']['networks'])} network objects...")
    for i, net in enumerate(config['addresses']['networks'], 1):
        name = net['name']
        
        if state.is_created('networks', name):
            continue
        
        sanitized = fmc.sanitize_name(name)
        display_name = sanitized if sanitized != name else name
        
        # Check if this is actually a /32 (should be a host)
        cidr = fmc._mask_to_cidr(net['mask'])
        
        if cidr == 32:
            # This is a /32, create as host instead
            print(f"  [{i}/{len(config['addresses']['networks'])}] {display_name[:50]} [/32→host]...", end='', flush=True)
            result = fmc.create_host(name, net['network'], net.get('description', ''))
        else:
            # Normal network
            print(f"  [{i}/{len(config['addresses']['networks'])}] {display_name[:50]}...", end='', flush=True)
            result = fmc.create_network(name, net['network'], net['mask'], net.get('description', ''))
        
        if 'error' in result:
            print(f" ✗ FAILED: {result['error'][:80]}")
            state.mark_failed('networks', name, result['error'])
        else:
            print(f" ✓")
            state.mark_created('networks', name, result['id'], sanitized_name=sanitized)
        
        time.sleep(0.5)
    
    # Ranges
    print(f"\nCreating {len(config['addresses']['ranges'])} range objects...")
    for i, rng in enumerate(config['addresses']['ranges'], 1):
        name = rng['name']
        
        if state.is_created('ranges', name):
            continue
        
        sanitized = fmc.sanitize_name(name)
        display_name = sanitized if sanitized != name else name
        print(f"  [{i}/{len(config['addresses']['ranges'])}] {display_name[:50]}...", end='', flush=True)
        
        result = fmc.create_range(name, rng['start'], rng['end'], rng.get('description', ''))
        
        if 'error' in result:
            print(f" ✗ FAILED: {result['error'][:80]}")
            state.mark_failed('ranges', name, result['error'])
        else:
            print(f" ✓")
            state.mark_created('ranges', name, result['id'], sanitized_name=sanitized)
        
        time.sleep(0.5)
    
    # FQDNs - with wildcard detection
    print(f"\nCreating {len(config['addresses']['fqdns'])} FQDN objects...")
    wildcard_count = 0
    for i, fqdn in enumerate(config['addresses']['fqdns'], 1):
        name = fqdn['name']
        
        if state.is_created('fqdns', name):
            continue
        
        sanitized = fmc.sanitize_name(name)
        display_name = sanitized if sanitized != name else name
        print(f"  [{i}/{len(config['addresses']['fqdns'])}] {display_name[:50]}...", end='', flush=True)
        
        result = fmc.create_fqdn(name, fqdn['fqdn'], fqdn.get('description', ''))
        
        if 'skipped' in result:
            print(f" ⊘ SKIPPED (wildcard: {result['fqdn_value']})")
            wildcard_count += 1
            state.mark_skipped_wildcard(name, result['fqdn_value'], fqdn.get('description', ''))
            state.mark_failed('fqdns', name, result['error'])
        elif 'error' in result:
            print(f" ✗ FAILED: {result['error'][:80]}")
            state.mark_failed('fqdns', name, result['error'])
        else:
            print(f" ✓")
            state.mark_created('fqdns', name, result['id'], sanitized_name=sanitized)
        
        time.sleep(0.5)
    
    if wildcard_count > 0:
        print(f"\n  ⚠ Skipped {wildcard_count} wildcard FQDNs (not supported in FMC)")
    
    # Phase 2: Create service objects
    print("\n[Phase 2] Creating Service Objects")
    print("-" * 60)
    
    # TCP Services
    print(f"\nCreating {len(config['services']['tcp'])} TCP service objects...")
    for i, svc in enumerate(config['services']['tcp'], 1):
        name = svc['name']
        
        if state.is_created('tcp_services', name):
            continue
        
        sanitized = fmc.sanitize_name(name)
        display_name = sanitized if sanitized != name else name
        print(f"  [{i}/{len(config['services']['tcp'])}] {display_name[:50]}...", end='', flush=True)
        
        result = fmc.create_tcp_port(name, svc['port'], svc.get('description', ''))
        
        if 'error' in result:
            print(f" ✗ FAILED: {result['error'][:80]}")
            state.mark_failed('tcp_services', name, result['error'])
        else:
            print(f" ✓")
            state.mark_created('tcp_services', name, result['id'], sanitized_name=sanitized)
        
        time.sleep(0.5)
    
    # UDP Services
    print(f"\nCreating {len(config['services']['udp'])} UDP service objects...")
    for i, svc in enumerate(config['services']['udp'], 1):
        name = svc['name']
        
        if state.is_created('udp_services', name):
            continue
        
        sanitized = fmc.sanitize_name(name)
        display_name = sanitized if sanitized != name else name
        print(f"  [{i}/{len(config['services']['udp'])}] {display_name[:50]}...", end='', flush=True)
        
        result = fmc.create_udp_port(name, svc['port'], svc.get('description', ''))
        
        if 'error' in result:
            print(f" ✗ FAILED: {result['error'][:80]}")
            state.mark_failed('udp_services', name, result['error'])
        else:
            print(f" ✓")
            state.mark_created('udp_services', name, result['id'], sanitized_name=sanitized)
        
        time.sleep(0.5)
    
    # ICMP Services
    print(f"\nCreating {len(config['services']['icmp'])} ICMP service objects...")
    for i, svc in enumerate(config['services']['icmp'], 1):
        name = svc['name']
        
        if state.is_created('icmp_services', name):
            continue
        
        sanitized = fmc.sanitize_name(name)
        display_name = sanitized if sanitized != name else name
        print(f"  [{i}/{len(config['services']['icmp'])}] {display_name[:50]}...", end='', flush=True)
        
        result = fmc.create_icmp(name, svc.get('description', ''))
        
        if 'error' in result:
            print(f" ✗ FAILED: {result['error'][:80]}")
            state.mark_failed('icmp_services', name, result['error'])
        else:
            print(f" ✓")
            state.mark_created('icmp_services', name, result['id'], sanitized_name=sanitized)
        
        time.sleep(0.5)
    
    # Phase 3: Create address groups
    print("\n[Phase 3] Creating Address Groups")
    print("-" * 60)
    
    # Separate groups by dependencies
    groups_no_deps = [g for g in config['address_groups'] if len(g.get('alias_references', [])) == 0]
    groups_with_deps = [g for g in config['address_groups'] if len(g.get('alias_references', [])) > 0]
    
    print(f"\nCreating {len(groups_no_deps)} address groups (no dependencies)...")
    for i, group in enumerate(groups_no_deps, 1):
        name = group['name']
        
        if state.is_created('address_groups', name):
            continue
        
        # Skip groups with only "Any" or interface references
        if group['members'] == ['Any'] or not group['members']:
            print(f"  [{i}/{len(groups_no_deps)}] {name[:50]}... ⊘ SKIPPED (Any/Empty)")
            continue
        
        sanitized = fmc.sanitize_name(name)
        display_name = sanitized if sanitized != name else name
        print(f"  [{i}/{len(groups_no_deps)}] {display_name[:50]}...", end='', flush=True)
        
        # Collect UUIDs for members
        member_uuids = []
        for member in group['members']:
            # Try to find UUID in all address object types
            uuid = (state.get_uuid('hosts', member) or 
                   state.get_uuid('networks', member) or
                   state.get_uuid('ranges', member) or
                   state.get_uuid('fqdns', member))
            
            if uuid:
                member_uuids.append(uuid)
        
        if not member_uuids:
            print(f" ⊘ SKIPPED (no valid members)")
            continue
        
        result = fmc.create_network_group(name, member_uuids, group.get('description', ''))
        
        if 'error' in result:
            print(f" ✗ FAILED: {result['error'][:80]}")
            state.mark_failed('address_groups', name, result['error'])
        else:
            print(f" ✓")
            state.mark_created('address_groups', name, result['id'], sanitized_name=sanitized)
        
        time.sleep(0.5)
    
    print(f"\nCreating {len(groups_with_deps)} address groups (with dependencies)...")
    for i, group in enumerate(groups_with_deps, 1):
        name = group['name']
        
        if state.is_created('address_groups', name):
            continue
        
        sanitized = fmc.sanitize_name(name)
        display_name = sanitized if sanitized != name else name
        print(f"  [{i}/{len(groups_with_deps)}] {display_name[:50]}...", end='', flush=True)
        
        # Collect UUIDs for direct members and referenced groups
        member_uuids = []
        
        # Direct members
        for member in group['members']:
            uuid = (state.get_uuid('hosts', member) or 
                   state.get_uuid('networks', member) or
                   state.get_uuid('ranges', member) or
                   state.get_uuid('fqdns', member))
            if uuid:
                member_uuids.append(uuid)
        
        # Referenced groups
        for ref in group.get('alias_references', []):
            uuid = state.get_uuid('address_groups', ref)
            if uuid:
                member_uuids.append(uuid)
        
        if not member_uuids:
            print(f" ⊘ SKIPPED (no valid members)")
            continue
        
        result = fmc.create_network_group(name, member_uuids, group.get('description', ''))
        
        if 'error' in result:
            print(f" ✗ FAILED: {result['error'][:80]}")
            state.mark_failed('address_groups', name, result['error'])
        else:
            print(f" ✓")
            state.mark_created('address_groups', name, result['id'], sanitized_name=sanitized)
        
        time.sleep(0.5)
    
    # Final report
    print("\n" + "="*60)
    print("MIGRATION COMPLETE")
    print("="*60)
    
    stats = state.get_stats()
    print("\nFinal Statistics:")
    for obj_type, s in stats.items():
        if s["total"] > 0:
            success_rate = (s['created'] / s['total'] * 100) if s['total'] > 0 else 0
            print(f"  {obj_type:20} {s['created']:4} created  {s['failed']:4} failed  ({success_rate:.1f}%)")
    
    print(f"\n✓ State saved to {state.state_file}")
    
    # Report name mappings
    if "name_mapping" in state.state and state.state["name_mapping"]:
        print(f"\n📝 {len(state.state['name_mapping'])} object names were sanitized")
        print("   Check migration_state.json 'name_mapping' section for details")
    
    # Report skipped wildcards
    if "skipped_wildcards" in state.state and state.state["skipped_wildcards"]:
        wildcard_count = len(state.state["skipped_wildcards"])
        print(f"\n⚠  {wildcard_count} wildcard FQDNs were skipped (not supported in FMC)")
        print("   Generating wildcard report...")
        
        # Generate wildcard report
        report_file = f"skipped_wildcards_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.txt"
        with open(report_file, 'w') as f:
            f.write("SKIPPED WILDCARD FQDNs - NOT SUPPORTED IN FMC\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Total skipped: {wildcard_count}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n\n")
            f.write("These wildcard FQDNs cannot be migrated to FMC as wildcard FQDN objects\n")
            f.write("are not supported. Consider alternative approaches:\n")
            f.write("  - Use URL filtering categories\n")
            f.write("  - Resolve to IP ranges and create network objects (brittle)\n")
            f.write("  - Use DNS-layer security controls\n")
            f.write("  - Evaluate if these rules are still necessary\n\n")
            f.write("-" * 80 + "\n\n")
            
            for item in state.state["skipped_wildcards"]:
                f.write(f"Name: {item['name']}\n")
                f.write(f"FQDN: {item['fqdn']}\n")
                if item.get('description'):
                    f.write(f"Description: {item['description']}\n")
                f.write("\n")
        
        print(f"   Report saved to: {report_file}")
    
    print("\n✓ Migration complete. Review any failed objects and re-run with --resume to retry")
    
    return True


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python fmc_migrate.py <config.json> <fmc_host> <username> <password> [--resume]")
        print("\nExample:")
        print("  python fmc_migrate.py watchguard_config.json 192.168.1.100 admin Cisco123!")
        print("  python fmc_migrate.py watchguard_config.json 192.168.1.100 admin Cisco123! --resume")
        sys.exit(1)
    
    config_file = sys.argv[1]
    fmc_host = sys.argv[2]
    username = sys.argv[3]
    password = sys.argv[4]
    resume = '--resume' in sys.argv
    
    migrate_objects(config_file, fmc_host, username, password, resume)