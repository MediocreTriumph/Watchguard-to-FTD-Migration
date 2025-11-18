#!/usr/bin/env python3
"""
Create FMC URL objects from WatchGuard wildcard FQDNs.
Converts *.example.com to URL category or URL object as appropriate.
"""

import json
import sys
import time
import requests
from datetime import datetime

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
    
    def create_url_object(self, name, url, description=""):
        """Create a URL object in FMC"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/urls"
        
        payload = {
            "name": name,
            "type": "Url",
            "url": url,
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
    
    def create_url_group(self, name, url_ids, description=""):
        """Create a URL group in FMC"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/urlgroups"
        
        objects = [{"type": "Url", "id": url_id} for url_id in url_ids]
        
        payload = {
            "name": name,
            "type": "UrlGroup",
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


def convert_wildcard_to_url(wildcard_fqdn):
    """
    Convert wildcard FQDN to URL pattern for FMC.
    
    WatchGuard: *.example.com
    FMC URL:    example.com (matches all subdomains by default)
    
    Or can use: .example.com (explicit subdomain wildcard)
    """
    # Remove leading *. if present
    if wildcard_fqdn.startswith('*.'):
        return wildcard_fqdn[2:]  # example.com
    elif wildcard_fqdn.startswith('*'):
        return wildcard_fqdn[1:]  # remove just the *
    else:
        return wildcard_fqdn


def sanitize_name(name):
    """Sanitize object name for FMC"""
    import re
    sanitized = name.replace(' ', '_')
    sanitized = re.sub(r'[^a-zA-Z0-9_\-.]', '_', sanitized)
    sanitized = sanitized[:128]
    
    if sanitized and not re.match(r'^[a-zA-Z0-9_]', sanitized):
        sanitized = 'url_' + sanitized
    if not sanitized:
        sanitized = f"URL_{hash(name) % 100000}"
    
    return sanitized


def create_url_objects(wildcard_analysis_file, fmc_host, fmc_user, fmc_pass, dry_run=True):
    """Main function to create URL objects from wildcard FQDNs"""
    
    print("="*80)
    print("WILDCARD FQDN TO URL OBJECT CONVERTER")
    print("="*80)
    
    # Load wildcard analysis
    print(f"\nLoading wildcard analysis from {wildcard_analysis_file}...")
    try:
        with open(wildcard_analysis_file, 'r') as f:
            analysis = json.load(f)
        
        wildcard_objects = analysis.get('wildcard_objects', [])
        affected_policies = analysis.get('affected_policies', [])
        
        print(f"✓ Found {len(wildcard_objects)} wildcard FQDN objects")
        print(f"✓ Found {len(affected_policies)} affected policies")
        
    except Exception as e:
        print(f"✗ Failed to load wildcard analysis: {e}")
        return False
    
    if not wildcard_objects:
        print("\n✓ No wildcard FQDNs found - nothing to convert")
        return True
    
    # Initialize FMC client
    print(f"\nConnecting to FMC at {fmc_host}...")
    fmc = FMCClient(fmc_host, fmc_user, fmc_pass)
    if not fmc.authenticate():
        print("✗ Failed to authenticate")
        return False
    
    # Prepare conversion plan
    conversion_plan = []
    
    print("\nPreparing conversion plan...")
    for wc_obj in wildcard_objects:
        wg_name = wc_obj['name']
        wg_fqdn = wc_obj['fqdn']
        wg_desc = wc_obj.get('description', '')
        
        # Convert wildcard to URL pattern
        url_pattern = convert_wildcard_to_url(wg_fqdn)
        
        # Sanitize name
        fmc_name = sanitize_name(wg_name)
        
        # Build description
        description = f"Migrated from WatchGuard wildcard FQDN: {wg_fqdn}"
        if wg_desc:
            description += f" | Original: {wg_desc}"
        
        conversion_plan.append({
            'wg_name': wg_name,
            'wg_fqdn': wg_fqdn,
            'fmc_name': fmc_name,
            'url_pattern': url_pattern,
            'description': description
        })
        
        print(f"  {wg_name} ({wg_fqdn}) → URL: {url_pattern}")
    
    # Save conversion plan
    plan_file = f"url_conversion_plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(plan_file, 'w') as f:
        json.dump({
            'metadata': {
                'generated': datetime.now().isoformat(),
                'total_conversions': len(conversion_plan)
            },
            'conversions': conversion_plan,
            'affected_policies': affected_policies
        }, f, indent=2)
    
    print(f"\n✓ Conversion plan saved to: {plan_file}")
    
    if dry_run:
        print("\n" + "="*80)
        print("DRY RUN MODE - NO OBJECTS CREATED")
        print("="*80)
        print("\n⚠ Review the conversion plan above")
        print("⚠ FMC URL objects will match the domain and ALL subdomains")
        print("⚠ For example: 'example.com' matches www.example.com, api.example.com, etc.")
        print("\nIf this looks correct, run with --execute flag")
        return True
    
    # Execute conversions
    print("\n" + "="*80)
    print("CREATING URL OBJECTS IN FMC")
    print("="*80)
    
    results = {
        'created': [],
        'failed': [],
        'url_mapping': {}  # WG name -> FMC URL object info
    }
    
    for i, conversion in enumerate(conversion_plan, 1):
        wg_name = conversion['wg_name']
        fmc_name = conversion['fmc_name']
        url_pattern = conversion['url_pattern']
        description = conversion['description']
        
        print(f"\n[{i}/{len(conversion_plan)}] Creating {fmc_name}...", end='', flush=True)
        
        result = fmc.create_url_object(fmc_name, url_pattern, description)
        
        if 'error' in result:
            print(f" ✗ FAILED")
            print(f"    Error: {result['error'][:80]}")
            results['failed'].append({
                'wg_name': wg_name,
                'fmc_name': fmc_name,
                'url_pattern': url_pattern,
                'error': result['error']
            })
        else:
            print(f" ✓")
            results['created'].append({
                'wg_name': wg_name,
                'fmc_name': fmc_name,
                'fmc_id': result['id'],
                'url_pattern': url_pattern
            })
            
            # Store mapping
            results['url_mapping'][wg_name] = {
                'fmc_name': fmc_name,
                'fmc_id': result['id'],
                'url_pattern': url_pattern,
                'type': 'Url'
            }
        
        time.sleep(0.3)  # Rate limiting
    
    # Save results
    results_file = f"url_creation_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(results_file, 'w') as f:
        json.dump({
            'metadata': {
                'completed': datetime.now().isoformat(),
                'created': len(results['created']),
                'failed': len(results['failed'])
            },
            'results': results
        }, f, indent=2)
    
    print("\n" + "="*80)
    print("CONVERSION COMPLETE")
    print("="*80)
    
    print(f"\nSuccessfully created: {len(results['created'])}")
    print(f"Failed:               {len(results['failed'])}")
    
    print(f"\n✓ Results saved to: {results_file}")
    
    if results['failed']:
        print(f"\n⚠ {len(results['failed'])} URL objects failed to create")
        print("  Check the results file for details")
    
    # Generate policy update instructions
    print("\n" + "="*80)
    print("NEXT STEPS - UPDATING POLICIES")
    print("="*80)
    
    print(f"\nYou have {len(affected_policies)} policies that reference these wildcard FQDNs:")
    for policy in affected_policies[:5]:
        print(f"  - {policy['policy_name']} ({policy['action']})")
    if len(affected_policies) > 5:
        print(f"  ... and {len(affected_policies) - 5} more")
    
    print("\nThese policies need to be updated to use URL filtering instead of")
    print("network object filtering. Options:")
    print("  1. Manually edit the policies in FMC to use the new URL objects")
    print("  2. Create new URL-based access rules for these policies")
    print("  3. Use FMC URL categories if they match your wildcard domains")
    
    print(f"\nURL object mapping saved to: {results_file}")
    print("Use the 'url_mapping' section to reference these objects in policies")
    
    return True


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python create_url_objects_from_wildcards.py <wildcard_analysis.json> <fmc_host> <username> <password> [--execute]")
        print("\nExample:")
        print("  # Dry run (default)")
        print("  python create_url_objects_from_wildcards.py wildcard_fqdn_analysis.json 192.168.255.122 admin password")
        print("\n  # Execute creation")
        print("  python create_url_objects_from_wildcards.py wildcard_fqdn_analysis.json 192.168.255.122 admin password --execute")
        print("\nThis script converts WatchGuard wildcard FQDNs (*.example.com) to FMC URL objects.")
        print("Note: FMC URL objects match the domain and all subdomains by default.")
        sys.exit(1)
    
    wildcard_file = sys.argv[1]
    fmc_host = sys.argv[2]
    username = sys.argv[3]
    password = sys.argv[4]
    dry_run = '--execute' not in sys.argv
    
    success = create_url_objects(wildcard_file, fmc_host, username, password, dry_run)
    sys.exit(0 if success else 1)