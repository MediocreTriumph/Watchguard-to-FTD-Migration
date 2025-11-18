#!/usr/bin/env python3

import json
import sys
import requests
from datetime import datetime
from pathlib import Path

# Disable SSL warnings for self-signed certs
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
                print(f"  {response.text}")
                return False
                
        except Exception as e:
            print(f"✗ Authentication error: {e}")
            return False
    
    def _make_request(self, method, endpoint, **kwargs):
        """Make API request with error handling"""
        kwargs['verify'] = False
        kwargs['timeout'] = 30
        kwargs['headers'] = self.headers
        
        try:
            response = requests.request(method, endpoint, **kwargs)
            return response
        except Exception as e:
            return {"error": str(e)}
    
    def get_all_applications(self):
        """Fetch all applications with pagination"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/applications"
        
        all_apps = []
        offset = 0
        limit = 1000  # Max per page
        
        print("\nFetching applications from FMC...")
        
        while True:
            params = {
                'offset': offset,
                'limit': limit,
                'expanded': True  # Get full details
            }
            
            response = self._make_request('GET', endpoint, params=params)
            
            if isinstance(response, dict) and 'error' in response:
                print(f"✗ Error fetching applications: {response['error']}")
                return None
            
            if response.status_code != 200:
                print(f"✗ Failed to fetch applications: {response.status_code}")
                print(f"  {response.text}")
                return None
            
            data = response.json()
            items = data.get('items', [])
            
            if not items:
                break
            
            all_apps.extend(items)
            print(f"  Fetched {len(all_apps)} applications...", end='\r', flush=True)
            
            # Check if there are more pages
            paging = data.get('paging', {})
            if not paging.get('next'):
                break
            
            offset += limit
        
        print(f"  Fetched {len(all_apps)} applications... ✓")
        return all_apps
    
    def get_all_application_filters(self):
        """Fetch all application filters (categories)"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/applicationfilters"
        
        all_filters = []
        offset = 0
        limit = 1000
        
        print("\nFetching application filters/categories from FMC...")
        
        while True:
            params = {
                'offset': offset,
                'limit': limit,
                'expanded': True
            }
            
            response = self._make_request('GET', endpoint, params=params)
            
            if isinstance(response, dict) and 'error' in response:
                print(f"✗ Error fetching filters: {response['error']}")
                return None
            
            if response.status_code != 200:
                print(f"✗ Failed to fetch filters: {response.status_code}")
                print(f"  {response.text}")
                return None
            
            data = response.json()
            items = data.get('items', [])
            
            if not items:
                break
            
            all_filters.extend(items)
            print(f"  Fetched {len(all_filters)} filters...", end='\r', flush=True)
            
            paging = data.get('paging', {})
            if not paging.get('next'):
                break
            
            offset += limit
        
        print(f"  Fetched {len(all_filters)} filters... ✓")
        return all_filters


def build_application_database(fmc_host, username, password, output_file="fmc_applications.json"):
    """Main function to fetch and save FMC application database"""
    
    print("="*60)
    print("FMC APPLICATION DATABASE BUILDER")
    print("="*60)
    
    # Connect to FMC
    print(f"\nConnecting to FMC at {fmc_host}...")
    fmc = FMCClient(fmc_host, username, password)
    
    if not fmc.authenticate():
        print("\n✗ Failed to authenticate with FMC")
        return False
    
    # Fetch applications
    applications = fmc.get_all_applications()
    if applications is None:
        print("\n✗ Failed to fetch applications")
        return False
    
    # Fetch application filters/categories
    filters = fmc.get_all_application_filters()
    if filters is None:
        print("\n✗ Failed to fetch application filters")
        return False
    
    # Build structured database
    print("\nBuilding application database...")
    
    database = {
        "metadata": {
            "fetched_date": datetime.now().isoformat(),
            "fmc_host": fmc_host,
            "domain_uuid": fmc.domain_uuid,
            "total_applications": len(applications),
            "total_filters": len(filters)
        },
        "applications": {},
        "filters": {},
        "categories": {},  # Organized by category for easier lookup
        "name_index": {}   # Lowercase name to ID mapping for fast lookup
    }
    
    # Process applications
    for app in applications:
        app_id = app.get('id')
        app_name = app.get('name')
        
        # Store full application data
        database["applications"][app_id] = {
            "id": app_id,
            "name": app_name,
            "type": app.get('type'),
            "description": app.get('description', ''),
            "risk": app.get('risk', 'UNKNOWN'),
            "category": app.get('category', 'UNKNOWN'),
            "productivity": app.get('productivity', 'UNKNOWN'),
            "tags": app.get('tags', [])
        }
        
        # Build name index (lowercase for case-insensitive matching)
        database["name_index"][app_name.lower()] = app_id
        
        # Organize by category
        category = app.get('category', 'UNKNOWN')
        if category not in database["categories"]:
            database["categories"][category] = []
        database["categories"][category].append(app_id)
    
    # Process filters/categories
    for filter_obj in filters:
        filter_id = filter_obj.get('id')
        filter_name = filter_obj.get('name')
        
        database["filters"][filter_id] = {
            "id": filter_id,
            "name": filter_name,
            "type": filter_obj.get('type'),
            "description": filter_obj.get('description', ''),
            "filter_type": filter_obj.get('filterType', 'UNKNOWN')
        }
    
    # Save to file
    print(f"\nSaving database to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(database, f, indent=2)
    
    print("\n" + "="*60)
    print("DATABASE BUILD COMPLETE")
    print("="*60)
    print(f"\n✓ {len(applications)} applications indexed")
    print(f"✓ {len(filters)} filters/categories indexed")
    print(f"✓ {len(database['categories'])} unique categories found")
    print(f"\n✓ Database saved to: {output_file}")
    
    # Print sample categories
    print("\nSample categories found:")
    for i, category in enumerate(sorted(database["categories"].keys())[:10], 1):
        count = len(database["categories"][category])
        print(f"  {i}. {category}: {count} apps")
    
    if len(database["categories"]) > 10:
        print(f"  ... and {len(database['categories']) - 10} more categories")
    
    return True


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python fmc_fetch_applications.py <fmc_host> <username> <password> [output_file]")
        print("\nExample:")
        print("  python fmc_fetch_applications.py 192.168.1.100 admin Cisco123!")
        print("  python fmc_fetch_applications.py 192.168.1.100 admin Cisco123! my_apps.json")
        sys.exit(1)
    
    fmc_host = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    output_file = sys.argv[4] if len(sys.argv) > 4 else "fmc_applications.json"
    
    success = build_application_database(fmc_host, username, password, output_file)
    sys.exit(0 if success else 1)