#!/usr/bin/env python3

import json
import sys
import time
import requests
import re
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
                
                print("  ⟳ Token refreshed")
                return True
            else:
                return self.authenticate()
                
        except Exception as e:
            return self.authenticate()
    
    def _make_request(self, method, endpoint, **kwargs):
        """Make API request with automatic token refresh on 401"""
        kwargs['verify'] = False
        kwargs['timeout'] = 30
        kwargs['headers'] = self.headers
        
        response = requests.request(method, endpoint, **kwargs)
        
        # If token expired, refresh and retry once
        if response.status_code == 401:
            if self.refresh_auth_token():
                kwargs['headers'] = self.headers
                response = requests.request(method, endpoint, **kwargs)
            else:
                return {"error": "Failed to refresh token", "status_code": 401}
        
        return response
    
    def get_access_policies(self):
        """Get all access control policies"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/policy/accesspolicies"
        
        try:
            response = self._make_request('GET', endpoint)
            
            if isinstance(response, dict) and 'error' in response:
                return None
            
            if response.status_code == 200:
                data = response.json()
                return data.get('items', [])
            
            return None
            
        except Exception as e:
            print(f"  Error fetching access policies: {e}")
            return None
    
    def create_access_rule(self, policy_id, rule_data):
        """Create an access control rule"""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/policy/accesspolicies/{policy_id}/accessrules"
        
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


class PolicyTranslator:
    """Translates WatchGuard policies to FMC access rules"""
    
    def __init__(self, wg_config, app_mapping, migration_state):
        self.wg_config = wg_config
        self.app_mapping = app_mapping
        self.migration_state = migration_state
        
    def sanitize_name(self, name):
        """Sanitize rule name for FMC"""
        # Replace spaces with underscores
        sanitized = name.replace(' ', '_')
        # Replace invalid characters
        sanitized = re.sub(r'[^a-zA-Z0-9_\-.]', '_', sanitized)
        # Trim to 128 chars
        sanitized = sanitized[:128]
        # Ensure starts with alphanumeric or underscore
        if sanitized and not re.match(r'^[a-zA-Z0-9_]', sanitized):
            sanitized = 'rule_' + sanitized
        if not sanitized:
            sanitized = f"Rule_{hash(name) % 100000}"
        return sanitized
    
    def get_app_action_policy(self, app_action_name):
        """Get app action policy by name"""
        for policy in self.wg_config.get('app_actions', []):
            if policy['name'] == app_action_name:
                return policy
        return None
    
    def check_app_mappings(self, app_list):
        """Check if all apps in list are mapped"""
        mapped = []
        unmapped = []
        
        for app_name in app_list:
            mapping = self.app_mapping['mappings'].get(app_name)
            
            if mapping and mapping.get('fmc_id'):
                # Successfully mapped to an individual app
                mapped.append({
                    'wg_name': app_name,
                    'fmc_id': mapping['fmc_id'],
                    'fmc_name': mapping['fmc_name'],
                    'is_category': False
                })
            elif mapping and mapping.get('is_category'):
                # Mapped to a category
                mapped.append({
                    'wg_name': app_name,
                    'fmc_category': mapping.get('fmc_category') or mapping.get('fmc_name'),
                    'is_category': True
                })
            else:
                # Not mapped
                unmapped.append(app_name)
        
        return mapped, unmapped
    
    def build_application_condition(self, allowed_apps, blocked_apps):
        """Build FMC application filter condition"""
        # FMC uses application filters in access rules
        # Format: list of application objects with IDs
        
        applications = []
        
        # Add allowed apps (note: in FMC, you specify apps to allow/block at rule level)
        for app in allowed_apps:
            if app.get('is_category'):
                # Category - would need to expand or use filter
                # For now, we'll note this needs manual handling
                continue
            else:
                applications.append({
                    'type': 'Application',
                    'id': app['fmc_id']
                })
        
        # Blocked apps would typically be handled with separate deny rules
        # or by inverting the logic
        
        return applications if applications else None
    
    def translate_policy_to_rule(self, policy):
        """Translate a single WatchGuard policy to FMC access rule"""
        
        # Get app action policy if specified
        app_action_name = policy.get('app_action', '')
        
        if not app_action_name:
            # No app control on this policy
            return None
        
        app_action = self.get_app_action_policy(app_action_name)
        
        if not app_action:
            return {
                'error': f'App action policy "{app_action_name}" not found',
                'policy_name': policy['name']
            }
        
        # Check mappings for allowed and blocked apps
        allowed_mapped, allowed_unmapped = self.check_app_mappings(app_action.get('allowed_apps', []))
        blocked_mapped, blocked_unmapped = self.check_app_mappings(app_action.get('blocked_apps', []))
        
        all_unmapped = allowed_unmapped + blocked_unmapped
        
        # Determine if rule should be enabled
        enabled = len(all_unmapped) == 0
        
        # Build rule name
        rule_name = self.sanitize_name(f"WG_{policy['name']}")
        
        # Build comments explaining the rule
        comments = []
        comments.append(f"Migrated from WatchGuard policy: {policy['name']}")
        comments.append(f"Original action: {policy.get('action', 'Unknown')}")
        comments.append(f"App control policy: {app_action_name}")
        
        if policy.get('description'):
            comments.append(f"Description: {policy['description']}")
        
        if allowed_mapped:
            comments.append(f"Allowed apps ({len(allowed_mapped)}): " + ", ".join([a['wg_name'] for a in allowed_mapped[:5]]))
            if len(allowed_mapped) > 5:
                comments.append(f"  ... and {len(allowed_mapped) - 5} more")
        
        if blocked_mapped:
            comments.append(f"Blocked apps ({len(blocked_mapped)}): " + ", ".join([a['wg_name'] for a in blocked_mapped[:5]]))
            if len(blocked_mapped) > 5:
                comments.append(f"  ... and {len(blocked_mapped) - 5} more")
        
        if all_unmapped:
            comments.append(f"⚠ DISABLED: {len(all_unmapped)} unmapped applications")
            comments.append(f"Unmapped apps: " + ", ".join(all_unmapped[:10]))
            if len(all_unmapped) > 10:
                comments.append(f"  ... and {len(all_unmapped) - 10} more")
        
        comment = " | ".join(comments)[:1000]  # FMC comment limit
        
        # Build application conditions
        app_conditions = self.build_application_condition(allowed_mapped, blocked_mapped)
        
        # Build rule structure
        rule = {
            'name': rule_name,
            'enabled': enabled,
            'action': 'ALLOW' if policy.get('action') == 'Allow' else 'BLOCK',
            'type': 'AccessRule',
            'commentHistoryList': [comment]
        }
        
        # Add application filter if we have mapped apps
        if app_conditions:
            rule['applications'] = {
                'applications': app_conditions
            }
        
        # Note: Source/destination zones, networks, etc. would be added here
        # For now, focusing on application control migration
        
        return {
            'rule': rule,
            'enabled': enabled,
            'unmapped_apps': all_unmapped,
            'policy_name': policy['name'],
            'allowed_count': len(allowed_mapped),
            'blocked_count': len(blocked_mapped)
        }


def translate_policies(wg_config_file, app_mapping_file, migration_state_file, 
                       fmc_host=None, fmc_user=None, fmc_pass=None, 
                       access_policy_id=None, dry_run=True):
    """Main policy translation function"""
    
    print("="*60)
    print("WATCHGUARD TO FMC POLICY TRANSLATOR")
    print("="*60)
    
    # Load WatchGuard config
    print(f"\nLoading WatchGuard configuration from {wg_config_file}...")
    try:
        with open(wg_config_file, 'r') as f:
            wg_config = json.load(f)
        print(f"✓ Loaded {len(wg_config.get('policies', []))} policies")
    except Exception as e:
        print(f"✗ Failed to load WatchGuard config: {e}")
        return False
    
    # Load application mapping
    print(f"\nLoading application mapping from {app_mapping_file}...")
    try:
        with open(app_mapping_file, 'r') as f:
            app_mapping = json.load(f)
        print(f"✓ Loaded {len(app_mapping['mappings'])} application mappings")
    except Exception as e:
        print(f"✗ Failed to load application mapping: {e}")
        return False
    
    # Load migration state
    print(f"\nLoading migration state from {migration_state_file}...")
    try:
        with open(migration_state_file, 'r') as f:
            migration_state = json.load(f)
        print(f"✓ Loaded migration state")
    except Exception as e:
        print(f"⚠ Could not load migration state: {e}")
        migration_state = {"objects": {}}
    
    # Initialize translator
    translator = PolicyTranslator(wg_config, app_mapping, migration_state)
    
    # Find policies with app actions
    policies_with_apps = [p for p in wg_config.get('policies', []) if p.get('app_action')]
    
    print(f"\nFound {len(policies_with_apps)} policies with application control")
    
    # Translate policies
    print("\nTranslating policies...")
    
    results = {
        'metadata': {
            'translated_date': datetime.now().isoformat(),
            'source_config': wg_config_file,
            'app_mapping': app_mapping_file,
            'total_policies': len(policies_with_apps),
            'dry_run': dry_run
        },
        'rules': [],
        'statistics': {
            'enabled_rules': 0,
            'disabled_rules': 0,
            'total_unmapped_apps': 0,
            'errors': 0
        }
    }
    
    for i, policy in enumerate(policies_with_apps, 1):
        print(f"\n[{i}/{len(policies_with_apps)}] {policy['name']}")
        
        translated = translator.translate_policy_to_rule(policy)
        
        if not translated:
            print(f"  ⊘ Skipped (no app control)")
            continue
        
        if 'error' in translated:
            print(f"  ✗ Error: {translated['error']}")
            results['statistics']['errors'] += 1
            results['rules'].append(translated)
            continue
        
        if translated['enabled']:
            print(f"  ✓ ENABLED - {translated['allowed_count']} allowed, {translated['blocked_count']} blocked apps")
            results['statistics']['enabled_rules'] += 1
        else:
            print(f"  ⊗ DISABLED - {len(translated['unmapped_apps'])} unmapped apps")
            results['statistics']['disabled_rules'] += 1
            results['statistics']['total_unmapped_apps'] += len(translated['unmapped_apps'])
        
        results['rules'].append(translated)
    
    # Save translation results
    output_file = f"translated_policies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    print(f"\nSaving translation results to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"✓ Saved")
    
    # Generate report
    report_file = f"translation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    print(f"\nGenerating translation report...")
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("WATCHGUARD TO FMC POLICY TRANSLATION REPORT\n")
        f.write("="*80 + "\n\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write(f"Source Config: {wg_config_file}\n")
        f.write(f"App Mapping: {app_mapping_file}\n")
        f.write(f"Mode: {'DRY RUN' if dry_run else 'LIVE DEPLOYMENT'}\n\n")
        
        f.write("TRANSLATION STATISTICS\n")
        f.write("-"*80 + "\n")
        f.write(f"Total Policies with App Control: {len(policies_with_apps)}\n")
        f.write(f"  Enabled Rules:                  {results['statistics']['enabled_rules']}\n")
        f.write(f"  Disabled Rules:                 {results['statistics']['disabled_rules']}\n")
        f.write(f"  Errors:                         {results['statistics']['errors']}\n")
        f.write(f"  Total Unmapped Apps:            {results['statistics']['total_unmapped_apps']}\n\n")
        
        f.write("ENABLED RULES (Ready for deployment)\n")
        f.write("-"*80 + "\n")
        enabled_rules = [r for r in results['rules'] if r.get('enabled')]
        if enabled_rules:
            for rule in enabled_rules:
                f.write(f"{rule['policy_name']}\n")
                f.write(f"  Allowed: {rule['allowed_count']} apps, Blocked: {rule['blocked_count']} apps\n\n")
        else:
            f.write("None\n\n")
        
        f.write("DISABLED RULES (Require manual review)\n")
        f.write("-"*80 + "\n")
        disabled_rules = [r for r in results['rules'] if not r.get('enabled') and 'rule' in r]
        if disabled_rules:
            for rule in disabled_rules:
                f.write(f"{rule['policy_name']}\n")
                f.write(f"  Unmapped apps ({len(rule['unmapped_apps'])}): ")
                f.write(", ".join(rule['unmapped_apps'][:5]))
                if len(rule['unmapped_apps']) > 5:
                    f.write(f" ... and {len(rule['unmapped_apps']) - 5} more")
                f.write("\n\n")
        else:
            f.write("None\n\n")
        
        f.write("NEXT STEPS\n")
        f.write("-"*80 + "\n")
        if dry_run:
            f.write("1. Review enabled and disabled rules above\n")
            f.write("2. Update application_mapping.json for unmapped apps\n")
            f.write("3. Re-run translator to regenerate rules\n")
            f.write("4. When ready, run with --deploy flag and specify access policy ID\n")
        else:
            f.write("1. Review deployed rules in FMC\n")
            f.write("2. Enable disabled rules after resolving unmapped applications\n")
            f.write("3. Test rules thoroughly before deploying to production\n")
    
    print(f"✓ Report saved to {report_file}")
    
    # If not dry run and FMC credentials provided, deploy to FMC
    if not dry_run and fmc_host and fmc_user and fmc_pass and access_policy_id:
        print("\n" + "="*60)
        print("DEPLOYING TO FMC")
        print("="*60)
        
        fmc = FMCClient(fmc_host, fmc_user, fmc_pass)
        if not fmc.authenticate():
            print("\n✗ Failed to authenticate with FMC")
            return False
        
        print(f"\nDeploying {len(results['rules'])} rules to access policy {access_policy_id}...")
        
        deployed = 0
        failed = 0
        
        for i, result in enumerate(results['rules'], 1):
            if 'rule' not in result:
                continue
            
            rule_data = result['rule']
            policy_name = result['policy_name']
            
            print(f"\n[{i}/{len(results['rules'])}] Deploying: {policy_name}...", end='', flush=True)
            
            response = fmc.create_access_rule(access_policy_id, rule_data)
            
            if 'error' in response:
                print(f" ✗ FAILED: {response['error'][:80]}")
                failed += 1
            else:
                print(f" ✓")
                deployed += 1
            
            time.sleep(0.5)  # Rate limiting
        
        print(f"\n{'='*60}")
        print(f"Deployment Complete: {deployed} deployed, {failed} failed")
        print(f"{'='*60}")
    
    # Print summary
    print("\n" + "="*60)
    print("TRANSLATION COMPLETE")
    print("="*60)
    
    stats = results['statistics']
    print(f"\nResults:")
    print(f"  Enabled Rules:    {stats['enabled_rules']}")
    print(f"  Disabled Rules:   {stats['disabled_rules']}")
    print(f"  Errors:           {stats['errors']}")
    print(f"  Unmapped Apps:    {stats['total_unmapped_apps']}")
    
    print(f"\nFiles Generated:")
    print(f"  ✓ {output_file} - Translation results")
    print(f"  ✓ {report_file} - Translation report")
    
    if dry_run:
        print("\n⚠ This was a DRY RUN - no changes made to FMC")
        print("  Review the output and run with --deploy to create rules")
    
    return True


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python translate_app_policies.py <wg_config.json> <app_mapping.json> <migration_state.json> [options]")
        print("\nOptions:")
        print("  --deploy                Deploy to FMC (requires FMC options)")
        print("  --fmc-host <host>       FMC hostname/IP")
        print("  --fmc-user <user>       FMC username")
        print("  --fmc-pass <pass>       FMC password")
        print("  --policy-id <id>        Access policy ID to deploy rules to")
        print("\nExamples:")
        print("  # Dry run (default)")
        print("  python translate_app_policies.py parsed_watchguard.json application_mapping.json migration_state.json")
        print("\n  # Deploy to FMC")
        print("  python translate_app_policies.py parsed_watchguard.json application_mapping.json migration_state.json \\")
        print("    --deploy --fmc-host 192.168.1.100 --fmc-user admin --fmc-pass Cisco123! --policy-id abc-123-def")
        sys.exit(1)
    
    wg_config = sys.argv[1]
    app_mapping = sys.argv[2]
    migration_state = sys.argv[3]
    
    # Parse options
    dry_run = '--deploy' not in sys.argv
    fmc_host = None
    fmc_user = None
    fmc_pass = None
    policy_id = None
    
    for i, arg in enumerate(sys.argv):
        if arg == '--fmc-host' and i + 1 < len(sys.argv):
            fmc_host = sys.argv[i + 1]
        elif arg == '--fmc-user' and i + 1 < len(sys.argv):
            fmc_user = sys.argv[i + 1]
        elif arg == '--fmc-pass' and i + 1 < len(sys.argv):
            fmc_pass = sys.argv[i + 1]
        elif arg == '--policy-id' and i + 1 < len(sys.argv):
            policy_id = sys.argv[i + 1]
    
    success = translate_policies(
        wg_config, app_mapping, migration_state,
        fmc_host, fmc_user, fmc_pass, policy_id, dry_run
    )
    
    sys.exit(0 if success else 1)