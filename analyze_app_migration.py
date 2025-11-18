#!/usr/bin/env python3

import json
import sys
from datetime import datetime
from difflib import SequenceMatcher
from pathlib import Path
import re


class ApplicationMapper:
    """Maps WatchGuard applications to FMC applications using fuzzy matching"""
    
    def __init__(self, fmc_apps_db):
        self.fmc_db = fmc_apps_db
        self.confidence_threshold = 0.80  # 80% match required
        
    def normalize_name(self, name):
        """Normalize application name for comparison"""
        # Convert to lowercase
        normalized = name.lower()
        # Remove common suffixes/prefixes
        normalized = re.sub(r'\s+(protocol|service|app|application)s?$', '', normalized)
        # Remove parenthetical content
        normalized = re.sub(r'\([^)]*\)', '', normalized)
        # Remove extra whitespace
        normalized = ' '.join(normalized.split())
        return normalized.strip()
    
    def string_similarity(self, str1, str2):
        """Calculate string similarity ratio"""
        return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()
    
    def find_exact_match(self, wg_app_name):
        """Try to find exact match in FMC database"""
        # Try exact match first (case-insensitive)
        app_id = self.fmc_db["name_index"].get(wg_app_name.lower())
        if app_id:
            return {
                "fmc_id": app_id,
                "fmc_name": self.fmc_db["applications"][app_id]["name"],
                "confidence": 1.0,
                "match_type": "exact",
                "category": self.fmc_db["applications"][app_id]["category"]
            }
        return None
    
    def find_fuzzy_match(self, wg_app_name):
        """Find best fuzzy match for application name"""
        normalized_wg = self.normalize_name(wg_app_name)
        
        best_match = None
        best_score = 0
        
        for app_id, app_data in self.fmc_db["applications"].items():
            fmc_name = app_data["name"]
            normalized_fmc = self.normalize_name(fmc_name)
            
            # Calculate similarity
            score = self.string_similarity(normalized_wg, normalized_fmc)
            
            # Bonus points for partial word matches
            wg_words = set(normalized_wg.split())
            fmc_words = set(normalized_fmc.split())
            common_words = wg_words & fmc_words
            if common_words and len(wg_words) > 0:
                word_match_bonus = len(common_words) / len(wg_words) * 0.2
                score += word_match_bonus
            
            # Cap at 1.0
            score = min(score, 1.0)
            
            if score > best_score:
                best_score = score
                best_match = {
                    "fmc_id": app_id,
                    "fmc_name": fmc_name,
                    "confidence": score,
                    "match_type": "fuzzy",
                    "category": app_data["category"]
                }
        
        # Only return if above threshold
        if best_match and best_score >= self.confidence_threshold:
            return best_match
        
        return None
    
    def find_category_match(self, wg_app_name):
        """Check if this might be a category name instead of individual app"""
        wg_lower = wg_app_name.lower()
        
        # Common category-like patterns
        category_patterns = [
            'tools', 'services', 'protocols', 'terminals', 'messengers',
            'streaming', 'sharing', 'update', 'management'
        ]
        
        is_category_like = any(pattern in wg_lower for pattern in category_patterns)
        
        if is_category_like:
            # Try to find matching category
            for category_name in self.fmc_db["categories"].keys():
                if self.string_similarity(wg_lower, category_name.lower()) > 0.6:
                    return {
                        "fmc_category": category_name,
                        "fmc_app_count": len(self.fmc_db["categories"][category_name]),
                        "confidence": 0.7,
                        "match_type": "category",
                        "is_category": True
                    }
        
        return None
    
    def map_application(self, wg_app_name):
        """Map a single WatchGuard application to FMC"""
        # Try exact match first
        exact = self.find_exact_match(wg_app_name)
        if exact:
            return exact
        
        # Try fuzzy match
        fuzzy = self.find_fuzzy_match(wg_app_name)
        if fuzzy:
            return fuzzy
        
        # Check if it's a category
        category = self.find_category_match(wg_app_name)
        if category:
            return category
        
        # No match found
        return {
            "fmc_id": None,
            "fmc_name": None,
            "confidence": 0.0,
            "match_type": "no_match",
            "needs_manual_review": True
        }


def extract_unique_apps(wg_config):
    """Extract all unique application names from WatchGuard config"""
    unique_apps = set()
    
    for policy in wg_config.get("app_actions", []):
        for app in policy.get("allowed_apps", []):
            unique_apps.add(app)
        for app in policy.get("blocked_apps", []):
            unique_apps.add(app)
    
    return sorted(list(unique_apps))


def detect_wildcard_fqdns(wg_config):
    """Detect all wildcard FQDN objects and policies that use them"""
    wildcard_objects = []
    
    # Find all wildcard FQDNs
    for fqdn in wg_config.get("addresses", {}).get("fqdns", []):
        if '*' in fqdn.get("fqdn", ""):
            wildcard_objects.append({
                "name": fqdn["name"],
                "fqdn": fqdn["fqdn"],
                "description": fqdn.get("description", "")
            })
    
    # Find policies that reference wildcard FQDNs
    wildcard_names = {obj["name"] for obj in wildcard_objects}
    affected_policies = []
    
    for policy in wg_config.get("policies", []):
        # Check if any source or destination members are wildcards
        referenced_wildcards = []
        
        for member in policy.get("source_members", []):
            if member in wildcard_names:
                referenced_wildcards.append(member)
        
        for member in policy.get("destination_members", []):
            if member in wildcard_names:
                referenced_wildcards.append(member)
        
        if referenced_wildcards:
            affected_policies.append({
                "policy_name": policy["name"],
                "action": policy.get("action"),
                "wildcard_objects": referenced_wildcards,
                "app_action": policy.get("app_action", "")
            })
    
    return {
        "wildcard_objects": wildcard_objects,
        "affected_policies": affected_policies
    }


def analyze_migration(wg_config_file, fmc_apps_file):
    """Main analysis function"""
    
    print("="*60)
    print("WATCHGUARD TO FMC APPLICATION MIGRATION ANALYZER")
    print("="*60)
    
    # Load WatchGuard config
    print(f"\nLoading WatchGuard configuration from {wg_config_file}...")
    try:
        with open(wg_config_file, 'r') as f:
            wg_config = json.load(f)
        print(f"✓ Loaded WatchGuard config")
    except Exception as e:
        print(f"✗ Failed to load WatchGuard config: {e}")
        return False
    
    # Load FMC applications database
    print(f"\nLoading FMC applications database from {fmc_apps_file}...")
    try:
        with open(fmc_apps_file, 'r') as f:
            fmc_db = json.load(f)
        print(f"✓ Loaded {fmc_db['metadata']['total_applications']} FMC applications")
    except Exception as e:
        print(f"✗ Failed to load FMC applications: {e}")
        return False
    
    # Initialize mapper
    mapper = ApplicationMapper(fmc_db)
    
    # Extract unique apps from WatchGuard
    print("\nExtracting unique applications from WatchGuard policies...")
    unique_apps = extract_unique_apps(wg_config)
    print(f"✓ Found {len(unique_apps)} unique applications")
    
    # Map applications
    print("\nMapping applications to FMC equivalents...")
    print(f"  Using {int(mapper.confidence_threshold * 100)}% confidence threshold")
    
    mapping_results = {
        "metadata": {
            "analyzed_date": datetime.now().isoformat(),
            "watchguard_config": wg_config_file,
            "fmc_database": fmc_apps_file,
            "total_apps": len(unique_apps),
            "confidence_threshold": mapper.confidence_threshold
        },
        "mappings": {},
        "statistics": {
            "exact_matches": 0,
            "fuzzy_matches": 0,
            "category_matches": 0,
            "no_matches": 0,
            "needs_review": 0
        }
    }
    
    manual_review = []
    
    for i, wg_app in enumerate(unique_apps, 1):
        print(f"  [{i}/{len(unique_apps)}] Mapping: {wg_app[:50]}...", end='', flush=True)
        
        match = mapper.map_application(wg_app)
        mapping_results["mappings"][wg_app] = match
        
        # Update statistics
        match_type = match["match_type"]
        if match_type == "exact":
            mapping_results["statistics"]["exact_matches"] += 1
            print(f" ✓ EXACT")
        elif match_type == "fuzzy":
            mapping_results["statistics"]["fuzzy_matches"] += 1
            conf_pct = int(match["confidence"] * 100)
            print(f" ≈ FUZZY ({conf_pct}%)")
        elif match_type == "category":
            mapping_results["statistics"]["category_matches"] += 1
            print(f" 📁 CATEGORY")
        else:
            mapping_results["statistics"]["no_matches"] += 1
            print(f" ✗ NO MATCH")
        
        # Flag for manual review if confidence below threshold or no match
        if match.get("needs_manual_review") or match["confidence"] < mapper.confidence_threshold:
            mapping_results["statistics"]["needs_review"] += 1
            manual_review.append({
                "watchguard_name": wg_app,
                "suggested_match": match,
                "requires_action": "Manual mapping required"
            })
    
    # Detect wildcard FQDNs
    print("\nAnalyzing wildcard FQDN usage...")
    wildcard_analysis = detect_wildcard_fqdns(wg_config)
    print(f"✓ Found {len(wildcard_analysis['wildcard_objects'])} wildcard FQDN objects")
    print(f"✓ Found {len(wildcard_analysis['affected_policies'])} policies using wildcards")
    
    # Save mapping file
    mapping_file = "application_mapping.json"
    print(f"\nSaving application mapping to {mapping_file}...")
    with open(mapping_file, 'w') as f:
        json.dump(mapping_results, f, indent=2)
    print(f"✓ Saved")
    
    # Save manual review file
    if manual_review:
        review_file = "manual_review_required.json"
        print(f"\nSaving manual review items to {review_file}...")
        with open(review_file, 'w') as f:
            json.dump({
                "metadata": {
                    "generated": datetime.now().isoformat(),
                    "total_items": len(manual_review)
                },
                "items": manual_review
            }, f, indent=2)
        print(f"✓ Saved {len(manual_review)} items for review")
    
    # Save wildcard analysis
    wildcard_file = "wildcard_fqdn_analysis.json"
    print(f"\nSaving wildcard FQDN analysis to {wildcard_file}...")
    with open(wildcard_file, 'w') as f:
        json.dump(wildcard_analysis, f, indent=2)
    print(f"✓ Saved")
    
    # Generate text report
    report_file = f"migration_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    print(f"\nGenerating migration analysis report...")
    
    with open(report_file, 'w') as f:
        f.write("WATCHGUARD TO FMC APPLICATION MIGRATION ANALYSIS\n")
        f.write("="*80 + "\n\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write(f"WatchGuard Config: {wg_config_file}\n")
        f.write(f"FMC Database: {fmc_apps_file}\n\n")
        
        f.write("MAPPING STATISTICS\n")
        f.write("-"*80 + "\n")
        f.write(f"Total Applications: {len(unique_apps)}\n")
        f.write(f"  Exact Matches:    {mapping_results['statistics']['exact_matches']:4} ({mapping_results['statistics']['exact_matches']/len(unique_apps)*100:.1f}%)\n")
        f.write(f"  Fuzzy Matches:    {mapping_results['statistics']['fuzzy_matches']:4} ({mapping_results['statistics']['fuzzy_matches']/len(unique_apps)*100:.1f}%)\n")
        f.write(f"  Category Matches: {mapping_results['statistics']['category_matches']:4} ({mapping_results['statistics']['category_matches']/len(unique_apps)*100:.1f}%)\n")
        f.write(f"  No Matches:       {mapping_results['statistics']['no_matches']:4} ({mapping_results['statistics']['no_matches']/len(unique_apps)*100:.1f}%)\n")
        f.write(f"  Needs Review:     {mapping_results['statistics']['needs_review']:4} ({mapping_results['statistics']['needs_review']/len(unique_apps)*100:.1f}%)\n\n")
        
        f.write("WILDCARD FQDN ANALYSIS\n")
        f.write("-"*80 + "\n")
        f.write(f"Wildcard FQDN Objects: {len(wildcard_analysis['wildcard_objects'])}\n")
        f.write(f"Affected Policies:     {len(wildcard_analysis['affected_policies'])}\n\n")
        
        if wildcard_analysis['wildcard_objects']:
            f.write("Wildcard FQDNs that cannot be migrated:\n")
            for obj in wildcard_analysis['wildcard_objects']:
                f.write(f"  - {obj['name']}: {obj['fqdn']}\n")
            f.write("\n")
        
        if wildcard_analysis['affected_policies']:
            f.write("Policies using wildcard FQDNs (require URL filtering approach):\n")
            for policy in wildcard_analysis['affected_policies']:
                f.write(f"  - {policy['policy_name']} ({policy['action']})\n")
                f.write(f"    Wildcards: {', '.join(policy['wildcard_objects'])}\n")
            f.write("\n")
        
        f.write("APPLICATION MAPPING DETAILS\n")
        f.write("-"*80 + "\n\n")
        
        # Group by match type
        exact = [(k, v) for k, v in mapping_results["mappings"].items() if v["match_type"] == "exact"]
        fuzzy = [(k, v) for k, v in mapping_results["mappings"].items() if v["match_type"] == "fuzzy"]
        category = [(k, v) for k, v in mapping_results["mappings"].items() if v["match_type"] == "category"]
        no_match = [(k, v) for k, v in mapping_results["mappings"].items() if v["match_type"] == "no_match"]
        
        if exact:
            f.write(f"EXACT MATCHES ({len(exact)})\n")
            f.write("-"*80 + "\n")
            for wg_name, match in sorted(exact):
                f.write(f"{wg_name}\n")
                f.write(f"  → {match['fmc_name']} (ID: {match['fmc_id']})\n")
                f.write(f"  Category: {match['category']}\n\n")
        
        if fuzzy:
            f.write(f"\nFUZZY MATCHES ({len(fuzzy)})\n")
            f.write("-"*80 + "\n")
            for wg_name, match in sorted(fuzzy, key=lambda x: x[1]['confidence'], reverse=True):
                conf_pct = int(match['confidence'] * 100)
                f.write(f"{wg_name}\n")
                f.write(f"  → {match['fmc_name']} (Confidence: {conf_pct}%)\n")
                f.write(f"  ID: {match['fmc_id']}, Category: {match['category']}\n\n")
        
        if category:
            f.write(f"\nCATEGORY MATCHES ({len(category)})\n")
            f.write("-"*80 + "\n")
            f.write("These appear to be categories rather than individual applications.\n")
            f.write("You may need to expand these to individual apps or use FMC category filters.\n\n")
            for wg_name, match in sorted(category):
                f.write(f"{wg_name}\n")
                f.write(f"  → Category: {match.get('fmc_category', 'Unknown')}\n")
                f.write(f"  Contains {match.get('fmc_app_count', 0)} applications\n\n")
        
        if no_match:
            f.write(f"\nNO MATCHES - MANUAL REVIEW REQUIRED ({len(no_match)})\n")
            f.write("-"*80 + "\n")
            f.write("These applications could not be automatically mapped.\n")
            f.write("Review manually and update application_mapping.json as needed.\n\n")
            for wg_name, _ in sorted(no_match):
                f.write(f"  - {wg_name}\n")
            f.write("\n")
        
        f.write("\nNEXT STEPS\n")
        f.write("-"*80 + "\n")
        f.write("1. Review manual_review_required.json and update mappings\n")
        f.write("2. Review wildcard_fqdn_analysis.json for URL filtering strategy\n")
        f.write("3. Edit application_mapping.json to correct any fuzzy matches\n")
        f.write("4. Run translate_app_policies.py to generate FMC access rules\n")
    
    print(f"✓ Report saved to {report_file}")
    
    # Print summary
    print("\n" + "="*60)
    print("ANALYSIS COMPLETE")
    print("="*60)
    
    stats = mapping_results["statistics"]
    print(f"\nMapping Results:")
    print(f"  Exact Matches:    {stats['exact_matches']:4} ({stats['exact_matches']/len(unique_apps)*100:.1f}%)")
    print(f"  Fuzzy Matches:    {stats['fuzzy_matches']:4} ({stats['fuzzy_matches']/len(unique_apps)*100:.1f}%)")
    print(f"  Category Matches: {stats['category_matches']:4} ({stats['category_matches']/len(unique_apps)*100:.1f}%)")
    print(f"  No Matches:       {stats['no_matches']:4} ({stats['no_matches']/len(unique_apps)*100:.1f}%)")
    print(f"  Needs Review:     {stats['needs_review']:4} ({stats['needs_review']/len(unique_apps)*100:.1f}%)")
    
    print(f"\nWildcard FQDN Analysis:")
    print(f"  Wildcard Objects:   {len(wildcard_analysis['wildcard_objects'])}")
    print(f"  Affected Policies:  {len(wildcard_analysis['affected_policies'])}")
    
    print(f"\nFiles Generated:")
    print(f"  ✓ {mapping_file} - Application mappings")
    if manual_review:
        print(f"  ✓ {review_file} - Items needing manual review")
    print(f"  ✓ {wildcard_file} - Wildcard FQDN analysis")
    print(f"  ✓ {report_file} - Full analysis report")
    
    print("\nNext Steps:")
    print("  1. Review the analysis report")
    print("  2. Check manual_review_required.json for unmapped apps")
    print("  3. Edit application_mapping.json to correct any mappings")
    print("  4. Address wildcard FQDN policies (consider URL filtering)")
    print("  5. Run translate_app_policies.py when ready")
    
    return True


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python analyze_app_migration.py <watchguard_config.json> <fmc_applications.json>")
        print("\nExample:")
        print("  python analyze_app_migration.py parsed_watchguard.json fmc_applications.json")
        print("\nThis script analyzes WatchGuard application control policies and maps them")
        print("to FMC applications. It also identifies wildcard FQDN objects that cannot")
        print("be directly migrated to FMC.")
        sys.exit(1)
    
    wg_config_file = sys.argv[1]
    fmc_apps_file = sys.argv[2]
    
    success = analyze_migration(wg_config_file, fmc_apps_file)
    sys.exit(0 if success else 1)