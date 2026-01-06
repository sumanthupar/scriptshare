import requests
import json
import csv
import sys
import os
import pandas as pd

def get_xray_violations_page(server_base_url, access_token, watch_name, limit, offset):
    api_url = f"{server_base_url}/xray/api/v1/violations" 
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }
    
    payload = {
        "filters": {
            "watch_name": watch_name,
            "include_details": True  
        },
        "pagination": {
            "limit": limit,
            "offset": offset
        }
    }
    
    print(f"  -> Fetching page with offset: {offset}")
    
    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as err:
        print(f"Error fetching data (HTTP {response.status_code}): {err}", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as err:
        print(f"Connection Error: {err}", file=sys.stderr)
        return None


def write_page_to_csv(json_data, csv_file):
    violations = json_data.get('violations', [])
    processed_count = 0
    
    with open(csv_file, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter=',', quoting=csv.QUOTE_ALL)
        
        for violation in violations:
            # 1. Artifact and Repo parsing
            impacted_artifacts = violation.get('impacted_artifacts', [])
            impacted_artifact = impacted_artifacts[0] if impacted_artifacts else "NA"
            
            repo_name = "NA"
            if isinstance(impacted_artifact, str) and '/' in impacted_artifact:
                parts = impacted_artifact.split('/')
                if len(parts) > 1:
                    repo_name = parts[1]
            
            # 2. Join lists with NA fallback
            fixed_version_list = "|".join(violation.get('fix_versions', [])) or "NA"
            infected_components = "|".join(violation.get('infected_components', [])) or "NA"
            infected_versions = "|".join(violation.get('infected_versions', [])) or "NA"

            # 3. CVE and CVSS Score (Trimmed)
            properties_list = violation.get('properties', [])
            properties = properties_list[0] if properties_list else {}
            cve_id = properties.get('cve') or "NA"
            
            raw_cvss = properties.get('cvss_v3') or "NA"
            cvss_v3 = raw_cvss.split('/')[0] if '/' in raw_cvss else raw_cvss

            # 4. AGGRESSIVE RESEARCH FIELDS FALLBACK (Handles missing extended_information)
            research_summary = "NA"
            research_details = "NA"
            remediation = "NA"

            ext_info = violation.get('extended_information')
            if isinstance(ext_info, dict) and ext_info:
                research_summary = ext_info.get('short_description') or "NA"
                research_details = ext_info.get('full_description') or "NA"
                remediation = ext_info.get('remediation') or "NA"
            
            # 5. Build Row
            row = [
                str(violation.get('type') or "NA"),
                str(violation.get('watch_name') or "NA"),
                str(violation.get('severity') or "NA"),
                str(repo_name), 
                str(impacted_artifact), 
                str(cve_id),
                str(cvss_v3),
                str(infected_components),   
                str(infected_versions),     
                str(fixed_version_list),    
                str(violation.get('description') or "NA"),
                str(research_summary),
                str(research_details),
                str(remediation)
            ]
            
            writer.writerow(row)
            processed_count += 1
            
    return processed_count


def build_repo_user_map(server_base_url, access_token, violations_data):
    repo_user_map = {}
    artifactory_url = f"{server_base_url}/artifactory/api/storage"
    access_url = f"{server_base_url}/access/api/v2/groups"
    headers = {"Authorization": f"Bearer {access_token}"}
    
    print("\n--- Building Repo-to-User Lookup ---")
    
    for repo in violations_data:
        repo_name = str(repo).strip().strip('"') 
        repon = repo_name.replace("-cache", "") if repo_name.lower().endswith("-cache") else repo_name
        
        try:
            storage_url = f"{artifactory_url}/{repon}?permissions"
            response = requests.get(storage_url, headers=headers, timeout=10)
            response.raise_for_status()
            permissions_data = response.json()
            
            manage_group = None
            groups = permissions_data.get('principals', {}).get('groups', {})
            for group_name in groups.keys():
                if group_name.lower().endswith('-manage'):
                    manage_group = group_name
                    break
            
            if not manage_group:
                repo_user_map[repo_name] = "NA"
                continue

            users_url = f"{access_url}/{manage_group}"
            users_response = requests.get(users_url, headers=headers, timeout=10)
            users_response.raise_for_status()
            users_data = users_response.json()
            members = users_data.get('members', [])
            
            repo_user_map[repo_name] = "|".join(members) if members else "NA"

        except Exception:
            repo_user_map[repo_name] = "NA"
            
    print("--- Lookup Complete ---")
    return repo_user_map

def get_xray_watch_violations(server_base_url, access_token, watch_name):
    print(f"Fetching Xray violations for watch '{watch_name}'...")
    
    limit = 100 
    CSV_FILE = f"violations_{watch_name}.csv"
    FINAL_OUTPUT_FILE = f"violations_enriched_{watch_name}.csv"
    
    header = [
        "Type", "WatchName", "Severity", "RepoNameOfImpactedArtifact", "ImpactedArtifacts", 
        "CVEID", "CVSSV3", "InfectedComponents", "InfectedVersions", "FixedVersions", 
        "Description", "JFrogResearchSummary", "JFrogResearchDetails", "JFrogResearchRemediation"
    ]
    
    with open(CSV_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter=',', quoting=csv.QUOTE_ALL)
        writer.writerow(header)

    first_page_data = get_xray_violations_page(server_base_url, access_token, watch_name, limit, 0)
    if not first_page_data:
        return

    total_violations = first_page_data.get('total_violations', 0)
    if total_violations == 0:
        print("  -> No violations found.")
        return
        
    total_pages = (total_violations + limit - 1) // limit
    print(f"Total violations: {total_violations}. Total pages: {total_pages}")

    violations_count = 0
    for i in range(total_pages):
        offset = i + 1
        page_data = first_page_data if i == 0 else get_xray_violations_page(server_base_url, access_token, watch_name, limit, offset)
        
        if not page_data: break
        
        array_length = write_page_to_csv(page_data, CSV_FILE)
        violations_count += array_length

    # Enrichment Phase
    try:
        violations_df = pd.read_csv(CSV_FILE, sep=',', quoting=csv.QUOTE_ALL)
        unique_repos = violations_df['RepoNameOfImpactedArtifact'].dropna().unique().tolist()
        
        repo_user_map = build_repo_user_map(server_base_url, access_token, unique_repos)
        map_df = pd.DataFrame(repo_user_map.items(), columns=['RepoNameOfImpactedArtifact', 'Users'])
        
        final_df = pd.merge(violations_df, map_df, on='RepoNameOfImpactedArtifact', how='left')
        final_df['Users'] = final_df['Users'].fillna('NA')

        final_df.to_csv(FINAL_OUTPUT_FILE, sep=',', index=False, quoting=csv.QUOTE_ALL)
        if os.path.exists(CSV_FILE): os.remove(CSV_FILE)
        
        print(f"\nSuccess. Report created: {FINAL_OUTPUT_FILE}")
    except Exception as e:
        print(f"Enrichment Error: {e}")

def validate_watch(server_base_url, access_token, watch_name):
    api_url = f"{server_base_url}/xray/api/v2/watches/{watch_name}"
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200: return True
        sys.exit(f"Error: Watch {watch_name} not found.")
    except Exception as e:
        sys.exit(f"Connection Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python get_watch_violations.py <url> <token> <watch>")
        sys.exit(1)

    SERVER_BASE_URL, ACCESS_TOKEN, WATCH_NAME = sys.argv[1], sys.argv[2], sys.argv[3]
    validate_watch(SERVER_BASE_URL, ACCESS_TOKEN, WATCH_NAME)
    get_xray_watch_violations(SERVER_BASE_URL, ACCESS_TOKEN, WATCH_NAME)
