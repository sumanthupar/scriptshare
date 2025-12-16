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
            impacted_artifact = violation.get('impacted_artifacts', [None])[0]
            repo_name = impacted_artifact.split('/')[1] if isinstance(impacted_artifact, str) and '/' in impacted_artifact else None
            
            applicability_details = violation.get('applicability_details', [{}])
            vulnerability_id = applicability_details[0].get('vulnerability_id') if applicability_details and isinstance(applicability_details[0], dict) else 'N/A'
            issue_id = violation.get('issue_id') 
            
            fixed_version_list = "|".join(violation.get('fix_versions', []))
            infected_components = "|".join(violation.get('infected_components', []))
            infected_versions = "|".join(violation.get('infected_versions', []))
            
            row = [
                violation.get('type'),
                violation.get('watch_name'),
                violation.get('severity'),
                repo_name, 
                impacted_artifact, 
                vulnerability_id, 
                issue_id,
                infected_components,   
                infected_versions,     
                fixed_version_list,    
                violation.get('description') 
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
        repo_name = repo.strip().strip('"') 

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
            
            users = "|".join(members) if members else "NA" 
            
            repo_user_map[repo_name] = users

        except requests.exceptions.HTTPError as e:
            print(f"  → Error querying API for {repon} (Status: {e.response.status_code}). Assigning NA.", file=sys.stderr)
            repo_user_map[repo_name] = "NA"
        except Exception as e:
            print(f"  → An unexpected error occurred for {repon}: {e}. Assigning NA.", file=sys.stderr)
            repo_user_map[repo_name] = "NA"
            
    print("--- Lookup Complete ---")
    return repo_user_map

def get_xray_watch_violations(server_base_url, access_token, watch_name):
    
    print(f"Fetching Xray violations for watch '{watch_name}' from server...")
    
    limit = 100 
    CSV_FILE = f"violations_{watch_name}.csv"
    FINAL_OUTPUT_FILE = f"violations_enriched_{watch_name}.csv"
    
    header = ["Type", "WatchName", "Severity", "RepoNameOfImpactedArtifact", "ImpactedArtifacts", 
              "Vulnerability_Id", "Issue_ID", "Infected_Components", "Infected_Versions", 
              "Fixed_Versions", "Description"]
    
    with open(CSV_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter=',', quoting=csv.QUOTE_ALL)
        writer.writerow(header)

    first_page_data = get_xray_violations_page(server_base_url, access_token, watch_name, limit, 0)
    if not first_page_data:
        return

    total_violations = first_page_data.get('total_violations', 0)
    if total_violations == 0:
        print("  -> Total violations: 0. Exiting.")
        return
        
    total_pages = (total_violations + limit - 1) // limit
    print(f"Total violations found: {total_violations}. Total pages: {total_pages}")

    violations_count = 0
    for i in range(total_pages):
        
        offset_page_number = i + 1
        
        if i == 0:
            page_data = first_page_data
        else:
            page_data = get_xray_violations_page(server_base_url, access_token, watch_name, limit, offset_page_number)
            if not page_data:
                break

        print(f"  -> Processing page {i + 1}")
        array_length = write_page_to_csv(page_data, CSV_FILE)
        violations_count += array_length
        
        if array_length == 0 and i < total_pages - 1:
            print("Warning: API returned 0 violations unexpectedly. Stopping early.")
            break

    print(f"\nSuccessfully fetched {violations_count} violation records into {CSV_FILE}.")
    
    
    try:
        violations_df = pd.read_csv(CSV_FILE, sep=',', quoting=csv.QUOTE_ALL)
        unique_repos = violations_df['RepoNameOfImpactedArtifact'].unique().tolist()
    except Exception as e:
        print(f"Error reading generated CSV file: {e}", file=sys.stderr)
        return

    repo_user_map = build_repo_user_map(server_base_url, access_token, unique_repos)

    map_df = pd.DataFrame(repo_user_map.items(), columns=['RepoNameOfImpactedArtifact', 'User_Assignment'])
    

    final_df = pd.merge(violations_df, map_df, on='RepoNameOfImpactedArtifact', how='left')
    

    FINAL_COLUMN_ORDER = header + ['User_Assignment']
    

    final_df = final_df.reindex(columns=FINAL_COLUMN_ORDER)
    

    final_df['User_Assignment'] = final_df['User_Assignment'].fillna('NA')

    final_df.to_csv(FINAL_OUTPUT_FILE, sep=',', index=False, quoting=csv.QUOTE_ALL)
    
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)

    print(f"\nProcessing complete. Final enriched CSV report created: {FINAL_OUTPUT_FILE}")


def validate_watch(server_base_url, access_token, watch_name):
    api_url = f"{server_base_url}/xray/api/v2/watches/{watch_name}"
    
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    
    print("Validating Watch name...")
    
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print(f"   Watch {watch_name} validated successfully.")
            return True
        
        elif response.status_code == 404:
            print(f"   Watch {watch_name} does not exist. Exiting.")
            sys.exit(1)
            
        else:
            print(f"Error validating watch (HTTP {response.status_code}). Exiting.", file=sys.stderr)
            print(f"API Response: {response.text}", file=sys.stderr)
            sys.exit(1)

    except requests.exceptions.RequestException as err:
        print(f"Connection or Request Error: {err}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python get_watch_violations.py <server_base_url> <access_token> <watch_name>")
        print("Example: python get_watch_violations.py https://myorg.jfrog.io my_secret_token bluecherry_watch")
        sys.exit(1)

    SERVER_BASE_URL = sys.argv[1]
    ACCESS_TOKEN = sys.argv[2]
    WATCH_NAME = sys.argv[3]

    validate_watch(SERVER_BASE_URL, ACCESS_TOKEN, WATCH_NAME)
    
    get_xray_watch_violations(SERVER_BASE_URL, ACCESS_TOKEN, WATCH_NAME)
