import requests
import json
import csv
import sys
import os
import pandas as pd

# Set a higher recursion limit for complex JSON processing if needed
# sys.setrecursionlimit(2000) 

def get_xray_violations_page(server_base_url, access_token, watch_name, limit, offset):
    """
    Fetches a single page of Xray violations using the REST API.
    
    Args:
        server_base_url (str): The base URL of your JFrog Platform (e.g., https://jfrog.io).
        access_token (str): The JFrog Access Token for authentication.
        watch_name (str): The name of the Xray Watch to filter by.
        limit (int): The page size limit.
        offset (int): The page offset (starting index).

    Returns:
        dict: The JSON response body if successful, otherwise None.
    """
    
    api_url = f"{server_base_url}/xray/api/v1/violations"
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }
    
    payload = {
        "filters": {
            "watch_name": watch_name
        },
        "pagination": {
            "limit": limit,
            "offset": offset
        }
    }
    
    print(f"  -> Fetching page with offset: {offset}")
    
    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.HTTPError as err:
        print(f"Error fetching data (HTTP {response.status_code}): {err}", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as err:
        print(f"Connection Error: {err}", file=sys.stderr)
        return None


def process_page_to_tsv(json_data, tsv_file):
    """
    Processes JSON violation data and appends it to a TSV file.
    
    Args:
        json_data (dict): The JSON response containing violation data.
        tsv_file (str): The path to the output TSV file.

    Returns:
        int: The number of violations processed on this page.
    """
    violations = json_data.get('violations', [])
    processed_count = 0
    
    # We open the file in append mode ('a') for continuous writing
    # We use 'csv.writer' with a TAB delimiter for robust TSV writing
    with open(tsv_file, 'a', newline='', encoding='utf-8') as f:
        # Use csv module's writer with a tab delimiter
        writer = csv.writer(f, delimiter='\t', quoting=csv.QUOTE_ALL)
        
        for violation in violations:
            # Safely extract all fields, using .get() and list/dict indexing
            impacted_artifact = violation.get('impacted_artifacts', [None])[0]
            repo_name = impacted_artifact.split('/')[1] if isinstance(impacted_artifact, str) and '/' in impacted_artifact else None
            
            # Extract vulnerability_id safely
            applicability_details = violation.get('applicability_details', [{}])
            vulnerability_id = applicability_details[0].get('vulnerability_id') if applicability_details and isinstance(applicability_details[0], dict) else 'N/A'
            
            row = [
                violation.get('type'),
                violation.get('watch_name'),
                violation.get('severity'),
                repo_name, # RepoNameOfImpactedArtifact
                impacted_artifact, # ImpactedArtifacts
                vulnerability_id, # Vulnerability_Id
                violation.get('issue_id'),
                violation.get('description') # Description (The multi-line field)
            ]
            
            writer.writerow(row)
            processed_count += 1
            
    return processed_count

def build_repo_user_map(server_base_url, access_token, violations_data):
    """
    Builds a dictionary mapping repository names to their assigned users 
    by querying the Artifactory Permissions and Access Group APIs.

    Args:
        server_base_url (str): The base URL of your JFrog Platform.
        access_token (str): The JFrog Access Token.
        violations_data (list): List of unique repository names to process.

    Returns:
        dict: A map {repo_name: 'user1|user2|userN'}
    """
    repo_user_map = {}
    
    # Base URLs for Artifactory and Access APIs
    artifactory_url = f"{server_base_url}/artifactory/api/storage"
    access_url = f"{server_base_url}/access/api/v2/groups"
    
    headers = {"Authorization": f"Bearer {access_token}"}
    
    print("\n--- Building Repo-to-User Lookup ---")
    
    for repo in violations_data:
        repo_name = repo.strip().strip('"') # Clean up any leading/trailing quotes/spaces

        # 1. Handle '-cache' removal (Logic from shell script)
        repon = repo_name.replace("-cache", "") if repo_name.lower().endswith("-cache") else repo_name
        
        #print(f"Processing repo: {repo_name} (Querying: {repon})")

        # 2. Fetch Manage-group name from Permissions API
        try:
            storage_url = f"{artifactory_url}/{repon}?permissions"
            response = requests.get(storage_url, headers=headers, timeout=10)
            response.raise_for_status()
            permissions_data = response.json()
            
            # Find the group key that ends with '-Manage'
            manage_group = None
            groups = permissions_data.get('principals', {}).get('groups', {})
            
            for group_name in groups.keys():
                if group_name.lower().endswith('-manage'):
                    manage_group = group_name
                    break
            
            if not manage_group:
                repo_user_map[repo_name] = "NA"
                #print("  → No Manage group found.")
                continue

            print(f"  → Found group: {manage_group}")

            # 3. Fetch users in Manage-group from Access API
            users_url = f"{access_url}/{manage_group}"
            users_response = requests.get(users_url, headers=headers, timeout=10)
            users_response.raise_for_status()
            users_data = users_response.json()
            
            members = users_data.get('members', [])
            
            # Join members with '|'
            users = ",".join(members) if members else "NA"
            
            repo_user_map[repo_name] = users
            #print(f"  → Users: {users}")

        except requests.exceptions.HTTPError as e:
            # Handle cases where the repo or group is not found (404)
            print(f"  → Error querying API for {repon} (Status: {e.response.status_code}). Assigning NA.", file=sys.stderr)
            repo_user_map[repo_name] = "NA"
        except Exception as e:
            print(f"  → An unexpected error occurred for {repon}: {e}. Assigning NA.", file=sys.stderr)
            repo_user_map[repo_name] = "NA"
            
    print("--- Lookup Complete ---")
    return repo_user_map

def get_xray_watch_violations(server_base_url, access_token, watch_name):
    """
    Main function to fetch all violations for a watch using pagination.
    """
    
    print(f"Fetching Xray violations for watch '{watch_name}' from server...")
    
    limit = 100  # Page size limit
    
    tsv_file = f"violations_{watch_name}.tsv"
    FINAL_OUTPUT_FILE = f"violations_enriched_{watch_name}.tsv"
    # 1. Fetch the first page (Offset 0) to get total_violations
    # The first call must still use offset 0 to retrieve the total count.
    first_page_data = get_xray_violations_page(server_base_url, access_token, watch_name, limit, 0)
    if not first_page_data:
        return

    total_violations = first_page_data.get('total_violations', 0)
    
    if total_violations == 0:
        print("  -> Total violations: 0. Exiting.")
        return
        
    total_pages = (total_violations + limit - 1) // limit
    print(f"Total violations found: {total_violations}. Total pages: {total_pages}")

    # 2. Write the TSV Header
    tsv_file = f"violations_{watch_name}.tsv"
    header = ["Type", "WatchName", "Severity", "RepoNameOfImpactedArtifact", "ImpactedArtifacts", "Vulnerability_Id", "Issue_ID", "Description"]
    with open(tsv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter='\t', quoting=csv.QUOTE_ALL)
        writer.writerow(header)

    violations_count = 0

    # 3. Loop through all pages, implementing the working shell logic
    for i in range(total_pages):
        
        # *** IMPLEMENTING YOUR WORKING LOGIC: OFFSET = i + 1 ***
        # If the API interprets offset as Page Number (1, 2, 3...)
        offset_page_number = i + 1
        
        # If this is the first page (i=0), use the already fetched data.
        if i == 0:
            current_offset = 0 # Use the index 0 for the first fetch
            page_data = first_page_data
        else:
            # For subsequent pages, use the Page Number as the offset argument.
            current_offset = offset_page_number 
            
            # Call API with the page number as the offset
            page_data = get_xray_violations_page(server_base_url, access_token, watch_name, limit, current_offset)
            
            if not page_data:
                break

        print(f"  -> Processing page {i + 1}")
            
        # Process and write the data to the TSV file
        array_length = process_page_to_tsv(page_data, tsv_file)
        violations_count += array_length
        
        if array_length == 0 and i < total_pages - 1:
            print("Warning: API returned 0 violations unexpectedly. Stopping early.")
            break

    print(f"Successfully fetched a total of {violations_count} violations.")
    print(f"TSV report created: {tsv_file}")
# 4. Extract unique repository names from the generated TSV file
    # We load the generated TSV file to get the list of repositories.
    try:
        violations_df = pd.read_csv(tsv_file, sep='\t', quoting=csv.QUOTE_ALL)
        unique_repos = violations_df['RepoNameOfImpactedArtifact'].unique().tolist()
    except Exception as e:
        print(f"Error reading generated TSV file: {e}", file=sys.stderr)
        return

    # 5. Build the Repo-to-User Map (The new logic)
    repo_user_map = build_repo_user_map(server_base_url, access_token, unique_repos)

    # 6. Merge the user map into the violations DataFrame
    
    # Create a DataFrame from the map for easy merging
    map_df = pd.DataFrame(repo_user_map.items(), columns=['RepoNameOfImpactedArtifact', 'User_Assignment'])
    
    # Merge on the repository name
    final_df = pd.merge(violations_df, map_df, on='RepoNameOfImpactedArtifact', how='left')
    
    # Fill any remaining NA users with "NA" (for repos that weren't in the unique list, if any)
    final_df['User_Assignment'] = final_df['User_Assignment'].fillna('NA')

    # 7. Save the final enriched file (Replaces your FINAL variable)
    final_df.to_csv(FINAL_OUTPUT_FILE, sep='\t', index=False, quoting=csv.QUOTE_ALL)
    
    print(f"Successfully fetched a total of {violations_count} violations.")
    print(f"Final enriched TSV report created: {FINAL_OUTPUT_FILE}")

def validate_watch(server_base_url, access_token, watch_name):
    """
    Validates if the specified Xray Watch exists by fetching its details directly.
    """
    # Use the direct endpoint: /api/v2/watches/{watch_name}
    api_url = f"{server_base_url}/xray/api/v2/watches/{watch_name}"
    
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    
    print("Validating Watch name...")
    
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        
        # Check for success (200 OK)
        if response.status_code == 200:
            # Successfully fetched the configuration, so the watch exists.
            print(f"   Watch {watch_name} validated successfully.")
            return True
        
        # Check for Not Found (404)
        elif response.status_code == 404:
            # The API confirms the watch does not exist.
            print(f"   Watch {watch_name} does not exist. Exiting.")
            sys.exit(1)
            
        # Handle other API errors (e.g., 401 Unauthorized, 500 Server Error)
        else:
            print(f"Error validating watch (HTTP {response.status_code}). Exiting.", file=sys.stderr)
            print(f"API Response: {response.text}", file=sys.stderr)
            sys.exit(1)

    except requests.exceptions.RequestException as err:
        print(f"Connection or Request Error: {err}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    # --- Execution ---
    
    # Check if we have the correct number of arguments
    if len(sys.argv) != 4:
        print("Usage: python get_watch_violations.py <server_base_url> <access_token> <watch_name>")
        print("Example: python get_watch_violations.py https://myorg.jfrog.io my_secret_token infymaliciouswatch")
        sys.exit(1)

    SERVER_BASE_URL = sys.argv[1]
    ACCESS_TOKEN = sys.argv[2]
    WATCH_NAME = sys.argv[3]

    # 1. Validate the watch name
    validate_watch(SERVER_BASE_URL, ACCESS_TOKEN, WATCH_NAME)
    
    # Run the main function
    get_xray_watch_violations(SERVER_BASE_URL, ACCESS_TOKEN, WATCH_NAME)
