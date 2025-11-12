#!/bin/bash

# =========================================================
# JFrog Xray Watch Repository Updater Script (Pre-Configured CLI)
# =========================================================

SERVER_ID="${1:?ERROR: Please provide the configured JFrog CLI Server ID as the first argument.}"
XRAY_WATCH_NAME="${2:?ERROR: Please provide the Xray Watch Name as the second argument.}"
REPO_LIST_FILE="${3:?ERROR: Please provide the path to the file containing repo keys (one per line) as the third argument.}"

if [ ! -f "$REPO_LIST_FILE" ]; then
    echo "ERROR: Repository list file not found at: ${REPO_LIST_FILE}"
    exit 1
fi

# --- Initialize Files ---
WATCH_FILE="current_watch_${XRAY_WATCH_NAME}.json"
UPDATED_WATCH_FILE="updated_watch_${XRAY_WATCH_NAME}.json"
NEW_RESOURCES=()

RepoActions(){

while IFS= read -r REPO_KEY; do
    REPO_KEY=$(echo "$REPO_KEY" | xargs) # Trim whitespace

    if [ -z "$REPO_KEY" ]; then
        continue
    fi

    echo "   Processing: ${REPO_KEY}"

	jf rt curl -s -XGET "/api/repositories" --server-id="$SERVER_ID" | grep -i "$REPO_KEY" > /dev/null 2>&1
	if [ $? -eq 0 ];then
		REPO_TYPE=$(jf rt curl -s -XGET "/api/repositories/$REPO_KEY" --server-id="$SERVER_ID" | jq -r '.rclass')
	else
		echo "   Repo $REPO_KEY not exist, Skipping"	
		continue
	fi

    # Map the Artifactory rclass to the Xray Watch resource type
    if [[ "$REPO_TYPE" == "local" || "$REPO_TYPE" == "federated" ]]; then
        REPO_TYPE="local"
    elif [[ "$REPO_TYPE" == "remote" ]]; then
        REPO_TYPE="remote"
    else
        echo "WARNING: Could not determine type for ${REPO_KEY}. RCLASS: ${RCLASS}. Skipping."
        continue
    fi

    # Create the JSON object for the Xray resource
    REPO_RESOURCE_JSON=$(jq -n --arg type "repository" --arg repo_typ "$REPO_TYPE" --arg repo_key "$REPO_KEY" --arg bin_mgr_id "default" \
        '{
            "type": $type,
            "bin_mgr_id": $bin_mgr_id,
            "name": $repo_key,
	    "repo_type": $repo_typ
        }')

    NEW_RESOURCES+=("$REPO_RESOURCE_JSON")
done < "$REPO_LIST_FILE"

if [ ${#NEW_RESOURCES[@]} -eq 0 ]; then
    echo "ERROR: No valid repositories found to add. Exiting."
    exit 1
fi

NEW_RESOURCES_JSON=$(printf "%s\n" "${NEW_RESOURCES[@]}" | jq -s '.')
}

XrayActions()
{
jf xr curl "api/v2/watches/${XRAY_WATCH_NAME}" -X GET -o "$WATCH_FILE" -s
mkdir -p backup
cp $WATCH_FILE backup/$WATCH_FILE

if [ $? -ne 0 ] || ! jq -e . "$WATCH_FILE" >/dev/null; then
    echo "Error or invalid JSON received when fetching Watch. Check Watch name."
    rm -f "$WATCH_FILE"
    exit 1
fi
FormatJson
}

FormatJson()
{
jq --argjson new_resources "$NEW_RESOURCES_JSON" \
   '
    .project_resources.resources |= (. // [])
    |
    .project_resources.resources += $new_resources
    |
    .project_resources.resources = (
        .project_resources.resources | unique_by(.name + .type + .bin_mgr_id)
    )
   ' \
   "$WATCH_FILE" > "$UPDATED_WATCH_FILE"
}
Update()
{
jf xr curl "api/v2/watches/${XRAY_WATCH_NAME}" -X PUT -H "Content-Type: application/json" -d "@${UPDATED_WATCH_FILE}"
}

rm -f "$WATCH_FILE" "$UPDATED_WATCH_FILE"

RepoActions
XrayActions
Update
