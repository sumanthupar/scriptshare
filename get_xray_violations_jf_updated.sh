#!/bin/bash
# -------------------------------------------------------------------
# Fetch JFrog Xray Violations for a given Watch using JFrog CLI
# Creates both JSON and CSV outputs
# Usage: ./get_xray_violations_jf.sh <server-id> <watch-name>
# Example: ./get_xray_violations_jf.sh psblr dockall
# -------------------------------------------------------------------

SERVER_ID="$1"
WATCH_NAME="$2"

if [[ -z "$SERVER_ID" || -z "$WATCH_NAME" ]]; then
  echo "Usage: $0 <server-id> <watch-name>"
  exit 1
fi

JSON_FILE="violations_${WATCH_NAME}.json"
CSV_FILE="violations_${WATCH_NAME}.csv"


ValidateWatch()
{
        jf xr curl -s -XGET "api/v2/watches" --server-id="$SERVER_ID" | grep -i "$WATCH_NAME" > /dev/null 2>&1
        if [ $? -ne 0 ];then
                echo "   Watch $WATCH_NAME not exist, Exitting"
                exit 1
        fi
}

GetXrayWatchViolations()
{

echo "Fetching Xray violations for watch '${WATCH_NAME}' from server '${SERVER_ID}'..."

# --- Fetch data from Xray ---
jf xr curl -s -XPOST "api/v1/violations" \
  -H "Content-Type: application/json" \
  -d "{
        \"filters\": {
          \"watch_name\": \"${WATCH_NAME}\"
        }
      }" \
  --server-id "${SERVER_ID}" > "${JSON_FILE}"
# --- Validate JSON ---
if ! jq empty "${JSON_FILE}" 2>/dev/null; then
  echo "Failed to fetch valid JSON data. Please check the server ID, watch name, or permissions."
  exit 1
fi

echo "JSON data saved to: ${JSON_FILE}"

}


FormatOut()
{
# --- Generate CSV ---
echo "Generating CSV report..."

  echo "Type,WatchName,Severity,RepoNameOfImpactedArtifact,ImpactedArtifacts,Vulnerability_Id,Issue_ID,Description" > ${CSV_FILE}
jq -r '
  .violations[] |
  [
    .type,
    .watch_name,
    .severity,
    (.impacted_artifacts[0] | split("/")[1]),
    .impacted_artifacts[0],
    .applicability_details[0].vulnerability_id,
    .issue_id,
    .description
  ] | @csv' "${JSON_FILE}" >> "${CSV_FILE}"

if [[ -s "${CSV_FILE}" ]]; then
  echo "CSV report created: ${CSV_FILE}"
else
  echo "No violations found or CSV file is empty."
fi
}

ValidateWatch
GetXrayWatchViolations
FormatOut
