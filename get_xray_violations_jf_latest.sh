#!/bin/bash

SERVER_ID="$1"
WATCH_NAME="$2"

if [[ -z "$SERVER_ID" || -z "$WATCH_NAME" ]]; then
  echo "Usage: $SCRIPT_NAME <server-id> <watch-name>"
  exit 1
fi

JSON_FILE="violations_${WATCH_NAME}.json"
CSV_FILE="violations_${WATCH_NAME}.csv"
TEMP_JSON_FILE="temp_violations_page.json"


ValidateWatch()
{
  echo "Validating Watch name..."
  # Using v2 endpoint for watch validation is generally recommended
  jf xr curl -s -XGET "api/v2/watches" --server-id="$SERVER_ID" | grep -i "$WATCH_NAME" > /dev/null 2>&1
  if [ $? -ne 0 ];then
    echo "   Watch $WATCH_NAME does not exist. Exiting."
    exit 1
  fi
  echo "   Watch $WATCH_NAME validated successfully."
}

GetXrayViolationsPage()
{
  local LIMIT=$1
  local OFFSET=$2
  
  echo "  -> Fetching page with offset: ${OFFSET}"
  jf xr curl -s -XPOST "api/v1/violations" \
    -H "Content-Type: application/json" \
    -d "{
          \"filters\": {
            \"watch_name\": \"${WATCH_NAME}\"
          },
          \"pagination\": {
            \"limit\": ${LIMIT},
            \"offset\": ${OFFSET}
          }
        }" \
    --server-id "${SERVER_ID}" > "${TEMP_JSON_FILE}"

  if [[ ! -s "${TEMP_JSON_FILE}" ]]; then
    echo "Error: API call failed or returned an empty response for offset ${OFFSET}." >&2
    return 1
  fi
  if ! jq empty "${TEMP_JSON_FILE}" 2>/dev/null; then
    echo "Error: Failed to parse valid JSON data from page offset ${OFFSET}. Check for non-JSON output." >&2
    return 1
  fi
}

ProcessPageToCSV()
{
  local TEMP_JSON_FILE="$1"
  local CSV_FILE="$2"
  
  jq -r '
    .violations[] |
    [
      .type,
      .watch_name,
      .severity,
      (.impacted_artifacts[0] | split("/")[1]),
      .impacted_artifacts[0],
      (.applicability_details[0].vulnerability_id // "N/A"),
      .issue_id,
      .description
    ] | @csv' "${TEMP_JSON_FILE}" >> "${CSV_FILE}"

  jq '.violations | length' "${TEMP_JSON_FILE}" 2>/dev/null
}


GetXrayWatchViolations()
{
  echo "Fetching Xray violations for watch '${WATCH_NAME}' from server '${SERVER_ID}'..."

  local LIMIT=100  # Set page size limit
  local OFFSET=0   # START at 0 (First Page Index)
  local TOTAL_VIOLATIONS=0
  local VIOLATIONS_COUNT=0
  
  GetXrayViolationsPage "${LIMIT}" "${OFFSET}" || return 1
  
  TOTAL_VIOLATIONS=$(jq -r '.total_violations' "${TEMP_JSON_FILE}" 2>/dev/null)
  
  if [[ -z "$TOTAL_VIOLATIONS" || "$TOTAL_VIOLATIONS" -eq 0 ]]; then
      echo "  -> Total violations: 0. Exiting."
      return 0
  fi
  
  TOTAL_PAGES=$(((TOTAL_VIOLATIONS + LIMIT - 1) / LIMIT))
  

  echo "Generating CSV report..."
  echo "Type,WatchName,Severity,RepoNameOfImpactedArtifact,ImpactedArtifacts,Vulnerability_Id,Issue_ID,Description" > ${CSV_FILE}


  for ((i = 0; i < TOTAL_PAGES; i++)); do
	OFFSET=$((i + 1))
      if [ "$i" -ne 0 ]; then
          GetXrayViolationsPage "${LIMIT}" "${OFFSET}" || return 1
      fi

      echo "  -> Processing page $((i + 1)) (Offset: ${OFFSET})"
      
      ARRAY_LENGTH=$(ProcessPageToCSV "${TEMP_JSON_FILE}" "${CSV_FILE}")
      
      VIOLATIONS_COUNT=$((VIOLATIONS_COUNT + ARRAY_LENGTH))
      
      if [ "$ARRAY_LENGTH" -eq 0 ] && [ "$i" -lt "$((TOTAL_PAGES - 1))" ]; then
          echo "Warning: API returned 0 violations unexpectedly. Stopping early."
          break
      fi

  done

  echo "Successfully fetched a total of ${VIOLATIONS_COUNT} violations."
  echo "CSV report created: ${CSV_FILE}"
}

Cleanup()
{
  # Remove temporary files
  rm -f "${TEMP_JSON_FILE}"
}

# --- Execution ---
ValidateWatch
GetXrayWatchViolations
Cleanup
