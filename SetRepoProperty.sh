#!/bin/bash

# Usage:
#   ./SetRepoProperty.sh <server-id> <repo-name> <property-key> <property-value>
# Example:
#   ./SetRepoProperty.sh my-jfrog libs-release-local team devops

SERVER_ID="${1:?ERROR: Please provide the configured JFrog CLI Server ID as the first argument.}"
REPO_NAME="${2:?ERROR: Please provide the repository name as the second argument.}"
PROP_KEY="${3:?ERROR: Please provide the property key as the third argument.}"
PROP_VALUE="${4:?ERROR: Please provide the property value as the fourth argument.}"

echo "Setting property '$PROP_KEY=$PROP_VALUE' on repository '$REPO_NAME' using server ID '$SERVER_ID'..."

# Use JFrog CLI to send the REST API request to set property on repository
jf rt curl -XPUT "/api/storage/${REPO_NAME}?properties=${PROP_KEY}=${PROP_VALUE}" --server-id="${SERVER_ID}"
if [ $? -eq 0 ]; then
  echo "Property successfully set on repository '$REPO_NAME'."
else
  echo "Failed to set property on repository '$REPO_NAME'." >&2
  exit 1
fi
