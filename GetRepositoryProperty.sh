#!/bin/bash

# Usage: ./SetRepoProperty.sh <server-id> <repo-name> <property-key> <property-value>
# Example: ./SetRepoProperty.sh my-jfrog libs-release-local team devops

SERVER_ID="${1:?ERROR: Please provide the configured JFrog CLI Server ID as the first argument.}"
REPO_NAME="${2:?ERROR: Please provide the repository name as the second argument.}"

echo "🔹 Get property on repository '$REPO_NAME' using server ID '$SERVER_ID'..."

# Use JFrog CLI to send the REST API request to set property on repository
jf rt curl -s -XGET "/api/storage/${REPO_NAME}?properties" | jq -r '.properties | to_entries[] | [.key, .value[0]] | @csv'
