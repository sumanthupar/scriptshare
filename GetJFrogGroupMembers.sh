#!/bin/bash

# Usage:
#   ./GetJFrogGroupMembers.sh <jfrog-url> <access-token> <group-name>
#
# Example:
#   ./GetJFrogGroupMembers.sh https://psblr.jfrog.io abcdef123456789 testgroup
#

JFROG_URL="${1?ERROR: Please provide the JFrog URL as the first argument.}"  # default if not provided
ACCESS_TOKEN="${2:?ERROR: Please provide the JFrog Access token as the second argument.}"
GROUP_NAME="${3:?ERROR: Please provide the JFrog group name as the third argument.}"

echo "Fetching members of group '${GROUP_NAME}' from '${JFROG_URL}'..."

curl -s -H "Authorization: Bearer ${ACCESS_TOKEN}" "${JFROG_URL}/access/api/v2/groups/${GROUP_NAME}" | jq -r '.members| @csv' > $GROUP_NAME_users.csv
if [ $? -eq 0 ]; then
  echo "The members for group '${GROUP_NAME}' are below"
  cat $GROUP_NAME_users.csv
else
  echo "Failed to fetch members for group '${GROUP_NAME}'."
  exit 1
fi
