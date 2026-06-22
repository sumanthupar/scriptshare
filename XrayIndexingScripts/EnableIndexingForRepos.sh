#!/bin/bash

xray_json=temp.json

# --- Configuration ---
ARTIFACTORY_URL="${1:?Error: ARTIFACTORY_URL is required. ex: https://mycompany.jfrog.io/artifactory}"
ACCESS_TOKEN="${2:?Error: ACCESS_TOKEN is required.}"
REPO_FILE="${3:?Error: REPO_FILE is required. ex: repos.txt}"

if [[ -z "$ARTIFACTORY_URL" || -z "$ACCESS_TOKEN" || -z "$REPO_FILE" ]]; then
  echo "Usage: $0 <artifactory-url> <access-token> <repo-file>"
  exit 1
fi


GetIndexedRepos()
{
  curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "$ARTIFACTORY_URL/xray/api/v1/binMgr/default/repos" | jq '.indexed_repos[] | .name' > indexed_repos.txt
}


IndexRepo()
{
  local repo_name="$1"

  if [ ! -f "$xray_json" ]; then
    echo '{"xrayIndex": true}' > "$xray_json"
  fi

  curl -s -X POST "$ARTIFACTORY_URL/artifactory/api/repositories/$repo_name" -H "Authorization: Bearer $ACCESS_TOKEN" -H "Content-Type: application/json" -T "$xray_json"
  echo ""
}


EnableIndexing()
{
  while IFS= read -r i; do
    [[ -z "$i" ]] && continue

    if grep -qw "$i" indexed_repos.txt; then
      echo "Repo $i indexing already enabled..Skipping"
    else
      echo "Enabling Xray indexing for repo: $i"
      IndexRepo "$i"
    fi

    echo ""
  done < "$REPO_FILE"
}


GetIndexedRepos
EnableIndexing
