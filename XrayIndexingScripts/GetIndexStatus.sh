#!/bin/bash

ARTIFACTORY_URL="${1:?Error: ARTIFACTORY_URL is required. ex: https://mycompany.jfrog.io/artifactory}"
ACCESS_TOKEN="${2:?Error: ACCESS_TOKEN is required.}"
repostoindex="$3"  # Optional: repo list file

indexstatusfile=repos_index_statusfile.csv
notfullyindexfile=repos_not_fully_indexed.csv

echo "Reponame,Completed,Potential,Percentage,Size" > $indexstatusfile

usage() {
  echo ""
  echo "Usage:"
  echo "  $0 <ARTIFACTORY_URL> <ACCESS_TOKEN> [REPO_LIST_FILE]"
  echo ""
  echo "Mandatory:"
  echo "  ARTIFACTORY_URL   Base Artifactory URL (example: https://mycompany.jfrog.io/artifactory)"
  echo "  ACCESS_TOKEN      JFrog Access Token"
  echo ""
  echo "Optional:"
  echo "  REPO_LIST_FILE    File containing repository names (one per line)"
  echo "                    If omitted, runs in discovery mode (all indexed repos)"
  echo ""
  echo "Output files:"
  echo "  $indexstatusfile     — index status of all repos"
  echo "  $notfullyindexfile   — repos with index < 100%"
  echo ""
  echo "Examples:"
  echo "  $0 https://mycompany.jfrog.io/artifactory \$TOKEN"
  echo "  $0 https://mycompany.jfrog.io/artifactory \$TOKEN repos.txt"
  echo ""
  exit 1
}

GetIndexedRepos() {
  curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
    "$ARTIFACTORY_URL/xray/api/v1/binMgr/default/repos" \
    | jq -r '.indexed_repos[].name' > indexed_repos.txt
}

GetStorageSummary() {
  curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
    "$ARTIFACTORY_URL/artifactory/api/storageinfo" \
    | jq '.repositoriesSummaryList' > storagesummary.json
  sleep 1
  sed -i 's/-cache//g' storagesummary.json
}

GetNonIndexedRepos() {
  nonindexedfile="repos_not_indexed.csv"
  echo " Finding repos not indexed in Xray at all..."

  xray_repos=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
    "$ARTIFACTORY_URL/xray/api/v1/binMgr/default/repos")

  echo "$xray_repos" | jq -r '.indexed_repos[].name' | sort -u > indexed_repos_sorted.txt

  echo "RepoName,PackageType,RepoType,FilesCount,Size" > "$nonindexedfile"

  jq -c '.[] | select(
    .repoKey != "TOTAL" and
    (.repoType == "LOCAL" or .repoType == "CACHE" or .repoType == "FEDERATED") and
    .packageType != "BuildInfo" and
    .packageType != "ReleaseBundles" and
    .packageType != "VCS" and
    .packageType != "TerraformBackend" and
    .packageType != "P2" and
    .packageType != "MachineLearning"
  ) | {repoKey, packageType, repoType, filesCount, usedSpace, usedSpaceInBytes}' storagesummary.json \
  | while IFS= read -r entry; do
      repoKey=$(echo "$entry"          | jq -r '.repoKey')
      packageType=$(echo "$entry"      | jq -r '.packageType')
      repoType=$(echo "$entry"         | jq -r '.repoType')
      filesCount=$(echo "$entry"       | jq -r '.filesCount')
      usedSpace=$(echo "$entry"        | jq -r '.usedSpace')
      usedSpaceInBytes=$(echo "$entry" | jq -r '.usedSpaceInBytes')

      if ! grep -qx "$repoKey" indexed_repos_sorted.txt; then
        echo "$usedSpaceInBytes,$repoKey,$packageType,$repoType,$filesCount,$usedSpace"
      fi
  done \
  | sort -t',' -k1 -rn \
  | awk -F',' 'OFS="," { $1=""; sub(/^,/, ""); print }' >> "$nonindexedfile"

  total=$(echo "$xray_repos"       | jq '(.indexed_repos | length) + (.non_indexed_repos | length)')
  indexed=$(echo "$xray_repos"     | jq '.indexed_repos | length')
  non_indexed=$(echo "$xray_repos" | jq '.non_indexed_repos | length')
  notindexed_with_content=$(awk 'NR>1' "$nonindexedfile" | wc -l | tr -d ' ')

  echo ""
  echo "\t========================================="
  echo "\t        Xray Indexing Summary"
  echo "\t========================================="
  echo "\t  Total repositories : $total"
  echo "\t  Indexed            : $indexed"
  echo "\t  Not Indexed        : $non_indexed"
  echo "\t-----------------------------------------"
  echo "\t  Details saved in   : $nonindexedfile"
  echo "\t========================================="
  echo ""
}

GetIndexStatusOfRepos() {
  repo_file="$1"
  echo " Fetching index status of repos. This may take a moment..."
  tmpfile="${indexstatusfile}.tmp"

  for repo in $(cat "$repo_file"); do
  repoType=$(jq -r --arg repo "$repo" \
  '.[] | select(.repoKey==$repo) | .repoType // ""' storagesummary.json)
if [[ "$repoType" == "CACHE" ]]; then
  xray_repo_key="${repo}-cache"
else
  xray_repo_key="$repo"
fi
    response=$(curl -s -XPOST \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{\"repo_key\":\"$xray_repo_key\"}" \
      "$ARTIFACTORY_URL/xray/ui/unified/stats/indexStatus")
    completed=$(echo "$response" | jq -r '.completed // 0')
    potential=$(echo "$response" | jq -r '.potential // 0')
    if [[ "$potential" -gt 0 ]]; then
      percentage=$(awk "BEGIN { printf \"%d\", (($completed/$potential)*100) }")
    else
      percentage="0"
    fi
    usedSpace=$(jq -r --arg repo "$repo" \
      '.[] | select(.repoKey==$repo) | .usedSpace // 0' storagesummary.json)
    echo "$repo,$completed,$potential,$percentage,$usedSpace" >> "$tmpfile"
  done

  echo "Reponame,Completed,Potential,Percentage,Size" > "$indexstatusfile"
  sort -t',' -rk4 -n "$tmpfile" >> "$indexstatusfile"
  rm -f "$tmpfile"

  echo "Index status saved to: $indexstatusfile"
}

GetNotFullyIndexedRepos() {
  tmpfile="${notfullyindexfile}.tmp"
  > "$tmpfile"
  awk -F',' 'NR>1 && $4 != 100 && !($2==0 && $3==0) { print }' "$indexstatusfile" >> "$tmpfile"

  echo "Reponame,Completed,Potential,Percentage,Size" > "$notfullyindexfile"
  sort -t',' -rk4 -n "$tmpfile" >> "$notfullyindexfile"
  rm -f "$tmpfile"

  count=$(awk 'NR>1' "$notfullyindexfile" | wc -l | tr -d ' ')
  echo "Found $count repo(s) with index < 100% → saved to: $notfullyindexfile"
}

Action() {
  GetStorageSummary
  if [[ -n "$repostoindex" && -f "$repostoindex" ]]; then
    echo " Repo list provided: $repostoindex"
    GetIndexStatusOfRepos "$repostoindex"
  else
    echo " No repo list provided. Running discovery mode."
    GetIndexedRepos
    GetNonIndexedRepos
    GetIndexStatusOfRepos "indexed_repos.txt"
  fi
  GetNotFullyIndexedRepos
}

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  usage
fi

Action
