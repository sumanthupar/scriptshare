#!/bin/bash

ARTIFACTORY_URL="${1:?Error: ARTIFACTORY_URL is required. ex: https://mycompany.jfrog.io/artifactory}"
ACCESS_TOKEN="${2:?Error: ACCESS_TOKEN is required.}"
repostoindex="${3:?Error: REPO_LIST_FILE is required. ex: repos.txt}"

readonly MAX_REPOS=5
readonly POLL_INTERVAL=60   # seconds between each index status poll
readonly WAIT_FOR_COMPLETION=true  # true = wait until 100%; false = timeout after MAX_POLL_ATTEMPTS
readonly MAX_POLL_ATTEMPTS=2      # used only when WAIT_FOR_COMPLETION=false

indexreposfile=not_fully_indexed.csv
statusfile=redirectfile.csv

echo "reponame,completed,potential,percentage" > $statusfile

usage() {
  echo ""
  echo "Usage:"
  echo "  $0 <ARTIFACTORY_URL> <ACCESS_TOKEN> <REPO_LIST_FILE>"
  echo ""
  echo "Mandatory:"
  echo "  ARTIFACTORY_URL   Base Artifactory URL (example: https://mycompany.jfrog.io/artifactory)"
  echo "  ACCESS_TOKEN      JFrog Access Token"
  echo "  REPO_LIST_FILE    File containing repository names (one per line)"
  echo ""
  echo "Constants (edit in script to change behaviour):"
  echo "  MAX_REPOS              Maximum repos per run              (default: $MAX_REPOS)"
  echo "  POLL_INTERVAL          Seconds between status polls       (default: $POLL_INTERVAL)"
  echo "  WAIT_FOR_COMPLETION    Wait until 100% before next repo   (default: $WAIT_FOR_COMPLETION)"
  echo "  MAX_POLL_ATTEMPTS      Max polls before skipping repo     (default: $MAX_POLL_ATTEMPTS, used only if WAIT_FOR_COMPLETION=false)"
  echo ""
  echo "Notes:"
  echo "  • Repos with index < 100% will be indexed."
  echo "  • Indexing may take significant time depending on repo size and artifact count."
  echo "  • REPO_LIST_FILE must contain at most $MAX_REPOS repositories (MAX_REPOS constant)."
  echo "  • If WAIT_FOR_COMPLETION=true, the script waits indefinitely until each repo hits 100%."
  echo "  • If WAIT_FOR_COMPLETION=false, the script skips a repo after MAX_POLL_ATTEMPTS and moves on."
  echo ""
  echo "Examples:"
  echo "  $0 https://mycompany.jfrog.io/artifactory \$TOKEN repos.txt"
  echo "  $0 https://mycompany.jfrog.io/artifactory \$TOKEN repos_not_fully_indexed.csv"
  echo ""
  exit 1
}

GetIndexStatusOfRepos() {
  echo "\n\tFetching index status of repos..."

  for repo in $(cat "$repostoindex"); do
    echo "\tChecking: $repo"
    response=$(curl -s -XPOST \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Content-Type: application/json" \
      -d "{\"repo_key\":\"$repo\"}" \
      "$ARTIFACTORY_URL/xray/ui/unified/stats/indexStatus")
    completed=$(echo "$response" | jq -r '.completed // 0')
    potential=$(echo "$response" | jq -r '.potential // 0')
    if [[ "$potential" -gt 0 ]]; then
      percentage=$(awk "BEGIN { printf \"%d\", (($completed/$potential)*100) }")
    else
      percentage="0"
    fi
    echo "$repo,$completed,$potential,$percentage" >> "$statusfile"
  done
}

GetNotFullyIndexedRepos() {
  awk -F',' 'NR>1 && $4 != 100 { print $1 }' "$statusfile" > "$indexreposfile"

  count=$(wc -l < "$indexreposfile" | tr -d ' ')
  echo "\n\tFound $count repo(s) with index < 100% → saved to: $indexreposfile"
}

GetRepoIndexPercentage() {
  local repo="$1"
  local response completed potential percentage

  response=$(curl -s -XPOST \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"repo_key\":\"$repo\"}" \
    "$ARTIFACTORY_URL/xray/ui/unified/stats/indexStatus")

  completed=$(echo "$response" | jq -r '.completed // 0')
  potential=$(echo "$response" | jq -r '.potential // 0')

  if [[ "$potential" -gt 0 ]]; then
    percentage=$(awk "BEGIN { printf \"%d\", (($completed/$potential)*100) }")
  else
    percentage="0"
  fi

  echo "$percentage"
}

WaitForIndexCompletion() {
  local repo="$1"
  local attempt=1
  local percentage

  echo "\n\t  Waiting for $repo to reach 100%..."
  echo "\t  Mode: $([ "$WAIT_FOR_COMPLETION" == "true" ] && echo "wait indefinitely" || echo "timeout after $MAX_POLL_ATTEMPTS attempts")"

  while true; do
    percentage=$(GetRepoIndexPercentage "$repo")
    echo "\t  [Attempt $attempt] $repo — $percentage%"

    if [[ "$percentage" -eq 100 ]]; then
      echo "\t  ✓ $repo is fully indexed (100%). Moving to next repo."
      return 0
    fi

    if [[ "$WAIT_FOR_COMPLETION" == "false" && "$attempt" -ge "$MAX_POLL_ATTEMPTS" ]]; then
      echo "\t  ✗ Timeout: $repo reached $MAX_POLL_ATTEMPTS poll attempts at $percentage%. Skipping."
      return 1
    fi

    echo "\t  Sleeping $POLL_INTERVAL seconds before next poll..."
    sleep "$POLL_INTERVAL"
    attempt=$((attempt + 1))
  done
}

EnableIndexing() {
  if [[ ! -s "$indexreposfile" ]]; then
    echo "\n\tNo repos with index < 100%. Nothing to index."
    return
  fi

  while IFS= read -r repo; do
    [[ -z "$repo" ]] && continue

    echo "\n\t========================================="
    echo "\t  Indexing: $repo"
    echo "\t========================================="

    curl -s -XPOST \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Content-Type: application/json" \
      "$ARTIFACTORY_URL/xray/api/v1/index/repository/$repo"
    echo ""

    WaitForIndexCompletion "$repo"

  done < "$indexreposfile"
}

Action() {
  if [[ ! -f "$repostoindex" ]]; then
    echo "\n\tError: file '$repostoindex' not found."
    exit 1
  fi

  repo_count=$(wc -l < "$repostoindex" | tr -d ' ')
  if [[ "$repo_count" -gt "$MAX_REPOS" ]]; then
    echo "\n\tError: '$repostoindex' contains $repo_count repos, exceeding the limit of $MAX_REPOS (MAX_REPOS)."
    echo "\tSplit the file into smaller batches and re-run."
    exit 1
  fi

  echo "\n\tRepo count      : $repo_count / $MAX_REPOS"
  echo "\tWait for 100%   : $WAIT_FOR_COMPLETION"
  echo "\tPoll interval   : ${POLL_INTERVAL}s"
  [[ "$WAIT_FOR_COMPLETION" == "false" ]] && echo "\tMax poll attempts: $MAX_POLL_ATTEMPTS"

  GetIndexStatusOfRepos
  GetNotFullyIndexedRepos
  EnableIndexing
}

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  usage
fi

Action
