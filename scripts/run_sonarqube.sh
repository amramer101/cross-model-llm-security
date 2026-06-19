#!/bin/bash
# run_sonarqube.sh
#
# SonarQube must scan a "project" directory, not a single file via simple CLI
# flags the way semgrep/trivy/trufflehog do. This script treats each
# {model}/{language}/{condition} folder as one SonarQube project, scans it
# once, and pulls back the Security Hotspots + relevant issues via the
# SonarQube Web API, saving one JSON file per project.
#
# Prerequisites:
#   - SonarQube server running at http://localhost:9000 (already confirmed working)
#   - sonar-scanner CLI available (already confirmed working via Docker)
#   - A SonarQube user token exported as SONAR_TOKEN before running this script:
#       export SONAR_TOKEN=your_token_here
#
# Usage:
#   ./run_sonarqube.sh

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATED_DIR="$REPO_ROOT/generated_code"
RESULTS_DIR="$REPO_ROOT/scan_results"
SONAR_HOST="http://localhost:9000"

if [ -z "$SONAR_TOKEN" ]; then
  echo "ERROR: Please export SONAR_TOKEN before running this script."
  echo "  export SONAR_TOKEN=your_token_here"
  exit 1
fi

mkdir -p "$RESULTS_DIR"

for model_dir in "$GENERATED_DIR"/*/; do
  model=$(basename "$model_dir")
  for lang_dir in "$model_dir"*/; do
    lang=$(basename "$lang_dir")
    for cond_dir in "$lang_dir"*/; do
      cond=$(basename "$cond_dir")
      project_key="${model}_${lang}_${cond}"

      echo ">>> Scanning project: $project_key"

      sonar-scanner \
        -Dsonar.projectKey="$project_key" \
        -Dsonar.sources="$cond_dir" \
        -Dsonar.host.url="$SONAR_HOST" \
        -Dsonar.token="$SONAR_TOKEN" \
        -Dsonar.scm.disabled=true \
        || echo "WARNING: sonar-scanner failed for $project_key, continuing..."

      # Give the server a moment to process the analysis report
      sleep 5

      # Pull Security Hotspots for this project
      curl -s -u "$SONAR_TOKEN:" \
        "$SONAR_HOST/api/hotspots/search?projectKey=$project_key" \
        -o "$RESULTS_DIR/${project_key}_sonar_hotspots.json"

      # Pull general Issues (bugs/code smells/vulnerabilities) for this project
      curl -s -u "$SONAR_TOKEN:" \
        "$SONAR_HOST/api/issues/search?componentKeys=$project_key" \
        -o "$RESULTS_DIR/${project_key}_sonar_issues.json"

      echo "    Saved: ${project_key}_sonar_hotspots.json, ${project_key}_sonar_issues.json"
    done
  done
done

echo ""
echo "SonarQube scanning complete. Raw results in: $RESULTS_DIR"
echo "NOTE: Merge these into analysis/master_results.csv manually or extend"
echo "merge_sonar_results.py (see scripts/ directory) to automate this step."
