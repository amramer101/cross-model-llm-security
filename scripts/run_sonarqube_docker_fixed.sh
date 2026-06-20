#!/bin/bash
# run_sonarqube_docker_fixed_v2.sh — Final Fixed Version

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATED_DIR="$REPO_ROOT/Python_generated_code"
RESULTS_DIR="$REPO_ROOT/scan_results/python"

SONAR_HOST="http://host.docker.internal:9000"
SONAR_TOKEN="${SONAR_TOKEN:-sqa_24e950c376a24f5f4b26d6ea37a96a586a001744}"

echo "=== SonarQube Docker Fixed v2 ==="
echo "Server: $SONAR_HOST"

# التحقق من السيرفر
if ! curl -s -u "$SONAR_TOKEN:" "http://localhost:9000/api/system/status" | grep -q "UP"; then
    echo "❌ SonarQube server مش شغال"
    exit 1
fi

echo "✅ SonarQube server جاهز."

for model_dir in "$GENERATED_DIR"/*/; do
    model=$(basename "$model_dir")
    echo ">>> Processing model: $model"

    for cond_dir in "$model_dir"*/; do
        cond=$(basename "$cond_dir")
        if [[ "$cond" != "naive" && "$cond" != "hinted" ]]; then
            continue
        fi

        project_key="vibe_coded_${model}_python_${cond}"
        echo "    → Scanning $model / $cond ..."

        # Container-internal path
        CONTAINER_SOURCES="/usr/src/Python_generated_code/${model}/${cond}"

        docker run --rm \
            --network host \
            -e SONAR_HOST_URL="$SONAR_HOST" \
            -e SONAR_TOKEN="$SONAR_TOKEN" \
            -v "$REPO_ROOT:/usr/src" \
            --add-host=host.docker.internal:host-gateway \
            sonarsource/sonar-scanner-cli \
            -Dsonar.projectKey="$project_key" \
            -Dsonar.host.url="$SONAR_HOST" \
            -Dsonar.sources="$CONTAINER_SOURCES" \
            -Dsonar.language=py \
            -Dsonar.sourceEncoding=UTF-8 \
            -Dsonar.scm.disabled=true \
            -Dsonar.exclusions="**/*.json,**/*_truffleHog.json,**/*_semgrep.json" \
            || echo "⚠️  Scan failed for $model/$cond (continuing...)"

        # حفظ النتايج
        output_dir="$RESULTS_DIR/$model/$cond"
        mkdir -p "$output_dir"

        curl -s -u "$SONAR_TOKEN:" \
            "http://localhost:9000/api/hotspots/search?projectKey=$project_key" \
            -o "$output_dir/${project_key}_hotspots.json" 2>/dev/null || true

        curl -s -u "$SONAR_TOKEN:" \
            "http://localhost:9000/api/issues/search?componentKeys=$project_key" \
            -o "$output_dir/${project_key}_issues.json" 2>/dev/null || true

        echo "    ✅ Done for $model/$cond"
    done
done

echo ""
echo "🎉 SonarQube analysis completed!"
echo "نتايج محفوظة في: scan_results/python/{model}/{naive|hinted}/"
