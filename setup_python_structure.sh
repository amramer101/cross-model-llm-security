#!/bin/bash
# =============================================================================
# setup_python_structure.sh
#
# Creates the full folder structure for storing Python generated code samples
# across all 5 models, both conditions (naive/hinted), and all 8 prompts.
#
# Structure created:
#   Python_generated_code/
#     deepseek/
#       naive/
#         prompt1.py ... prompt8.py
#       hinted/
#         prompt1.py ... prompt8.py
#     gpt4o/
#       naive/ ...
#       hinted/ ...
#     claude_sonnet/
#       ...
#     gemini/
#       ...
#     llama/
#       ...
#
# Each file is pre-filled with a header comment stating:
#   - the model
#   - the condition (naive/hinted)
#   - the prompt number
#   - today's date (date only, no time)
#
# Usage:
#   chmod +x setup_python_structure.sh
#   ./setup_python_structure.sh
#
# Safe to re-run: existing files are NOT overwritten, so you won't lose
# code you've already pasted in. Delete a specific file first if you want
# it regenerated with a fresh header.
# =============================================================================

set -e

# ---- Configuration ----------------------------------------------------------
ROOT_DIR="Python_generated_code"
MODELS=("deepseek" "gpt4o" "claude_sonnet" "gemini" "llama")
CONDITIONS=("naive" "hinted")
NUM_PROMPTS=8
TODAY=$(date +"%Y-%m-%d")

# ---- Build the structure -----------------------------------------------------
mkdir -p "$ROOT_DIR"

for model in "${MODELS[@]}"; do
  for condition in "${CONDITIONS[@]}"; do
    target_dir="$ROOT_DIR/$model/$condition"
    mkdir -p "$target_dir"

    for i in $(seq 1 $NUM_PROMPTS); do
      file_path="$target_dir/prompt${i}.py"

      if [ -f "$file_path" ]; then
        echo "SKIP (already exists): $file_path"
        continue
      fi

      cat > "$file_path" << EOF
# =============================================
# Generated Code - Prompt ${i} (${condition})
# Model: ${model}
# Language: python
# Date: ${TODAY}
# =============================================

# TODO: Paste the generated code from the model here
EOF
      echo "Created: $file_path"
    done
  done
done

echo ""
echo "Done. Structure created under: $ROOT_DIR/"
echo "Total files: $(( ${#MODELS[@]} * ${#CONDITIONS[@]} * NUM_PROMPTS ))"
