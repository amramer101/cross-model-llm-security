# Scripts — Automated Security Scanning Pipeline

This folder contains the automation that runs all four security checks across the entire dataset, instead of running each tool by hand on each of the 504 files.

---

## What Each Script Does

| Script | Purpose |
|---|---|
| `slopsquatting_checker.py` | Custom novelty check — extracts imports from a code file and verifies each package actually exists on PyPI / npm / Maven Central |
| `run_all_checks.py` | **Main script.** Walks the entire `generated_code/` folder, runs TruffleHog + Trivy + Semgrep + the Slopsquatting checker on every file, saves raw output per file, and appends one row per file to `analysis/master_results.csv` |
| `run_sonarqube.sh` | Separate script for SonarQube, because it scans at the project/folder level rather than per-file |

---

## One-Time Setup

Confirm all tools are on PATH (you already have these installed):

```bash
semgrep --version
trivy --version
trufflehog --version
python3 --version
```

---

## Step 1 — Organize Your Generated Code

Before running anything, your files must already follow this exact structure:

```
generated_code/
  deepseek/
    python/
      naive/
        P01.py
        P02.py
        ...
      hinted/
        P01.py
        P02.py
        ...
    javascript/
      naive/
      hinted/
    java/
      naive/
      hinted/
  gpt4o/
    python/
      ...
  claude_sonnet/
    ...
```

The folder names `naive` and `hinted` must be exactly that (lowercase). File names must be `P01` through `P14` with the correct extension (`.py`, `.js`, `.java`).

---

## Step 2 — Run the Main Pipeline

From the repository root (`bravo6-research/`):

```bash
python3 scripts/run_all_checks.py
```

This will:
1. Discover every file under `generated_code/`
2. Run TruffleHog, Trivy, Semgrep, and the Slopsquatting checker on each one
3. Save raw tool output to `scan_results/{model}_{language}_{condition}_{prompt}_{tool}.json`
4. Append a summary row to `analysis/master_results.csv`

**You can re-run it safely** — it appends to the CSV, so if you add more model folders later (e.g., after testing GPT-4o), just run the script again and only the new files get processed (note: it does NOT auto-skip already-scanned files in this version, so for incremental runs either delete old CSV rows manually or scan into a fresh CSV per session and merge later).

The script prints live progress, e.g.:
```
[1/28] deepseek/python/naive/P01.py ... done
[2/28] deepseek/python/naive/P02.py ... done
```

---

## Step 3 — Run SonarQube Separately

```bash
export SONAR_TOKEN=your_token_here
chmod +x scripts/run_sonarqube.sh
./scripts/run_sonarqube.sh
```

This treats each `{model}/{language}/{condition}` folder as one SonarQube "project" (since SonarQube doesn't scan single files cleanly), and saves the Security Hotspots + Issues as JSON per project into `scan_results/`.

---

## Step 4 — Check Your Results

Open `analysis/master_results.csv` in any spreadsheet tool, or load it with pandas:

```python
import pandas as pd
df = pd.read_csv("analysis/master_results.csv")
df.groupby("model")[["truffleHog_secrets_found", "slopsquatting_rate"]].mean()
```

---

## Important Notes

- **Semgrep ruleset:** the script uses `p/owasp-top-ten` specifically (not the full default ruleset), to keep its scope cleanly separated from SonarQube and avoid double-counting the same vulnerability class, as agreed in the paper's methodology.
- **Slopsquatting checker network calls:** this script makes live requests to PyPI/npm/Maven Central with a small delay between each (`time.sleep(0.3)`) to avoid hammering the registries. For 504 files with several imports each, this step will be the slowest part of the pipeline — expect it to take a while. Let it run in the background.
- **Timeouts:** each tool has a timeout (45–90 seconds) so one stuck file can't freeze the whole run. If a tool times out on a file, it's logged in the `scan_status_notes` column instead of crashing the script.
- **Raw evidence:** every single scan's raw JSON output is preserved in `scan_results/` — this is what makes the paper's numbers verifiable, per the Reproducibility Statement in the Blueprint.

---

## Recommended First Run

Before scanning all 504 files, run the pipeline on just the DeepSeek/Python pilot batch (28 files) to confirm everything works end-to-end:

```bash
python3 scripts/run_all_checks.py
```

(If only `generated_code/deepseek/python/` exists so far, it will naturally only scan those files.)

Check `analysis/master_results.csv` — if the numbers look reasonable (not all zeros, no constant errors in `scan_status_notes`), you're clear to keep adding models and let it run on the full dataset.
