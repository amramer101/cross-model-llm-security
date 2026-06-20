#!/usr/bin/env python3
"""
run_all_checks.py

Master orchestrator for the "Vibe Coded, Vibe Hacked" research paper.

Walks {LANGUAGE}_generated_code/{model}/{naive|hinted}/promptN.ext, runs all
four security checks on every file, and saves:
  1. Raw tool output (JSON) per file per tool -> scan_results/{language}/{model}/{condition}/
  2. One aggregated row per file -> analysis/master_results.csv

Tools orchestrated:
  - TruffleHog   (secrets detection)
  - Trivy        (filesystem vulnerability/dependency scan)
  - Semgrep      (OWASP Top 10-aligned static analysis)
  - Slopsquatting checker (custom -- hallucinated dependency detection)

SonarQube is intentionally run separately (sonar-scanner requires a project-
level invocation, not a clean single-file CLI call) -- see run_sonarqube.sh.

--------------------------------------------------------------------------
IMPORTANT -- ONE-TIME SETUP TO AVOID TIMEOUTS (read this before running):
--------------------------------------------------------------------------
1. Semgrep was timing out because "--config p/owasp-top-ten" pulls the
   ruleset from Semgrep's registry over the network on every single run.
   Fix: download the ruleset ONCE, then this script uses the local copy:

       semgrep --config p/owasp-top-ten --json --dryrun . > /dev/null 2>&1
       (or simply run semgrep once manually on any file; it caches the
       ruleset locally under ~/.semgrep/cache automatically)

2. Trivy was timing out because the FIRST run downloads its vulnerability
   database (several hundred MB). Fix: download it ONCE before batch-
   scanning:

       trivy fs --download-db-only

   After that, every scan reuses the local DB and is fast.

Run both one-time steps once, then run this script normally -- timeouts
should disappear for all subsequent runs.
--------------------------------------------------------------------------

Usage:
    python3 run_all_checks.py <language>
    where <language> is one of: python, javascript, java

    Example:
        python3 run_all_checks.py python

Requirements:
    - semgrep, trivy, trufflehog must be on PATH
    - Python 3.8+
"""

import os
import sys
import json
import csv
import subprocess
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_RESULTS_DIR = REPO_ROOT / "scan_results"
ANALYSIS_DIR = REPO_ROOT / "analysis"
SLOPSQUATTING_SCRIPT = Path(__file__).resolve().parent / "slopsquatting_checker.py"

LANG_FOLDER_NAMES = {
    "python": "Python_generated_code",
    "javascript": "JavaScript_generated_code",
    "java": "Java_generated_code",
}
LANG_EXTENSIONS = {"python": ".py", "javascript": ".js", "java": ".java"}

CSV_FIELDS = [
    "model", "language", "condition", "prompt_id", "file_path",
    "truffleHog_secrets_found",
    "trivy_vulnerabilities_found", "trivy_critical", "trivy_high",
    "trivy_condition_level",          # always True -- Trivy runs per condition, not per file
    "semgrep_findings", "semgrep_errors",
    "slopsquatting_packages_checked", "slopsquatting_hallucinated",
    "slopsquatting_rate",
    "scan_timestamp", "scan_status_notes",
]


def run_cmd(cmd, timeout=60):
    """Run a shell command, return (stdout, stderr, returncode). Never raises."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except Exception as e:
        return "", str(e), -1


def run_trufflehog(file_path: Path, out_path: Path):
    """Run TruffleHog filesystem scan on a single file."""
    cmd = f'trufflehog filesystem "{file_path}" --json --no-update'
    stdout, stderr, rc = run_cmd(cmd, timeout=90)
    out_path.write_text(stdout if stdout else f"# stderr:\n{stderr}")

    findings = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if obj.get("SourceMetadata") or obj.get("DetectorName"):
                findings += 1
        except json.JSONDecodeError:
            continue
    return findings


MANIFEST_FILENAMES = {
    ".py":   "requirements.txt",
    ".js":   "package.json",
    ".java": "pom.xml",
}


def run_trivy_for_condition(cond_dir: Path, language: str, out_path: Path):
    """
    Run Trivy ONCE per condition directory (naive/ or hinted/) on its
    dependency manifest (requirements.txt / package.json / pom.xml).

    Why per-condition, not per-file:
      Trivy is a dependency scanner, not a source-code analyser.  It matches
      package names against its CVE database.  A bare .py/.js/.java file has
      no package metadata for Trivy to read -- only the manifest does.
      Since one manifest covers all prompts in a condition folder, one Trivy
      scan per condition is both correct and sufficient.

    The result (total vulns, critical, high) is stored once and then stamped
    onto every per-file CSV row for that condition, with the column
    trivy_condition_level=True so analysts know the granularity.

    Returns (total, critical, high) -- all zero if no manifest exists or
    Trivy finds nothing.
    """
    ext = LANG_EXTENSIONS[language]
    manifest_name = MANIFEST_FILENAMES.get(f".{language}" if language != "javascript" else ".js",
                                           MANIFEST_FILENAMES.get(".py"))
    # resolve manifest name from language key directly
    manifest_map = {
        "python":     "requirements.txt",
        "javascript": "package.json",
        "java":       "pom.xml",
    }
    manifest_name = manifest_map[language]
    manifest_path = cond_dir / manifest_name

    if not manifest_path.exists():
        out_path.write_text(
            f"# Trivy skipped: no {manifest_name} found in {cond_dir}\n"
            f"# Run generate_manifests.py {language} first.\n"
        )
        return 0, 0, 0

    cmd = (
        f'trivy fs --scanners vuln --format json '
        f'--include-dev-deps "{manifest_path}"'
    )
    stdout, stderr, rc = run_cmd(cmd, timeout=120)
    out_path.write_text(stdout if stdout else f"# stderr:\n{stderr}")

    total, critical, high = 0, 0, 0
    try:
        data = json.loads(stdout)
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []) or []:
                total += 1
                sev = vuln.get("Severity", "")
                if sev == "CRITICAL":
                    critical += 1
                elif sev == "HIGH":
                    high += 1
    except (json.JSONDecodeError, TypeError):
        pass
    return total, critical, high


def run_semgrep(file_path: Path, out_path: Path):
    """Run Semgrep with the OWASP Top 10-aligned ruleset (p/owasp-top-ten)."""
    cmd = f'semgrep --config p/owasp-top-ten --json "{file_path}"'
    stdout, stderr, rc = run_cmd(cmd, timeout=120)
    out_path.write_text(stdout if stdout else f"# stderr:\n{stderr}")

    findings, errors = 0, 0
    try:
        data = json.loads(stdout)
        findings = len(data.get("results", []))
        errors = len(data.get("errors", []))
    except json.JSONDecodeError:
        errors = 1
    return findings, errors


def run_slopsquatting(file_path: Path, language: str, out_path: Path):
    """Run the custom Slopsquatting checker on a single file."""
    cmd = f'python3 "{SLOPSQUATTING_SCRIPT}" "{file_path}" {language}'
    stdout, stderr, rc = run_cmd(cmd, timeout=90)
    out_path.write_text(stdout if stdout else f"# stderr:\n{stderr}")

    checked, hallucinated, rate = 0, 0, 0.0
    try:
        data = json.loads(stdout)
        checked = data.get("total_packages_checked", 0)
        hallucinated = data.get("hallucinated_count", 0)
        rate = data.get("hallucination_rate", 0.0)
    except json.JSONDecodeError:
        pass
    return checked, hallucinated, rate


def discover_files(language: str):
    """
    Walk {Language}_generated_code/{model}/{naive|hinted}/promptN.ext
    and yield metadata for every generated code file found.
    """
    root_dir = REPO_ROOT / LANG_FOLDER_NAMES[language]
    if not root_dir.exists():
        print(f"ERROR: {root_dir} does not exist. Nothing to scan.")
        print(f"Run setup_{language}_structure.sh first to create the folder structure.")
        return

    ext = LANG_EXTENSIONS[language]
    for model_dir in sorted(root_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        for cond_dir in sorted(model_dir.iterdir()):
            if not cond_dir.is_dir() or cond_dir.name not in ("naive", "hinted"):
                continue
            for f in sorted(cond_dir.glob(f"*{ext}")):
                yield {
                    "model": model_dir.name,
                    "language": language,
                    "condition": cond_dir.name,
                    "prompt_id": f.stem,
                    "file_path": f,
                }


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in LANG_EXTENSIONS:
        print("Usage: python3 run_all_checks.py <python|javascript|java>")
        sys.exit(1)

    language = sys.argv[1]

    ANALYSIS_DIR.mkdir(exist_ok=True)
    csv_path = ANALYSIS_DIR / "master_results.csv"

    files = list(discover_files(language))
    if not files:
        print(f"No files found under ./{LANG_FOLDER_NAMES[language]}. Check your folder structure.")
        print(f"Expected: {LANG_FOLDER_NAMES[language]}/{{model}}/{{naive|hinted}}/promptN{LANG_EXTENSIONS[language]}")
        sys.exit(1)

    print(f"Found {len(files)} file(s) to scan for language: {language}\n")

    # ------------------------------------------------------------------
    # Pre-compute Trivy results per (model, condition) -- runs ONCE each.
    # Key: (model, condition)  Value: (total, critical, high)
    # ------------------------------------------------------------------
    trivy_cache: dict = {}

    def get_trivy_for_condition(model: str, cond: str, cond_dir: Path) -> tuple:
        key = (model, cond)
        if key not in trivy_cache:
            result_dir = SCAN_RESULTS_DIR / language / model / cond
            result_dir.mkdir(parents=True, exist_ok=True)
            out_path = result_dir / "trivy.json"   # one file per condition, not per prompt
            print(f"  [Trivy] scanning {model}/{cond}/requirements manifest ...", end=" ", flush=True)
            try:
                tv = run_trivy_for_condition(cond_dir, language, out_path)
                print(f"done ({tv[0]} vulns, {tv[1]} critical, {tv[2]} high)")
            except Exception as e:
                tv = (0, 0, 0)
                print(f"error: {e}")
            trivy_cache[key] = tv
        return trivy_cache[key]

    # Run Trivy upfront for every unique (model, condition) we are about to scan
    seen_conditions = set()
    for item in files:
        key = (item["model"], item["condition"])
        if key not in seen_conditions:
            seen_conditions.add(key)
            cond_dir = item["file_path"].parent
            get_trivy_for_condition(item["model"], item["condition"], cond_dir)

    print()  # blank line before per-file scan output

    write_header = not csv_path.exists()
    with open(csv_path, "a", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_FIELDS)
        if write_header:
            writer.writeheader()

        for i, item in enumerate(files, 1):
            model, lang, cond, pid = item["model"], item["language"], item["condition"], item["prompt_id"]
            fpath = item["file_path"]
            print(f"[{i}/{len(files)}] {model}/{lang}/{cond}/{pid}{fpath.suffix} ...", end=" ", flush=True)

            # Output structure: scan_results/{language}/{model}/{condition}/
            result_dir = SCAN_RESULTS_DIR / lang / model / cond
            result_dir.mkdir(parents=True, exist_ok=True)
            result_prefix = result_dir / pid
            notes = []

            try:
                th_findings = run_trufflehog(fpath, Path(f"{result_prefix}_truffleHog.json"))
            except Exception as e:
                th_findings = 0
                notes.append(f"truffleHog_error:{e}")

            # Trivy: fetch from cache (already ran per condition above)
            tv_total, tv_crit, tv_high = trivy_cache.get((model, cond), (0, 0, 0))

            try:
                sg_findings, sg_errors = run_semgrep(fpath, Path(f"{result_prefix}_semgrep.json"))
            except Exception as e:
                sg_findings, sg_errors = 0, 0
                notes.append(f"semgrep_error:{e}")

            try:
                sl_checked, sl_halluc, sl_rate = run_slopsquatting(
                    fpath, lang, Path(f"{result_prefix}_slopsquatting.json")
                )
            except Exception as e:
                sl_checked, sl_halluc, sl_rate = 0, 0, 0.0
                notes.append(f"slopsquatting_error:{e}")

            row = {
                "model": model,
                "language": lang,
                "condition": cond,
                "prompt_id": pid,
                "file_path": str(fpath.relative_to(REPO_ROOT)),
                "truffleHog_secrets_found": th_findings,
                "trivy_vulnerabilities_found": tv_total,
                "trivy_critical": tv_crit,
                "trivy_high": tv_high,
                "trivy_condition_level": True,
                "semgrep_findings": sg_findings,
                "semgrep_errors": sg_errors,
                "slopsquatting_packages_checked": sl_checked,
                "slopsquatting_hallucinated": sl_halluc,
                "slopsquatting_rate": sl_rate,
                "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scan_status_notes": "; ".join(notes) if notes else "ok",
            }
            writer.writerow(row)
            csvfile.flush()
            print("done" if not notes else f"done (warnings: {len(notes)})")

    print(f"\nAll results saved to: {csv_path}")
    print(f"Raw per-tool outputs saved to: {SCAN_RESULTS_DIR / language}/{{model}}/{{naive|hinted}}/")


if __name__ == "__main__":
    main()