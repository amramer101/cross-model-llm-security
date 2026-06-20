#!/usr/bin/env python3
"""
generate_manifests.py

Pre-scan helper for the "Vibe Coded, Vibe Hacked" research paper.

Walks {LANGUAGE}_generated_code/{model}/{naive|hinted}/, collects every
third-party import across all prompt files in that condition folder, and
writes a dependency manifest file into the same folder.

  Python      -> requirements.txt   (one PINNED package per line)
  JavaScript  -> package.json       ({"dependencies": {pkg: "PINNED_VERSION"}})
  Java        -> pom-deps.txt       (one groupId stub per line, best-effort,
                                      audit trail only -- Trivy can't scan
                                      this format, see note below)

This lets Trivy find declared dependencies when scanning the condition
directory, since Trivy needs a manifest with RESOLVABLE VERSIONS -- it
cannot infer deps (or match CVEs) from raw source files or bare,
unversioned package names alone.

Run this ONCE before running run_all_checks.py:

    python3 generate_manifests.py python
    python3 generate_manifests.py javascript
    python3 generate_manifests.py java

The script is idempotent for the FILE PARSING step -- re-running it
overwrites existing manifests with a fresh parse of whatever prompt files
are currently present. Version resolution is NOT re-fetched on every
run: once a package's version is resolved, it is locked into
pypi_version_cache.json (Python) / npm_version_cache.json (JS) and reused
forever, so the same package always gets the same pinned version no
matter which model/condition it appears in, or how many weeks apart two
scans happen. This is intentional -- see Section "WHY VERSIONS ARE PINNED
THIS WAY" below.

--------------------------------------------------------------------------
IMPORTANT NOTE ON WHAT THIS FILE REPRESENTS
--------------------------------------------------------------------------
The generated manifest lists the THIRD-PARTY packages that the AI model
*imported* in its generated code -- not packages verified to exist.
Trivy then checks these (now pinned) versions against its CVE database.

This is intentionally different from the slopsquatting_checker, which
verifies existence on the registry. The two checks are complementary:
  - Trivy: "are any of these packages, at this version, vulnerable?"
  - Slopsquatting: "do these packages even exist?"

A package that fails to resolve a version here (not found on PyPI/npm)
is left UNPINNED with an "# UNRESOLVED" marker -- this is itself a signal
that should agree with the slopsquatting checker's findings for the same
file. If the two disagree, that's worth investigating.

--------------------------------------------------------------------------
WHY VERSIONS ARE PINNED THIS WAY (read before changing this logic)
--------------------------------------------------------------------------
The AI models being studied never specify a version in a Python import
statement -- there's no such syntax. So "what version did the model
intend" is not a real question; the model didn't intend any version.

The version pinned here is NOT meant to vary by model or by condition
(naive/hinted). The same package name must resolve to the SAME pinned
version everywhere in the dataset, regardless of which model or
condition it came from -- otherwise you'd be comparing models against
different CVE baselines for the same package, which would confound the
real research variable (model/language/condition) with an artificial one
(which day a particular file happened to get scanned).

The chosen approach: pin to the latest stable release on PyPI/npm at the
time a package is FIRST seen across the whole study, then freeze that in
a persisted cache file. This approximates "the version a developer would
get by default running `pip install <package>` / `npm install <package>`
around the time this code was generated" -- which is methodologically
honest, reproducible (the cache file IS the evidence), and avoids
cross-model version drift.

Commit the cache file(s) to the GitHub repo alongside the manifests --
together they document the exact dependency snapshot the whole CVE
analysis was run against, per Section 6 (Reproducibility & Evidence
Standard) of the project blueprint.

Usage:
    python3 generate_manifests.py <language>
    where <language> is one of: python, javascript, java
"""

import re
import sys
import json
import requests
from pathlib import Path

# ---------------------------------------------------------------------------
# Repo layout constants -- same as run_all_checks.py
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent

LANG_FOLDER_NAMES = {
    "python":     "Python_generated_code",
    "javascript": "JavaScript_generated_code",
    "java":       "Java_generated_code",
}

LANG_EXTENSIONS = {
    "python":     ".py",
    "javascript": ".js",
    "java":       ".java",
}

# ---------------------------------------------------------------------------
# Standard-library / built-in exclusion lists
# (kept in sync with slopsquatting_checker.py)
# ---------------------------------------------------------------------------
PYTHON_STDLIB = {
    "os", "sys", "re", "json", "time", "datetime", "math", "random", "string",
    "collections", "itertools", "functools", "typing", "dataclasses", "enum",
    "pathlib", "subprocess", "threading", "multiprocessing", "asyncio",
    "logging", "unittest", "io", "csv", "sqlite3", "hashlib", "hmac",
    "secrets", "base64", "uuid", "urllib", "http", "socket", "ssl",
    "email", "smtplib", "contextlib", "abc", "copy", "pickle", "shutil",
    "tempfile", "glob", "argparse", "configparser", "traceback", "inspect",
    "warnings", "weakref", "gc", "platform", "getpass", "textwrap",
    # a few extras that sometimes appear in auth/web code
    "struct", "array", "queue", "heapq", "bisect", "decimal", "fractions",
    "statistics", "cmath", "numbers", "operator", "pprint", "reprlib",
    "types", "importlib", "pkgutil", "zipimport", "builtins", "site",
    "atexit", "signal", "mmap", "ctypes", "select", "selectors", "errno",
    "fcntl", "termios", "tty", "pty", "pipes", "resource", "syslog",
    "curses", "readline", "rlcompleter", "xmlrpc", "html", "xml",
    "plistlib", "netrc", "ftplib", "poplib", "imaplib", "nntplib",
    "telnetlib", "ipaddress", "socketserver", "http", "cgi", "cgitb",
    "wsgiref", "token", "tokenize", "keyword", "ast", "symtable", "dis",
    "code", "codeop", "compileall", "py_compile", "zipfile", "tarfile",
    "lzma", "bz2", "gzip", "zlib", "binascii", "quopri", "uu",
    "codecs", "unicodedata", "difflib", "textwrap", "readline",
    "_thread", "concurrent",
}

NODE_BUILTINS = {
    "fs", "path", "http", "https", "crypto", "os", "url", "querystring",
    "util", "events", "stream", "child_process", "cluster", "net", "dns",
    "readline", "zlib", "assert", "buffer", "process", "timers",
    "module", "console", "global", "perf_hooks", "worker_threads",
    "v8", "vm", "tls", "dgram", "string_decoder", "punycode",
    "domain", "repl", "inspector", "async_hooks", "trace_events",
    "wasi", "diagnostics_channel", "node:fs", "node:path", "node:http",
    "node:https", "node:crypto", "node:os", "node:url", "node:util",
    "node:events", "node:stream", "node:child_process", "node:net",
    "node:dns", "node:readline", "node:zlib", "node:assert", "node:buffer",
    "node:timers", "node:module", "node:perf_hooks", "node:worker_threads",
    "node:v8", "node:vm", "node:tls", "node:dgram", "node:string_decoder",
    "node:repl", "node:inspector", "node:async_hooks",
}

JAVA_STDLIB_PREFIXES = ("java.", "javax.", "jakarta.", "sun.", "com.sun.")

# ---------------------------------------------------------------------------
# Version cache files -- one per ecosystem, persisted across runs
# ---------------------------------------------------------------------------
PYPI_CACHE_PATH = Path(__file__).resolve().parent / "pypi_version_cache.json"
NPM_CACHE_PATH = Path(__file__).resolve().parent / "npm_version_cache.json"


def load_cache(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            print(f"    WARNING: {path.name} is corrupted, starting fresh.")
    return {}


def save_cache(cache: dict, path: Path):
    path.write_text(json.dumps(cache, indent=2, sort_keys=True) + "\n")


def resolve_pypi_version(pkg: str, cache: dict) -> str | None:
    """
    Latest stable version on PyPI, resolved ONCE per package name and then
    frozen in cache for every subsequent run (regardless of model/condition
    or how much time passes between runs). Returns None if the package
    doesn't exist on PyPI at all (likely hallucinated -- cross-check
    against the slopsquatting checker's output for the same file).
    """
    if pkg in cache:
        return cache[pkg]
    try:
        r = requests.get(f"https://pypi.org/pypi/{pkg}/json", timeout=10)
        version = r.json()["info"]["version"] if r.status_code == 200 else None
    except Exception as e:
        print(f"    WARNING: PyPI lookup failed for '{pkg}': {e}")
        version = None
    cache[pkg] = version  # cache the miss too, so we don't re-query a
                          # nonexistent package on every future run
    return version


def resolve_npm_version(pkg: str, cache: dict) -> str | None:
    """Same idea as resolve_pypi_version, but against the npm registry."""
    if pkg in cache:
        return cache[pkg]
    try:
        r = requests.get(f"https://registry.npmjs.org/{pkg}/latest", timeout=10)
        version = r.json().get("version") if r.status_code == 200 else None
    except Exception as e:
        print(f"    WARNING: npm lookup failed for '{pkg}': {e}")
        version = None
    cache[pkg] = version
    return version


# ---------------------------------------------------------------------------
# Import extractors (same logic as slopsquatting_checker.py)
# ---------------------------------------------------------------------------

def extract_python_imports(code: str) -> set:
    """Return third-party top-level package names from Python source."""
    packages = set()
    for line in code.splitlines():
        line = line.strip()
        m1 = re.match(r"^import\s+([a-zA-Z0-9_\.]+)", line)
        m2 = re.match(r"^from\s+([a-zA-Z0-9_\.]+)\s+import", line)
        match = m1 or m2
        if match:
            pkg = match.group(1).split(".")[0]
            if pkg and pkg not in PYTHON_STDLIB:
                packages.add(pkg)
    return packages


def extract_js_imports(code: str) -> set:
    """Return third-party package names from JS require()/import statements."""
    packages = set()
    patterns = [
        r"require\(['\"]([^'\"]+)['\"]\)",
        r"import\s+.*?from\s+['\"]([^'\"]+)['\"]",
        r"import\s+['\"]([^'\"]+)['\"]",
    ]
    for pattern in patterns:
        for m in re.finditer(pattern, code):
            pkg = m.group(1)
            if pkg.startswith("."):
                continue
            # scoped packages: @org/name -> keep as-is
            if pkg.startswith("@"):
                pkg = "/".join(pkg.split("/")[:2])
            else:
                pkg = pkg.split("/")[0]
            # strip node: prefix if present
            pkg = pkg.replace("node:", "")
            if pkg and pkg not in NODE_BUILTINS:
                packages.add(pkg)
    return packages


def extract_java_imports(code: str) -> set:
    """Return non-stdlib import root stubs from Java source."""
    packages = set()
    for m in re.finditer(r"^import\s+(?:static\s+)?([a-zA-Z0-9_\.]+)\s*;",
                         code, re.MULTILINE):
        full = m.group(1)
        if not full.startswith(JAVA_STDLIB_PREFIXES):
            parts = full.split(".")
            packages.add(".".join(parts[:3]))
    return packages


EXTRACTORS = {
    "python":     extract_python_imports,
    "javascript": extract_js_imports,
    "java":       extract_java_imports,
}

# ---------------------------------------------------------------------------
# Manifest writers -- now version-aware
# ---------------------------------------------------------------------------

def write_python_manifest(packages: set, out_path: Path, version_cache: dict) -> list:
    """
    Write requirements.txt with PINNED versions (package==X.Y.Z) so Trivy
    can actually match against its CVE database. Packages that don't
    resolve on PyPI are written as a commented-out UNRESOLVED line --
    Trivy will skip them (correctly -- there's no real package to scan),
    but they stay in the file as an audit trail.

    Returns the list of unresolved package names.
    """
    lines = []
    unresolved = []
    for pkg in sorted(packages):
        version = resolve_pypi_version(pkg, version_cache)
        if version:
            lines.append(f"{pkg}=={version}")
        else:
            lines.append(f"# UNRESOLVED (not found on PyPI): {pkg}")
            unresolved.append(pkg)

    out_path.write_text(
        "# Auto-generated by generate_manifests.py\n"
        "# Third-party imports found across all prompts in this condition folder.\n"
        "# Versions pinned to latest PyPI release as of first resolution\n"
        "# (frozen in scripts/pypi_version_cache.json -- same package always\n"
        "# gets the same version everywhere in the dataset).\n\n"
        + "\n".join(lines)
        + "\n"
    )
    return unresolved


def write_js_manifest(packages: set, out_path: Path, version_cache: dict) -> list:
    """Write a package.json with PINNED versions so Trivy picks up real npm deps."""
    deps = {}
    unresolved = []
    for pkg in sorted(packages):
        version = resolve_npm_version(pkg, version_cache)
        if version:
            deps[pkg] = version
        else:
            deps[pkg] = "UNRESOLVED"
            unresolved.append(pkg)

    data = {
        "_note": "Auto-generated by generate_manifests.py. Versions pinned "
                 "to latest npm release as of first resolution (frozen in "
                 "scripts/npm_version_cache.json).",
        "name": "vibe-coded-generated",
        "version": "0.0.1",
        "dependencies": deps,
    }
    out_path.write_text(json.dumps(data, indent=2) + "\n")
    return unresolved


def write_java_manifest(packages: set, out_path: Path):
    """
    Write pom-deps.txt -- a plain list of import roots.
    Trivy's Maven support requires a full pom.xml with proper groupId/artifactId,
    which can't be reliably inferred from import statements alone, so this
    is NOT version-pinned and NOT scanned by Trivy directly.
    This file serves as a human-readable audit trail; the slopsquatting checker
    handles Java registry existence checks separately.
    """
    out_path.write_text(
        "# Auto-generated by generate_manifests.py\n"
        "# Java import roots found across all prompts in this condition folder.\n"
        "# NOTE: Trivy requires a proper pom.xml for Maven scanning.\n"
        "# This file is an audit trail only -- use slopsquatting_checker for\n"
        "# Java dependency existence checks.\n\n"
        + "\n".join(sorted(packages))
        + "\n"
    )


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def process_condition_dir(cond_dir: Path, language: str, version_cache: dict) -> tuple:
    """
    Parse all prompt files in one condition directory (e.g. deepseek/naive/),
    collect unique third-party packages, write the (version-pinned) manifest,
    and return (manifest_path, package_count, file_count, unresolved_list).
    """
    ext = LANG_EXTENSIONS[language]
    extractor = EXTRACTORS[language]

    all_packages = set()
    prompt_files = sorted(cond_dir.glob(f"*{ext}"))

    for f in prompt_files:
        try:
            code = f.read_text(encoding="utf-8", errors="ignore")
            all_packages |= extractor(code)
        except Exception as e:
            print(f"    WARNING: could not read {f.name}: {e}")

    unresolved = []

    if language == "python":
        manifest_path = cond_dir / "requirements.txt"
        if all_packages:
            unresolved = write_python_manifest(all_packages, manifest_path, version_cache)
        else:
            manifest_path.write_text(
                "# Auto-generated by generate_manifests.py\n"
                "# No third-party imports found in this condition folder.\n"
            )
    elif language == "javascript":
        manifest_path = cond_dir / "package.json"
        if all_packages:
            unresolved = write_js_manifest(all_packages, manifest_path, version_cache)
        else:
            manifest_path.write_text(json.dumps({
                "_note": "Auto-generated by generate_manifests.py -- no deps found.",
                "name": "vibe-coded-generated", "version": "0.0.1",
                "dependencies": {},
            }, indent=2) + "\n")
    else:  # java
        manifest_path = cond_dir / "pom-deps.txt"
        if all_packages:
            write_java_manifest(all_packages, manifest_path)
        else:
            manifest_path.write_text(
                "# Auto-generated by generate_manifests.py\n"
                "# No third-party imports found in this condition folder.\n"
            )

    return manifest_path, len(all_packages), len(prompt_files), unresolved


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in LANG_EXTENSIONS:
        print("Usage: python3 generate_manifests.py <python|javascript|java>")
        sys.exit(1)

    language = sys.argv[1]
    lang_root = REPO_ROOT / LANG_FOLDER_NAMES[language]
    manifest_name = {"python": "requirements.txt", "javascript": "package.json",
                      "java": "pom-deps.txt"}[language]

    if not lang_root.exists():
        print(f"ERROR: {lang_root} does not exist.")
        print(f"Run the setup script first to create the folder structure.")
        sys.exit(1)

    # Load the right persisted version cache for this ecosystem
    version_cache = {}
    cache_path = None
    if language == "python":
        cache_path = PYPI_CACHE_PATH
        version_cache = load_cache(cache_path)
    elif language == "javascript":
        cache_path = NPM_CACHE_PATH
        version_cache = load_cache(cache_path)

    print(f"Generating {manifest_name} manifests for language: {language}")
    print(f"Root: {lang_root}")
    if cache_path:
        print(f"Version cache: {cache_path} ({len(version_cache)} package(s) already resolved)\n")
    else:
        print()

    total_manifests = 0
    all_unresolved = set()

    for model_dir in sorted(lang_root.iterdir()):
        if not model_dir.is_dir():
            continue
        for cond_dir in sorted(model_dir.iterdir()):
            if not cond_dir.is_dir() or cond_dir.name not in ("naive", "hinted"):
                continue

            manifest_path, pkg_count, file_count, unresolved = process_condition_dir(
                cond_dir, language, version_cache
            )
            total_manifests += 1
            all_unresolved.update(unresolved)
            unresolved_note = f", {len(unresolved)} UNRESOLVED" if unresolved else ""
            print(
                f"  [{model_dir.name}/{cond_dir.name}] "
                f"{file_count} prompt(s) -> "
                f"{pkg_count} unique package(s){unresolved_note} -> "
                f"{manifest_path.name}"
            )

    # Persist the cache so future runs (any model, any condition, any day)
    # reuse the same resolved versions instead of re-querying the registry.
    if cache_path:
        save_cache(version_cache, cache_path)
        print(f"\nVersion cache saved: {cache_path} ({len(version_cache)} package(s) total)")

    print(f"\nDone. {total_manifests} manifest(s) written.")
    if all_unresolved:
        print(
            f"\n{len(all_unresolved)} package(s) never resolved on the registry "
            f"(cross-check against slopsquatting_checker output for these files):"
        )
        for pkg in sorted(all_unresolved):
            print(f"  - {pkg}")
    print(
        f"\nNow run:  python3 scripts/run_all_checks.py {language}\n"
        f"Trivy will pick up the pinned {manifest_name} in each condition folder."
    )


if __name__ == "__main__":
    main()