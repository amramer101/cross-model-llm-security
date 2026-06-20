#!/usr/bin/env python3
"""
generate_manifests.py

Pre-scan helper for the "Vibe Coded, Vibe Hacked" research paper.

Walks {LANGUAGE}_generated_code/{model}/{naive|hinted}/, collects every
third-party import across all prompt files in that condition folder, and
writes a dependency manifest file into the same folder.

  Python      -> requirements.txt   (one package per line)
  JavaScript  -> package.json       (minimal {"dependencies": {...}})
  Java        -> pom-deps.txt       (one groupId stub per line, best-effort)

This lets Trivy find declared dependencies when scanning the condition
directory, since Trivy needs a manifest -- it cannot infer deps from raw
source files alone.

Run this ONCE before running run_all_checks.py:

    python3 generate_manifests.py python
    python3 generate_manifests.py javascript
    python3 generate_manifests.py java

The script is idempotent -- re-running it overwrites existing manifests
with a fresh parse of whatever prompt files are currently present.

--------------------------------------------------------------------------
IMPORTANT NOTE ON WHAT THIS FILE REPRESENTS
--------------------------------------------------------------------------
The generated manifest lists the THIRD-PARTY packages that the AI model
*imported* in its generated code -- not packages verified to exist.
Trivy then checks these against its CVE database.

This is intentionally different from the slopsquatting_checker, which
verifies existence on the registry. The two checks are complementary:
  - Trivy: "are any of these packages vulnerable?"
  - Slopsquatting: "do these packages even exist?"

--------------------------------------------------------------------------

Usage:
    python3 generate_manifests.py <language>
    where <language> is one of: python, javascript, java
"""

import re
import sys
import json
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
# Manifest writers
# ---------------------------------------------------------------------------

def write_python_manifest(packages: set, out_path: Path):
    """Write requirements.txt with one package per line (no version pins)."""
    out_path.write_text(
        "# Auto-generated by generate_manifests.py\n"
        "# Third-party imports found across all prompts in this condition folder.\n"
        "# No version pins -- Trivy will scan for any known CVE per package.\n\n"
        + "\n".join(sorted(packages))
        + "\n"
    )


def write_js_manifest(packages: set, out_path: Path):
    """Write a minimal package.json so Trivy picks up npm deps."""
    data = {
        "_note": "Auto-generated by generate_manifests.py",
        "name": "vibe-coded-generated",
        "version": "0.0.1",
        "dependencies": {pkg: "*" for pkg in sorted(packages)},
    }
    out_path.write_text(json.dumps(data, indent=2) + "\n")


def write_java_manifest(packages: set, out_path: Path):
    """
    Write pom-deps.txt -- a plain list of import roots.
    Trivy's Maven support requires a full pom.xml with proper groupId/artifactId,
    which can't be reliably inferred from import statements alone.
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


MANIFEST_WRITERS = {
    "python":     ("requirements.txt", write_python_manifest),
    "javascript": ("package.json",     write_js_manifest),
    "java":       ("pom-deps.txt",     write_java_manifest),
}

# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def process_condition_dir(cond_dir: Path, language: str) -> tuple:
    """
    Parse all prompt files in one condition directory (e.g. deepseek/naive/),
    collect unique third-party packages, write the manifest, and return
    (manifest_path, package_count, file_count).
    """
    ext = LANG_EXTENSIONS[language]
    extractor = EXTRACTORS[language]
    manifest_name, writer = MANIFEST_WRITERS[language]

    all_packages = set()
    prompt_files = sorted(cond_dir.glob(f"*{ext}"))

    for f in prompt_files:
        try:
            code = f.read_text(encoding="utf-8", errors="ignore")
            all_packages |= extractor(code)
        except Exception as e:
            print(f"    WARNING: could not read {f.name}: {e}")

    manifest_path = cond_dir / manifest_name

    if all_packages:
        writer(all_packages, manifest_path)
    else:
        # Write an empty manifest so Trivy doesn't error on a missing file
        manifest_path.write_text(
            f"# Auto-generated by generate_manifests.py\n"
            f"# No third-party imports found in this condition folder.\n"
        )

    return manifest_path, len(all_packages), len(prompt_files)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in LANG_EXTENSIONS:
        print("Usage: python3 generate_manifests.py <python|javascript|java>")
        sys.exit(1)

    language = sys.argv[1]
    lang_root = REPO_ROOT / LANG_FOLDER_NAMES[language]
    manifest_name = MANIFEST_WRITERS[language][0]

    if not lang_root.exists():
        print(f"ERROR: {lang_root} does not exist.")
        print(f"Run the setup script first to create the folder structure.")
        sys.exit(1)

    print(f"Generating {manifest_name} manifests for language: {language}")
    print(f"Root: {lang_root}\n")

    total_manifests = 0

    for model_dir in sorted(lang_root.iterdir()):
        if not model_dir.is_dir():
            continue
        for cond_dir in sorted(model_dir.iterdir()):
            if not cond_dir.is_dir() or cond_dir.name not in ("naive", "hinted"):
                continue

            manifest_path, pkg_count, file_count = process_condition_dir(
                cond_dir, language
            )
            total_manifests += 1
            print(
                f"  [{model_dir.name}/{cond_dir.name}] "
                f"{file_count} prompt(s) -> "
                f"{pkg_count} unique package(s) -> "
                f"{manifest_path.name}"
            )

    print(f"\nDone. {total_manifests} manifest(s) written.")
    print(
        f"Now run:  python3 scripts/run_all_checks.py {language}\n"
        f"Trivy will pick up the generated {manifest_name} in each condition folder."
    )


if __name__ == "__main__":
    main()
