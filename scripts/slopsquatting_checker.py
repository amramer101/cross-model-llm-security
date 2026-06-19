#!/usr/bin/env python3
"""
slopsquatting_checker.py

Custom novelty check for the "Vibe Coded, Vibe Hacked" research paper.

For a given source file, extracts all imported package/module names and
verifies each one actually exists on the relevant official package registry
(PyPI for Python, npm for JavaScript, Maven Central for Java).

A package name that returns "not found" is logged as a HALLUCINATED
DEPENDENCY -- a direct, measurable proxy for slopsquatting attack surface.

Usage:
    python3 slopsquatting_checker.py <file_path> <language: python|javascript|java>

Output:
    JSON written to stdout with the list of checked packages and their status.
"""

import sys
import re
import json
import time
import urllib.request
import urllib.error

# Standard library modules that should NEVER be flagged (Python)
PYTHON_STDLIB = {
    "os", "sys", "re", "json", "time", "datetime", "math", "random", "string",
    "collections", "itertools", "functools", "typing", "dataclasses", "enum",
    "pathlib", "subprocess", "threading", "multiprocessing", "asyncio",
    "logging", "unittest", "io", "csv", "sqlite3", "hashlib", "hmac",
    "secrets", "base64", "uuid", "urllib", "http", "socket", "ssl",
    "email", "smtplib", "contextlib", "abc", "copy", "pickle", "shutil",
    "tempfile", "glob", "argparse", "configparser", "traceback", "inspect",
    "warnings", "weakref", "gc", "platform", "getpass", "textwrap"
}

# Node.js built-in modules that should never be flagged (JavaScript)
NODE_BUILTINS = {
    "fs", "path", "http", "https", "crypto", "os", "url", "querystring",
    "util", "events", "stream", "child_process", "cluster", "net", "dns",
    "readline", "zlib", "assert", "buffer", "process", "timers"
}

# Java packages from the standard JDK that should never be flagged
JAVA_STDLIB_PREFIXES = (
    "java.", "javax.", "jakarta."
)


def extract_python_imports(code: str):
    """Extract top-level package names from Python import statements."""
    packages = set()
    for line in code.splitlines():
        line = line.strip()
        m1 = re.match(r"^import\s+([a-zA-Z0-9_\.]+)", line)
        m2 = re.match(r"^from\s+([a-zA-Z0-9_\.]+)\s+import", line)
        if m1:
            packages.add(m1.group(1).split(".")[0])
        elif m2:
            packages.add(m2.group(1).split(".")[0])
    return {p for p in packages if p not in PYTHON_STDLIB}


def extract_js_imports(code: str):
    """Extract package names from JS require()/import statements."""
    packages = set()
    for m in re.finditer(r"require\(['\"]([^'\"]+)['\"]\)", code):
        pkg = m.group(1)
        if not pkg.startswith("."):
            packages.add(pkg.split("/")[0] if not pkg.startswith("@") else "/".join(pkg.split("/")[:2]))
    for m in re.finditer(r"import\s+.*?from\s+['\"]([^'\"]+)['\"]", code):
        pkg = m.group(1)
        if not pkg.startswith("."):
            packages.add(pkg.split("/")[0] if not pkg.startswith("@") else "/".join(pkg.split("/")[:2]))
    return {p for p in packages if p not in NODE_BUILTINS}


def extract_java_imports(code: str):
    """Extract top-level group:artifact-like roots from Java import statements."""
    packages = set()
    for m in re.finditer(r"^import\s+(?:static\s+)?([a-zA-Z0-9_\.]+)\s*;", code, re.MULTILINE):
        full = m.group(1)
        if not full.startswith(JAVA_STDLIB_PREFIXES):
            # Use the first 2-3 segments as a reasonable "library" identifier
            parts = full.split(".")
            packages.add(".".join(parts[:3]))
    return packages


def check_pypi(package: str) -> bool:
    """
    Return True if package exists on PyPI, False if confirmed not found (404),
    or None if the check was inconclusive (network error, rate limit, proxy
    block, etc). None must NEVER be treated as "exists" by the caller.
    """
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "slopsquatting-checker/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        # Any other HTTP error (403, 429, 500, etc.) is inconclusive -- NOT proof
        # the package exists. Treating it as "exists" would silently hide real
        # hallucinations whenever the registry blocks/rate-limits the request.
        return None
    except Exception:
        return None  # Network/DNS/timeout error -- inconclusive, not "exists"


def check_npm(package: str) -> bool:
    """
    Return True if package exists on npm, False if confirmed not found (404),
    or None if the check was inconclusive. None must NEVER be treated as
    "exists" by the caller.
    """
    url = f"https://registry.npmjs.org/{package}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "slopsquatting-checker/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        return None
    except Exception:
        return None


def check_maven(group_artifact: str) -> bool:
    """
    Best-effort check against Maven Central's search API using the
    first two dotted segments as a guess for the groupId.
    Java import roots don't map 1:1 to Maven coordinates, so this is
    treated as a heuristic, lower-confidence signal -- documented as a
    limitation in the paper.
    """
    query = group_artifact.replace(".", "+")
    url = f"https://search.maven.org/solrsearch/select?q=g:{query}&rows=1&wt=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "slopsquatting-checker/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
            return data.get("response", {}).get("numFound", 0) > 0
    except Exception:
        return None


def run_check(file_path: str, language: str):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()

    if language == "python":
        packages = extract_python_imports(code)
        checker = check_pypi
    elif language == "javascript":
        packages = extract_js_imports(code)
        checker = check_npm
    elif language == "java":
        packages = extract_java_imports(code)
        checker = check_maven
    else:
        raise ValueError("language must be one of: python, javascript, java")

    results = []
    for pkg in sorted(packages):
        exists = checker(pkg)
        status = "exists" if exists is True else ("hallucinated" if exists is False else "unknown")
        results.append({"package": pkg, "status": status})
        time.sleep(0.3)  # be polite to the registries

    hallucinated = [r for r in results if r["status"] == "hallucinated"]

    output = {
        "file": file_path,
        "language": language,
        "total_packages_checked": len(results),
        "hallucinated_count": len(hallucinated),
        "hallucination_rate": round(len(hallucinated) / len(results), 3) if results else 0.0,
        "details": results,
    }
    return output


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(json.dumps({"error": "Usage: slopsquatting_checker.py <file> <python|javascript|java>"}))
        sys.exit(1)

    file_path, language = sys.argv[1], sys.argv[2]
    result = run_check(file_path, language)
    print(json.dumps(result, indent=2))
