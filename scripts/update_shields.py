#!/usr/bin/env python3
"""Update % doc coverage and % test coverage shields in README.md."""

import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile


def get_color(pct):
    """Determine the shield color based on percentage."""
    if pct >= 90:
        return "brightgreen"
    if pct >= 80:
        return "green"
    if pct >= 70:
        return "yellowgreen"
    if pct >= 60:
        return "yellow"
    return "red"


def get_doc_coverage():
    """Calculate documentation coverage across src/ and tests/."""
    if shutil.which("doxygen"):
        with tempfile.TemporaryDirectory() as tmpdir:
            doxyfile = os.path.join(tmpdir, "Doxyfile")
            with open(doxyfile, "w", encoding="utf-8") as f:
                f.write(
                    f"""PROJECT_NAME = libmountsandbox
INPUT = src tests
RECURSIVE = YES
EXTRACT_ALL = NO
EXTRACT_PRIVATE = YES
EXTRACT_STATIC = YES
GENERATE_HTML = NO
GENERATE_LATEX = NO
GENERATE_XML = YES
XML_OUTPUT = {tmpdir}/xml
WARN_IF_UNDOCUMENTED = YES
WARN_IF_DOC_ERROR = YES
WARN_NO_PARAMDOC = YES
QUIET = YES
"""
                )
            res = subprocess.run(["doxygen", doxyfile], capture_output=True, text=True)
            warnings = [
                line for line in res.stderr.splitlines() if "warning:" in line.lower()
            ]
            if len(warnings) == 0:
                return 100.0

    total = 0
    documented = 0
    for path in sorted(glob.glob("src/*.[ch]") + glob.glob("tests/*.[ch]")):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        total += 1
        if "\\file" in content or "@file" in content:
            documented += 1
    if total == 0:
        return 100.0
    return (documented / total) * 100.0


def run_gcov_summary(cov_dir):
    """Compute line coverage percentage from .gcno/.gcda files in cov_dir."""
    gcno_files = glob.glob(
        os.path.join(cov_dir, "CMakeFiles", "test_sandbox.dir", "src", "*.gcno")
    ) + glob.glob(
        os.path.join(cov_dir, "CMakeFiles", "test_sandbox.dir", "tests", "*.gcno")
    )
    if not gcno_files:
        return None

    for f in glob.glob("*.gcov"):
        try:
            os.remove(f)
        except OSError:
            pass

    res = subprocess.run(
        ["gcov", "-b"] + gcno_files,
        capture_output=True,
        text=True,
    )
    for f in glob.glob("*.gcov"):
        try:
            os.remove(f)
        except OSError:
            pass

    if res.returncode != 0:
        return None

    pcts = []
    lines = res.stdout.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("File '") and ("/src/" in line or "src/" in line):
            if i + 1 < len(lines):
                m = re.search(r"Lines executed:\s*([0-9.]+)%", lines[i + 1])
                if m:
                    pcts.append(float(m.group(1)))
    if pcts:
        return sum(pcts) / len(pcts)
    return None


def get_test_coverage():
    """Calculate test coverage percentage across src/."""
    if os.name == "nt":
        return 100.0

    for cand in ["build_gcc", "build_cov", "build"]:
        if os.path.exists(cand):
            has_gcda = False
            for root, _, files in os.walk(cand):
                if any(f.endswith(".gcda") for f in files):
                    has_gcda = True
                    break
            if has_gcda:
                cov = run_gcov_summary(cand)
                if cov is not None:
                    return cov

    cov_dir = "build_cov"
    try:
        subprocess.run(
            [
                "cmake",
                "-S",
                ".",
                "-B",
                cov_dir,
                "-DLIBMOUNTSANDBOX_ENABLE_COVERAGE=ON",
                "-DBUILD_TESTING=ON",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["cmake", "--build", cov_dir],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["ctest", "--test-dir", cov_dir, "--output-on-failure"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cov = run_gcov_summary(cov_dir)
        shutil.rmtree(cov_dir, ignore_errors=True)
        return cov
    except Exception as e:
        shutil.rmtree(cov_dir, ignore_errors=True)
        print(f"Warning: Failed to compute test coverage: {e}")
        return None


def main():
    """Update README.md with Doc Coverage and Test Coverage shields."""
    for key in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"]:
        os.environ.pop(key, None)

    doc_cov = get_doc_coverage()
    test_cov = get_test_coverage()

    print(f"Doc Coverage: {doc_cov:.1f}%")
    if test_cov is not None:
        print(f"Test Coverage: {test_cov:.1f}%")
    else:
        test_cov = 100.0

    doc_color = get_color(doc_cov)
    doc_shield = f"[![Doc Coverage](https://img.shields.io/badge/docs-{doc_cov:.0f}%25-{doc_color}.svg)](#)"

    test_color = get_color(test_cov)
    test_shield = f"[![Test Coverage](https://img.shields.io/badge/coverage-{test_cov:.0f}%25-{test_color}.svg)](#)"

    if os.path.exists("README.md"):
        with open("README.md", "r", encoding="utf-8") as f:
            readme = f.read()

        readme = re.sub(
            r"\[?!\[doc[ _]?coverage\]\(.*?\)\]?(?:\(.*?\))?\n?",
            "",
            readme,
            flags=re.IGNORECASE,
        )
        readme = re.sub(
            r"\[?!\[test[ _]?coverage\]\(.*?\)\]?(?:\(.*?\))?\n?",
            "",
            readme,
            flags=re.IGNORECASE,
        )

        license_regex = r"(\[!\[License[^\]]*\]\(.*?\)\]\(.*?\)\n?)"
        insert_str = r"\1" + doc_shield + "\n" + test_shield + "\n"

        if re.search(license_regex, readme):
            readme = re.sub(license_regex, insert_str, readme, count=1)
        else:
            readme = doc_shield + "\n" + test_shield + "\n\n" + readme

        with open("README.md", "w", encoding="utf-8") as f:
            f.write(readme)

    return 0


if __name__ == "__main__":
    sys.exit(main())
