"""Thin remote-only NVIDIA adapter. Candidate bytes never return to the client."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SCANNER_COMMIT = "69dcdfb74487d361ba4c811d088cfdea2ff3a9dc"
SCANNER_VERSION = "2.11.2"
MAX_REPORT = 8 * 1024 * 1024
STATUSES = {"ELIGIBLE_FOR_INSPIRATION_REVIEW", "REJECTED", "UNVERIFIED"}
REASONS = {"NO_STATIC_FINDINGS", "SECURITY_FINDINGS", "INCOMPLETE_OR_FAILED", "INVALID_INPUT", "SELF_TEST_PASS", "SELF_TEST_FAIL", "FETCH_FAILED"}
STAGE = "NONE"
STAGES = {"NONE", "INPUT", "CLONE", "REVISION", "PATH", "DIGEST", "RECEIPT"}
FAILURES = {"NONE", "PERMISSION", "VALUE", "PROCESS", "TIMEOUT", "OS", "OTHER"}


def target(value):
    match = re.fullmatch(r"https://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9_][A-Za-z0-9_.-]{0,99})(?:/tree/([A-Za-z0-9_.-]+)/([A-Za-z0-9_./-]+))?/?", value)
    if not match:
        raise ValueError("INVALID_INPUT")
    owner, repo, ref, folder = match.groups()
    if repo.endswith(".git"):
        repo = repo[:-4]
    folder = (folder or "").rstrip("/")
    if any(part in {"", ".", "..", ".git"} for part in folder.split("/")) and folder:
        raise ValueError("INVALID_INPUT")
    if len(folder) > 240 or (ref and ref in {".", ".."}):
        raise ValueError("INVALID_INPUT")
    return f"https://github.com/{owner}/{repo}", ref, folder


def base(status="UNVERIFIED", reason="INCOMPLETE_OR_FAILED"):
    return dict(schema="public-skill-screen-v1", status=status, reason=reason,
                scanner_commit=SCANNER_COMMIT, scanner_version=SCANNER_VERSION,
                scan_mode="STATIC_ONLY_OFFLINE", installation_authorized=False,
                finding_count=0, component_count=0, complete=False,
                candidate_commit=None, source_digest=None,
                failure_stage="NONE", failure_kind="NONE")


def verdict(report):
    out = base()
    risk = report.get("risk_assessment", {})
    issues = report.get("issues")
    meta = report.get("metadata", {})
    completeness = report.get("analysis_completeness", {})
    components = report.get("components")
    if not isinstance(issues, list) or not isinstance(components, list):
        return out
    out["finding_count"] = len(issues)
    out["component_count"] = len(components)
    out["complete"] = completeness.get("is_complete") is True
    if issues or risk.get("recommendation") in {"CAUTION", "DO_NOT_INSTALL"}:
        out.update(status="REJECTED", reason="SECURITY_FINDINGS")
    elif (risk.get("recommendation") == "SAFE" and report.get("execution_successful") is True
          and out["complete"] and components and meta.get("llm_requested") is False
          and meta.get("skillspector_version") == SCANNER_VERSION
          and type(report.get("suppressed_count")) is int and report["suppressed_count"] == 0):
        out.update(status="ELIGIBLE_FOR_INSPIRATION_REVIEW", reason="NO_STATIC_FINDINGS")
    return out


def project(value):
    """Rebuild an envelope from fixed enums and bounded primitives only."""
    result = base()
    if not isinstance(value, dict) or value.get("schema") != result["schema"]:
        return result
    if (value.get("scanner_commit") != SCANNER_COMMIT or value.get("scanner_version") != SCANNER_VERSION
        or value.get("status") not in STATUSES or value.get("reason") not in REASONS
        or value.get("installation_authorized") is not False
        or value.get("scan_mode") != result["scan_mode"]
        or value.get("failure_stage", "NONE") not in STAGES
        or value.get("failure_kind", "NONE") not in FAILURES):
        return result
    for key in ("finding_count", "component_count"):
        if type(value.get(key)) is not int or not 0 <= value[key] <= 100000:
            return result
    if type(value.get("complete")) is not bool:
        return result
    for key, width in (("candidate_commit", 40), ("source_digest", 64)):
        val = value.get(key)
        if val is not None and (not isinstance(val, str) or not re.fullmatch(f"[0-9a-f]{{{width}}}", val)):
            return result
    for key in result:
        if key in value:
            result[key] = value[key]
    if result["status"] == "ELIGIBLE_FOR_INSPIRATION_REVIEW" and (
        not result["complete"] or result["finding_count"] or not result["component_count"]
        or result["reason"] != "NO_STATIC_FINDINGS" or not result["candidate_commit"] or not result["source_digest"]
    ):
        return base()
    if result["status"] == "REJECTED" and result["reason"] != "SECURITY_FINDINGS":
        return base()
    return result


def read_json(path, maximum=MAX_REPORT):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("INCOMPLETE_OR_FAILED")
    return json.loads(path.read_bytes())


def git(directory, *args):
    return subprocess.check_output(["git", "-C", str(directory), *args], stderr=subprocess.DEVNULL, timeout=20).decode().strip()


def fetch(url):
    """Run only in the fresh remote container, with anonymous public access."""
    global STAGE
    STAGE = "INPUT"
    root_url, requested_ref, folder = target(url)
    from skillspector.input_handler import InputHandler
    handler = InputHandler()
    # NVIDIA performs its own bounded clone and path checks inside /data.
    tempfile.tempdir = "/data"
    STAGE = "CLONE"
    root, kind = handler.resolve(root_url)
    STAGE = "REVISION"
    commit = git(root, "rev-parse", "HEAD")
    branch = git(root, "symbolic-ref", "--short", "HEAD")
    if requested_ref and requested_ref not in {commit, branch, "HEAD"}:
        raise ValueError("INVALID_INPUT")
    STAGE = "PATH"
    selected = root / folder
    if not selected.is_dir() or selected.is_symlink() or not selected.resolve().is_relative_to(root.resolve()):
        raise ValueError("INVALID_INPUT")
    # Preserve source provenance without returning source paths or text.
    STAGE = "DIGEST"
    digest = hashlib.sha256()
    for file in sorted(selected.rglob("*")):
        if ".git" in file.relative_to(root).parts:
            continue
        if file.is_symlink():
            raise ValueError("INVALID_INPUT")
        if file.is_file():
            name = file.relative_to(selected).as_posix().encode()
            digest.update(len(name).to_bytes(4, "big") + name)
            digest.update(hashlib.sha256(file.read_bytes()).digest())
    STAGE = "RECEIPT"
    Path("/data/source.json").write_text(json.dumps(dict(path=str(selected), commit=commit, digest=digest.hexdigest())))


def scan(directory):
    with tempfile.TemporaryDirectory(prefix="report-") as tmp:
        report_path = Path(tmp) / "report.json"
        command = ["skillspector", "scan", str(directory), "--no-llm", "--format", "json", "--output", str(report_path)]
        completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=180)
        if completed.returncode not in (0, 1):
            return base()
        result = verdict(read_json(report_path))
        if completed.returncode != 0 and result["status"] == "ELIGIBLE_FOR_INSPIRATION_REVIEW":
            return base()
        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["fetch", "scan", "self-test", "project"])
    parser.add_argument("value", nargs="?")
    args = parser.parse_args()
    try:
        if args.mode != "project" and (sys.platform != "linux" or os.environ.get("REMOTE_SCANNER") != "1"):
            raise ValueError("REMOTE_ONLY")
        if args.mode == "fetch":
            fetch(args.value)
            return 0
        if args.mode == "project":
            result = project(read_json(Path(args.value), 16384))
        elif args.mode == "self-test":
            safe = scan("/opt/nvidia/tests/fixtures/safe_skill")
            bad = scan("/opt/nvidia/tests/fixtures/malicious_skill")
            passed = safe["status"] == "ELIGIBLE_FOR_INSPIRATION_REVIEW" and bad["status"] == "REJECTED"
            result = base(reason="SELF_TEST_PASS" if passed else "SELF_TEST_FAIL")
        else:
            source = read_json(Path("/data/source.json"), 4096)
            result = scan(source["path"])
            result.update(candidate_commit=source["commit"], source_digest=source["digest"])
        print(json.dumps(project(result), sort_keys=True))
        return 0
    except Exception as error:
        result = base(reason="FETCH_FAILED" if args.mode == "fetch" else "INCOMPLETE_OR_FAILED")
        if args.mode == "fetch":
            result["failure_stage"] = STAGE
            result["failure_kind"] = next((name for cls, name in (
                (PermissionError, "PERMISSION"), (ValueError, "VALUE"),
                (subprocess.TimeoutExpired, "TIMEOUT"), (subprocess.CalledProcessError, "PROCESS"),
                (OSError, "OS")) if isinstance(error, cls)), "OTHER")
        print(json.dumps(result, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
