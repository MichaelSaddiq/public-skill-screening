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
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
from urllib.parse import quote

SCANNER_COMMIT = "69dcdfb74487d361ba4c811d088cfdea2ff3a9dc"
SCANNER_VERSION = "2.11.2"
MAX_REPORT = 8 * 1024 * 1024
STATUSES = {"ELIGIBLE_FOR_INSPIRATION_REVIEW", "REJECTED", "UNVERIFIED"}
REASONS = {"NO_STATIC_FINDINGS", "SECURITY_FINDINGS", "INCOMPLETE_OR_FAILED", "INVALID_INPUT", "SELF_TEST_PASS", "SELF_TEST_FAIL", "FETCH_FAILED"}
STAGE = "NONE"
STAGES = {"NONE", "INPUT", "CLONE", "REVISION", "PATH", "DIGEST", "RECEIPT", "TREE", "BLOB"}
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


MAX_FILE = 1024 * 1024  # NVIDIA's per-file analysis cap; no silent truncation.
MAX_TOTAL = 100 * 1024 * 1024
MAX_ENTRIES = 10000


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def read_public(url, limit):
    if not (url.startswith("https://api.github.com/repos/") or
            url.startswith("https://raw.githubusercontent.com/")):
        raise ValueError("INVALID_INPUT")
    opener = build_opener(ProxyHandler({}), NoRedirect())
    request = Request(url, headers={"User-Agent": "public-skill-screening", "Accept-Encoding": "identity"})
    with opener.open(request, timeout=15) as response:
        if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
            raise ValueError("INCOMPLETE_OR_FAILED")
        lengths = response.headers.get_all("Content-Length", [])
        if len(lengths) > 1 or (lengths and (not lengths[0].isdigit() or int(lengths[0]) > limit)):
            raise ValueError("INCOMPLETE_OR_FAILED")
        data = response.read(limit + 1)
        if len(data) > limit or (lengths and len(data) != int(lengths[0])):
            raise ValueError("INCOMPLETE_OR_FAILED")
        return data


def object_sha(value):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{40}", value):
        raise ValueError("INVALID_INPUT")
    return value


def file_list(document):
    if document.get("truncated") is not False or not isinstance(document.get("tree"), list):
        raise ValueError("INCOMPLETE_OR_FAILED")
    if len(document["tree"]) > MAX_ENTRIES:
        raise ValueError("INCOMPLETE_OR_FAILED")
    files, seen, total = [], set(), 0
    for entry in document["tree"]:
        name = entry.get("path")
        if (not isinstance(name, str) or len(name) > 240 or
                not re.fullmatch(r"[A-Za-z0-9_./-]+", name) or
                any(p in {"", ".", "..", ".git"} for p in name.split("/")) or name in seen):
            raise ValueError("INVALID_INPUT")
        seen.add(name)
        object_sha(entry.get("sha"))
        if entry.get("type") == "tree" and entry.get("mode") == "040000":
            continue
        if entry.get("type") != "blob" or entry.get("mode") not in {"100644", "100755"}:
            raise ValueError("INVALID_INPUT")
        size = entry.get("size")
        if type(size) is not int or not 0 <= size <= MAX_FILE:
            raise ValueError("INCOMPLETE_OR_FAILED")
        total += size
        if total > MAX_TOTAL:
            raise ValueError("INCOMPLETE_OR_FAILED")
        files.append(entry)
    if not files:
        raise ValueError("INCOMPLETE_OR_FAILED")
    return sorted(files, key=lambda e: e["path"])


def fetch(url, data_root=Path("/data")):
    """Fetch only a commit-pinned subtree in the disposable remote container."""
    global STAGE
    STAGE = "INPUT"
    root_url, requested_ref, folder = target(url)
    owner_repo = root_url.removeprefix("https://github.com/")
    if owner_repo.split("/")[0].casefold() == "michaelsaddiq":
        raise ValueError("INVALID_INPUT")
    api = "https://api.github.com/repos/" + owner_repo
    def metadata(suffix):
        return json.loads(read_public(api + suffix, 2 * 1024 * 1024))
    repo = metadata("")
    if repo.get("private") is not False:
        raise ValueError("INVALID_INPUT")
    branch = repo["default_branch"]
    STAGE = "REVISION"
    revision = metadata("/commits/" + quote(branch, safe=""))
    commit = object_sha(revision["sha"])
    if requested_ref and requested_ref not in {commit, branch, "HEAD"}:
        raise ValueError("INVALID_INPUT")
    tree = object_sha(revision["commit"]["tree"]["sha"])
    STAGE = "TREE"
    for segment in folder.split("/") if folder else []:
        listing = metadata("/git/trees/" + tree)
        if listing.get("truncated") is not False:
            raise ValueError("INCOMPLETE_OR_FAILED")
        matches = [e for e in listing["tree"] if e.get("path") == segment and e.get("type") == "tree" and e.get("mode") == "040000"]
        if len(matches) != 1:
            raise ValueError("INVALID_INPUT")
        tree = object_sha(matches[0]["sha"])
    entries = file_list(metadata("/git/trees/" + tree + "?recursive=1"))
    selected = data_root / "candidate"
    selected.mkdir(exist_ok=False)
    STAGE = "BLOB"
    for entry in entries:
        name = entry["path"]
        rel = (folder + "/" if folder else "") + name
        data = read_public("https://raw.githubusercontent.com/" + owner_repo + "/" + commit + "/" + quote(rel, safe="/"), MAX_FILE)
        if len(data) != entry["size"] or hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() != entry["sha"]:
            raise ValueError("INCOMPLETE_OR_FAILED")
        path = selected / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as output:
            output.write(data)
    # Preserve source provenance without returning source paths or text.
    STAGE = "DIGEST"
    digest = hashlib.sha256()
    for file in sorted(selected.rglob("*")):
        if ".git" in file.relative_to(selected).parts:
            continue
        if file.is_symlink():
            raise ValueError("INVALID_INPUT")
        if file.is_file():
            name = file.relative_to(selected).as_posix().encode()
            digest.update(len(name).to_bytes(4, "big") + name)
            digest.update(hashlib.sha256(file.read_bytes()).digest())
    STAGE = "RECEIPT"
    (data_root / "source.json").write_text(json.dumps(dict(path=str(selected), commit=commit, digest=digest.hexdigest())))


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
