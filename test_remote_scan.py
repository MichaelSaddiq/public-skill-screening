import copy
import json
import unittest
import hashlib
import tempfile
from email.message import Message
from unittest.mock import patch, MagicMock
from pathlib import Path
from remote_scan import SCANNER_VERSION, base, project, target, verdict
from remote_scan import fetch, file_list, read_public, NoRedirect, MAX_FILE


def clean():
    return {"risk_assessment": {"recommendation": "SAFE"}, "issues": [],
            "components": [{"path": "SKILL.md"}], "execution_successful": True,
            "analysis_completeness": {"is_complete": True}, "suppressed_count": 0,
            "metadata": {"llm_requested": False, "skillspector_version": SCANNER_VERSION}}


class Checks(unittest.TestCase):
    def test_workflow_file_limit_is_bytes_and_probed_offline(self):
        workflow = (Path(__file__).parent / ".github/workflows/scan.yml").read_text()
        self.assertIn("--ulimit fsize=16777216:16777216", workflow)
        self.assertNotIn("--ulimit fsize=16384:16384", workflow)
        self.assertIn("--network=none --entrypoint python", workflow)
        self.assertIn("resource.getrlimit(resource.RLIMIT_FSIZE)==(16777216,16777216)", workflow)
        self.assertIn("f.write(bytes(16385))", workflow)

    def test_benign(self):
        self.assertEqual(verdict(clean())["status"], "ELIGIBLE_FOR_INSPIRATION_REVIEW")

    def test_caution(self):
        for recommendation in ("CAUTION", "DO_NOT_INSTALL"):
            report = clean()
            report["risk_assessment"]["recommendation"] = recommendation
            self.assertEqual(verdict(report)["status"], "REJECTED")

    def test_any_finding_rejected_and_not_echoed(self):
        report = clean()
        report["issues"] = [{"message": "UNTRUSTED_PAYLOAD"}]
        result = verdict(report)
        self.assertEqual(result["status"], "REJECTED")
        self.assertNotIn("UNTRUSTED_PAYLOAD", json.dumps(result))

    def test_incomplete_missing_or_suppressed(self):
        for field in clean():
            report = clean()
            del report[field]
            self.assertEqual(verdict(report)["status"], "UNVERIFIED", field)
        for key, value in (("execution_successful", False), ("components", []), ("suppressed_count", 1), ("suppressed_count", False)):
            report = clean()
            report[key] = value
            self.assertEqual(verdict(report)["status"], "UNVERIFIED")

    def test_projection_drops_payload(self):
        result = verdict(clean())
        result.update(candidate_commit="a" * 40, source_digest="b" * 64)
        result["message"] = "UNTRUSTED_PAYLOAD"
        self.assertNotIn("UNTRUSTED_PAYLOAD", json.dumps(project(result)))
        result["reason"] = "UNTRUSTED_PAYLOAD"
        self.assertEqual(project(result)["status"], "UNVERIFIED")

    def test_eligible_requires_provenance_and_consistent_reason(self):
        result = verdict(clean())
        self.assertEqual(project(result)["status"], "UNVERIFIED")
        result.update(candidate_commit="a"*40, source_digest="b"*64)
        self.assertEqual(project(result)["status"], "ELIGIBLE_FOR_INSPIRATION_REVIEW")
        result["reason"] = "SECURITY_FINDINGS"
        self.assertEqual(project(result)["status"], "UNVERIFIED")

    def test_projection_invalid_types(self):
        for key, val in (("finding_count", True), ("component_count", -1), ("complete", "true"), ("candidate_commit", "bad"), ("installation_authorized", True), ("failure_kind", "RAW_PAYLOAD"), ("failure_stage", "RAW_PAYLOAD")):
            result = verdict(clean())
            result[key] = val
            self.assertEqual(project(result)["status"], "UNVERIFIED")

    def test_urls(self):
        self.assertEqual(target("https://github.com/NVIDIA/SkillSpector")[0], "https://github.com/NVIDIA/SkillSpector")
        self.assertEqual(target("https://github.com/NVIDIA/SkillSpector/tree/main/tests/fixtures/safe_skill")[2], "tests/fixtures/safe_skill")
        for url in ("file:///x", "https://github.com.evil/a/b", "https://token@github.com/a/b", "https://github.com/a/b?token=x", "https://github.com/a/b/tree/main/../secret", "https://github.com/a/b/tree/main/a/.git/config", "https://github.com/a/b;echo", "https://github.com/a/b/tree/main/a%2fb"):
            with self.assertRaises(ValueError, msg=url):
                target(url)

    def test_subtree_fetch_does_not_clone_or_fetch_siblings(self):
        content = b"Synthetic harmless skill fixture\n"
        sha = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        responses = [dict(private=False, default_branch="main"),
                     dict(sha="a"*40, commit=dict(tree=dict(sha="b"*40))),
                     dict(truncated=False, tree=[dict(path="skill", type="tree", mode="040000", sha="c"*40)]),
                     dict(truncated=False, tree=[dict(path="SKILL.md", type="blob", mode="100644", sha=sha, size=len(content))])]
        with tempfile.TemporaryDirectory() as td, patch("remote_scan.read_public", side_effect=[json.dumps(x).encode() for x in responses]+[content]) as read, patch("remote_scan.subprocess.check_output") as git:
            fetch("https://github.com/example/catalog/tree/main/skill", Path(td))
            self.assertEqual((Path(td)/"candidate/SKILL.md").read_bytes(), content)
            receipt = json.loads((Path(td)/"source.json").read_text())
            self.assertEqual(receipt["commit"], "a"*40)
            self.assertEqual(read.call_count, 5)
            self.assertIn("/"+"a"*40+"/skill/SKILL.md", read.call_args.args[0])
            git.assert_not_called()

    def test_bad_tree_entries_and_truncation_rejected(self):
        good = dict(path="SKILL.md", type="blob", mode="100644", sha="a"*40, size=3)
        for change in (dict(path="../x"), dict(path=".git/config"), dict(path="/x"),
                       dict(mode="120000"), dict(type="commit", mode="160000"),
                       dict(size=MAX_FILE+1), dict(size=True), dict(sha="bad")):
            with self.assertRaises(ValueError):
                file_list(dict(truncated=False, tree=[dict(good, **change)]))
        for listing in (dict(truncated=True, tree=[good]), dict(tree=[good]),
                        dict(truncated=False, tree=[good, good]), dict(truncated=False, tree=[])):
            with self.assertRaises(ValueError):
                file_list(listing)

    def test_wrong_blob_never_produces_receipt(self):
        responses = [dict(private=False, default_branch="main"),
                     dict(sha="a"*40, commit=dict(tree=dict(sha="b"*40))),
                     dict(truncated=False, tree=[dict(path="SKILL.md", type="blob", mode="100644", sha="c"*40, size=3)])]
        with tempfile.TemporaryDirectory() as td, patch("remote_scan.read_public", side_effect=[json.dumps(x).encode() for x in responses]+[b"bad"]):
            with self.assertRaises(ValueError):
                fetch("https://github.com/example/skill", Path(td))
            self.assertFalse((Path(td)/"source.json").exists())

    def test_bounded_read_incomplete_and_redirect(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, None, None, None, None))
        for body, declared in ((b"abc", "4"), (b"abcde", "5"), (b"abc", "bad")):
            response = MagicMock()
            response.status = 200
            response.headers = Message()
            response.headers["Content-Length"] = declared
            response.read.return_value = body
            response.__enter__.return_value = response
            with patch("remote_scan.build_opener") as opener:
                opener.return_value.open.return_value = response
                with self.assertRaises(ValueError):
                    read_public("https://api.github.com/repos/example/skill", 4)

    def test_unique_workflow_group_preserves_pending_requests(self):
        workflow = (Path(__file__).parent / ".github/workflows/scan.yml").read_text()
        self.assertIn("group: public-skill-screening-${{ github.run_id }}", workflow)
        self.assertIn("cancel-in-progress: false", workflow)


if __name__ == "__main__":
    unittest.main()
