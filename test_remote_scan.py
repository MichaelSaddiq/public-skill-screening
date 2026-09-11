import copy
import json
import unittest
from remote_scan import SCANNER_VERSION, base, project, target, verdict


def clean():
    return {"risk_assessment": {"recommendation": "SAFE"}, "issues": [],
            "components": [{"path": "SKILL.md"}], "execution_successful": True,
            "analysis_completeness": {"is_complete": True}, "suppressed_count": 0,
            "metadata": {"llm_requested": False, "skillspector_version": SCANNER_VERSION}}


class Checks(unittest.TestCase):
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
        for key, val in (("finding_count", True), ("component_count", -1), ("complete", "true"), ("candidate_commit", "bad"), ("installation_authorized", True)):
            result = verdict(clean())
            result[key] = val
            self.assertEqual(project(result)["status"], "UNVERIFIED")

    def test_urls(self):
        self.assertEqual(target("https://github.com/NVIDIA/SkillSpector")[0], "https://github.com/NVIDIA/SkillSpector")
        self.assertEqual(target("https://github.com/NVIDIA/SkillSpector/tree/main/tests/fixtures/safe_skill")[2], "tests/fixtures/safe_skill")
        for url in ("file:///x", "https://github.com.evil/a/b", "https://token@github.com/a/b", "https://github.com/a/b?token=x", "https://github.com/a/b/tree/main/../secret", "https://github.com/a/b/tree/main/a/.git/config", "https://github.com/a/b;echo", "https://github.com/a/b/tree/main/a%2fb"):
            with self.assertRaises(ValueError, msg=url):
                target(url)


if __name__ == "__main__":
    unittest.main()
