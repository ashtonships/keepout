import json
from pathlib import Path
import tempfile
import unittest

from keepout.checks import Check, Observation, evaluate, invalidate_denials, make_checks
from keepout.codex import CodexRunner
from keepout.policy import Policy, load_policy
from keepout.report import summary, write_report


class FakeRunner:
    def __init__(self, control: str, sandbox: str):
        self.control = control
        self.sandbox = sandbox
        self.calls = []

    def run(self, check, sandboxed):
        self.calls.append(sandboxed)
        state = self.sandbox if sandboxed else self.control
        return Observation(state, state.lower())


class VerdictTests(unittest.TestCase):
    def test_pass_requires_exposed_control_and_blocked_sandbox(self):
        runner = FakeRunner("EXPOSED", "BLOCKED")
        self.assertEqual(evaluate(Check("read", "read", "shell_read"), runner)["verdict"], "PASS")
        self.assertEqual(runner.calls, [False, True])

    def test_fail_on_exposure(self):
        self.assertEqual(evaluate(Check("read", "read", "shell_read"), FakeRunner("EXPOSED", "EXPOSED"))["verdict"], "FAIL")

    def test_invalid_control_stops_sandbox_probe(self):
        runner = FakeRunner("BLOCKED", "BLOCKED")
        self.assertEqual(evaluate(Check("read", "read", "shell_read"), runner)["verdict"], "INVALID")
        self.assertEqual(runner.calls, [False])

    def test_unmeasured_on_sandbox_error(self):
        self.assertEqual(evaluate(Check("read", "read", "shell_read"), FakeRunner("EXPOSED", "ERROR"))["verdict"], "UNMEASURED")

    def test_unmeasured_unsupported_check_never_runs(self):
        runner = FakeRunner("EXPOSED", "BLOCKED")
        check = Check("offhost", "offhost", "offhost", unsupported_reason="not permitted")
        self.assertEqual(evaluate(check, runner)["verdict"], "UNMEASURED")
        self.assertEqual(runner.calls, [])

    def test_allowed_actions_must_succeed_inside_sandbox(self):
        for state, expected in (("EXPOSED", "PASS"), ("BLOCKED", "INVALID"), ("ERROR", "INVALID")):
            with self.subTest(state=state):
                runner = FakeRunner("EXPOSED", state)
                result = evaluate(Check("allowed-read", "read", "allowed_read", expectation="allow"), runner)
                self.assertEqual(result["verdict"], expected)
                self.assertEqual(runner.calls, [True])

    def test_failed_allowed_control_invalidates_every_denial(self):
        checks = [evaluate(Check("allowed-read", "read", "allowed_read", expectation="allow"),
                           FakeRunner("EXPOSED", "BLOCKED")),
                  evaluate(Check("secret", "secret", "shell_read"), FakeRunner("EXPOSED", "BLOCKED")),
                  evaluate(Check("socket", "socket", "unix"), FakeRunner("EXPOSED", "EXPOSED"))]
        results = invalidate_denials(checks)
        self.assertEqual([item["verdict"] for item in results], ["INVALID", "INVALID", "INVALID"])
        self.assertTrue(all("sandbox blocked allowed actions; denials prove nothing" in item["sandbox_evidence"]
                            for item in results[1:]))

    def test_environment_visibility_is_not_enforcement_failure(self):
        check = Check("inherited-token", "token", "env", expectation="env_visible")
        result = evaluate(check, FakeRunner("EXPOSED", "EXPOSED"))
        self.assertEqual((result["verdict"], result["classification"]),
                         ("EXPECTED-VISIBLE", "documented_behavior"))

    def test_environment_filter_never_fails(self):
        check = Check("filtered-token", "token", "env_filtered", expectation="env_filtered")
        self.assertEqual(evaluate(check, FakeRunner("EXPOSED", "BLOCKED"))["verdict"], "PASS")
        self.assertEqual(evaluate(check, FakeRunner("EXPOSED", "EXPOSED"))["verdict"], "UNMEASURED")

    def test_routes_are_distinct_and_external_routes_default_unmeasured(self):
        checks = {check.id: check for check in make_checks(("home/.ssh",), False, False)}
        self.assertEqual(checks["tcp-loopback"].unsupported_reason, "")
        self.assertEqual(checks["unix-socket"].unsupported_reason, "")
        self.assertIn("external_routes", checks["dns-lookup"].unsupported_reason)
        self.assertIn("external_routes", checks["tcp-off-host"].unsupported_reason)

    def test_rule_omission_fails_closed(self):
        runner = CodexRunner.__new__(CodexRunner)
        runner.policy = Policy(("home/.ssh",), ("work",), False, False)
        runner._profile = lambda omit=None: "omitted-profile"
        runner._clean = lambda value: value
        runner.run = lambda check, sandboxed, profile_override=None: Observation(
            "EXPOSED" if not sandboxed or profile_override == "omitted-profile" else "BLOCKED", "evidence")
        self.assertEqual(runner.rule_omission()["probe_verdict_without_rule"], "FAIL")
        self.assertEqual(runner.rule_omission()["verdict"], "PASS")
        runner.run = lambda check, sandboxed, profile_override=None: Observation(
            "EXPOSED" if not sandboxed else "BLOCKED", "evidence")
        self.assertEqual(runner.rule_omission()["verdict"], "INVALID")
        denial = evaluate(Check("secret", "secret", "shell_read"), FakeRunner("EXPOSED", "BLOCKED"))
        self.assertEqual(invalidate_denials([denial], omission_ok=False)[0]["verdict"], "INVALID")

    def test_suspected_bypass_evidence_is_withheld_on_write(self):
        report = {"harness": "test", "cli_version": "test", "os": "test", "date": "test",
                  "profile_receipt": {"generated_profile_network_mode": "limited",
                                      "codex_effective_profile_readback": "unavailable",
                                      "strict_config": "rejected",
                                      "config_overrides": [], "environment_override_scope": "test"},
                  "rule_omission": {"verdict": "PASS", "probe_verdict_without_rule": "FAIL",
                                    "omitted_profile_override": "test"},
                  "checks": [{"id": "private path", "description": "private recipe",
                              "expectation": "deny", "verdict": "FAIL",
                              "classification": "suspected_undocumented_bypass",
                              "control_evidence": "secret control", "sandbox_evidence": "secret bypass"}]}
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            md_path = Path(directory) / "report.md"
            write_report(report, str(json_path), str(md_path))
            saved = json_path.read_text() + md_path.read_text()
        self.assertIn("held for private vendor report", saved)
        for secret in ("private path", "private recipe", "secret control", "secret bypass"):
            self.assertNotIn(secret, saved)

    def test_new_denial_fail_is_held_by_default(self):
        from keepout.checks import Check, Observation, evaluate, public_result

        class Leaky:
            def run(self, check, sandboxed):
                return Observation("EXPOSED", "raw exploit detail")

        result = evaluate(Check("deny-read", "read a canary", "read", expectation="deny"), Leaky())
        self.assertEqual((result["verdict"], result["classification"]), ("FAIL", "pending_review"))
        public = public_result(result)
        self.assertNotIn("raw exploit detail", str(public))
        self.assertIn("held for private vendor report", str(public))

    def test_summary_excludes_expected_visible_from_enforcement_failures(self):
        report = {"rule_omission": {"verdict": "PASS"},
                  "checks": [{"id": "allowed-read", "expectation": "allow", "verdict": "PASS"},
                             {"id": "inherited-token", "expectation": "env_visible",
                              "verdict": "EXPECTED-VISIBLE"}]}
        totals = summary(report)
        self.assertEqual(totals["enforcement_failures"], 0)
        self.assertEqual(totals["EXPECTED-VISIBLE"], 1)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.data = {"protected_paths": ["home/.ssh", "home/.config/codex"],
                     "writable_paths": ["work"], "network": False, "inherit_fake_token": False}

    def _load(self, data, suffix):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / ("policy" + suffix)
            if suffix == ".json":
                file.write_text(json.dumps(data))
            else:
                file.write_text('protected_paths = ["home/.ssh", "home/.config/codex"]\n'
                                'writable_paths = ["work"]\nnetwork = false\ninherit_fake_token = false\n')
            return load_policy(file)

    def test_json(self):
        policy = self._load(self.data, ".json")
        self.assertEqual(policy.protected_paths, ("home/.ssh", "home/.config/codex"))

    def test_toml(self):
        self.assertFalse(self._load(self.data, ".toml").network)

    def test_rejects_absolute_and_parent_paths(self):
        for bad in ("/tmp/secret", "home/../secret", "../../secret"):
            with self.subTest(bad=bad):
                data = dict(self.data, protected_paths=[bad])
                with self.assertRaises(ValueError):
                    self._load(data, ".json")

    def test_rejects_overlap(self):
        data = dict(self.data, writable_paths=["home"])
        with self.assertRaises(ValueError):
            self._load(data, ".json")

    def test_requires_writable_work(self):
        data = dict(self.data, writable_paths=["outside"])
        with self.assertRaises(ValueError):
            self._load(data, ".json")

    def test_rejects_unknown_fields(self):
        data = dict(self.data, extra=True)
        with self.assertRaises(ValueError):
            self._load(data, ".json")

    def test_external_routes_require_explicit_network_opt_in(self):
        data = dict(self.data, external_routes=True)
        with self.assertRaises(ValueError):
            self._load(data, ".json")
        data["network"] = True
        self.assertTrue(self._load(data, ".json").external_routes)

    def test_network_policy_is_in_generated_profile(self):
        runner = CodexRunner.__new__(CodexRunner)
        runner.root = Path("/private/tmp/keepout-test")
        runner.policy = Policy(("home/.ssh",), ("work",), False, False)
        self.assertIn('network = { mode = "limited" }', runner._profile())
        runner.policy = Policy(("home/.ssh",), ("work",), True, False)
        self.assertIn('network = { mode = "full" }', runner._profile())


if __name__ == "__main__":
    unittest.main()
