import contextlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest

from keepout.watch import watch


OS = "macOS-27.0-arm64-arm-64bit-Mach-O"
NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
POLICY = {"protected_paths": ["protected"], "writable_paths": ["work"], "network": False,
          "inherit_fake_token": False}
SAVED_POLICY = dict(POLICY, external_routes=False)


def report(version, checks=None):
    return {"harness": "codex sandbox named permission profile", "cli_version": version, "os": OS,
            "date": "2026-10-03T12:00:00+00:00", "policy": SAVED_POLICY,
            "profile_receipt": {"generated_profile_network_mode": "limited",
                                "codex_effective_profile_readback": "unavailable", "strict_config": "rejected",
                                "config_overrides": [], "environment_override_scope": "filtered-token only"},
            "rule_omission": {"verdict": "PASS", "probe_verdict_without_rule": "FAIL",
                              "omitted_profile_override": "x"},
            "checks": checks or [{"id": "allowed-read", "description": "d", "expectation": "allow",
                                  "verdict": "PASS", "classification": "configuration_outcome",
                                  "control_evidence": "c", "sandbox_evidence": "s"}]}


class WatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.results = root / "results"
        self.results.mkdir()
        self.policy = root / "policy.json"
        self.policy.write_text(json.dumps(POLICY))
        self.calls = []

    def tearDown(self):
        self.temp.cleanup()

    def suite(self, version="codex-cli 0.157.0", checks=None):
        def run(policy):
            self.calls.append(policy)
            return report(version, checks)
        return run

    def watch(self, versions, **kwargs):
        sequence = iter(versions)

        def version_fn():
            value = next(sequence)
            if isinstance(value, Exception):
                raise value
            return value
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = watch("codex", str(self.policy), str(self.results), version_fn=version_fn,
                         suite_fn=kwargs.pop("suite_fn", self.suite()), now=NOW, os_name=OS, **kwargs)
        return code, out.getvalue()

    def log(self):
        path = self.results / "watch-log.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_existing_match_is_skipped(self):
        (self.results / "2026-10-01-macos-codex-0.156.1.json").write_text(json.dumps(report("codex-cli 0.156.1")))
        code, out = self.watch(["codex-cli 0.156.1"])
        self.assertEqual(code, 0)
        self.assertIn("up to date: 2026-10-01-macos-codex-0.156.1.json (codex-cli 0.156.1)", out)
        self.assertEqual(self.calls, [])
        self.assertEqual(len(list(self.results.glob("*.json"))), 1)
        self.assertEqual([(e["action"], e["result_file"]) for e in self.log()],
                         [("skipped", "2026-10-01-macos-codex-0.156.1.json")])

    def test_superseded_or_other_policy_does_not_match(self):
        (self.results / "a.json").write_text(json.dumps(dict(report("codex-cli 0.157.0"), superseded_note="old")))
        (self.results / "b.json").write_text(json.dumps(dict(report("codex-cli 0.157.0"),
                                                             policy=dict(SAVED_POLICY, network=True))))
        (self.results / "c.json").write_text("{broken")
        code, out = self.watch(["codex-cli 0.157.0"], dry_run=True)
        self.assertIn("would run", out)

    def test_new_version_runs_and_same_day_force_gets_suffix(self):
        code, _ = self.watch(["codex-cli 0.157.0", "codex-cli 0.157.0"])
        self.assertEqual(code, 0)
        self.assertEqual(len(self.calls), 1)
        self.assertTrue((self.results / "2026-10-03-macos-codex-0.157.0.json").exists())
        self.assertTrue((self.results / "2026-10-03-macos-codex-0.157.0.md").exists())
        code, out = self.watch(["codex-cli 0.157.0"], force=False)
        self.assertIn("up to date", out)
        self.watch(["codex-cli 0.157.0", "codex-cli 0.157.0"], force=True)
        self.assertTrue((self.results / "2026-10-03b-macos-codex-0.157.0.json").exists())
        self.assertEqual([e["action"] for e in self.log()], ["ran", "skipped", "ran"])

    def test_dry_run_writes_nothing(self):
        code, out = self.watch(["codex-cli 0.157.0"], dry_run=True)
        self.assertEqual(code, 0)
        self.assertIn("would run: codex-cli 0.157.0", out)
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.results.iterdir()), [])

    def test_missing_cli_is_unmeasured(self):
        code, out = self.watch([FileNotFoundError("no codex")])
        self.assertEqual(code, 2)
        self.assertIn("UNMEASURED", out)
        self.assertEqual(self.log()[0]["action"], "error")
        self.assertIn("UNMEASURED", self.log()[0]["reason"])
        self.assertEqual(self.calls, [])

    def test_version_change_during_run_writes_no_result(self):
        code, _ = self.watch(["codex-cli 0.157.0", "codex-cli 0.158.0"])
        self.assertEqual(code, 2)
        self.assertEqual(list(self.results.glob("*.json")), [])
        self.assertEqual(self.log()[0]["reason"].split(":")[0], "CLI version changed during run")

    def test_held_fail_is_redacted_when_written(self):
        checks = [{"id": "read-shell:protected", "description": "private recipe", "expectation": "deny",
                   "verdict": "FAIL", "classification": "pending_review", "control_evidence": "control secret",
                   "sandbox_evidence": "bypass secret"}]
        code, out = self.watch(["codex-cli 0.157.0", "codex-cli 0.157.0"],
                               suite_fn=self.suite(checks=checks))
        self.assertEqual(code, 1)
        saved = (self.results / "2026-10-03-macos-codex-0.157.0.json").read_text()
        saved += (self.results / "2026-10-03-macos-codex-0.157.0.md").read_text() + out
        self.assertIn("held for private vendor report", saved)
        for secret in ("read-shell:protected", "private recipe", "control secret", "bypass secret"):
            self.assertNotIn(secret, saved)

    def test_suite_crash_is_logged_unmeasured_and_writes_no_result(self):
        def boom(policy):
            raise OSError("runner died")
        with self.assertRaises(OSError):
            self.watch(["codex-cli 0.157.0"], suite_fn=boom)
        self.assertEqual(list(self.results.glob("*.json")), [])
        self.assertEqual(self.log()[0]["action"], "error")
        self.assertIn("UNMEASURED", self.log()[0]["reason"])

    def test_suite_measuring_another_version_writes_no_result(self):
        code, _ = self.watch(["codex-cli 0.157.0", "codex-cli 0.157.0"],
                             suite_fn=self.suite(version="codex-cli 0.155.0"))
        self.assertEqual(code, 2)
        self.assertEqual(list(self.results.glob("*.json")), [])
        self.assertIn("CLI version changed during run", self.log()[0]["reason"])

    def test_cli_version_timeout_becomes_runtime_error(self):
        import subprocess
        from unittest import mock
        from keepout import codex
        with mock.patch.object(codex.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired(["codex"], 10)):
            with self.assertRaises(RuntimeError):
                codex.cli_version("/nonexistent/codex")


if __name__ == "__main__":
    unittest.main()
