import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest import mock

from keepout import claude
from keepout.__main__ import build_parser
from keepout.checks import Check, Observation, evaluate, make_checks
from keepout.claude import ClaudeRunner, UNREACHABLE
from keepout.policy import Policy, load_policy


PROTECTED = ("home/.ssh", "home/.config/codex", "protected")


def bare_runner(network=False):
    runner = ClaudeRunner.__new__(ClaudeRunner)
    runner.policy = Policy(PROTECTED, ("work",), network, False)
    runner.root = Path("/private/tmp/keepout-test")
    runner.work = runner.root / "work"
    runner.marker = "keepout-marker-123"
    runner.token = "fake-token-456"
    runner.srt = "/private/var/folders/x/T/keepout-srt/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js"
    runner.node = "/usr/local/bin/node"
    runner.env = {"PATH": "/usr/bin:/bin"}
    return runner


class SettingsTests(unittest.TestCase):
    def test_network_false_denies_local_routes(self):
        settings = bare_runner(False)._settings()
        self.assertEqual(settings["network"], {"allowedDomains": [], "deniedDomains": [],
                                               "allowLocalBinding": False, "allowAllUnixSockets": False})

    def test_network_true_allows_local_routes_only(self):
        network = bare_runner(True)._settings()["network"]
        self.assertTrue(network["allowLocalBinding"])
        self.assertTrue(network["allowAllUnixSockets"])
        self.assertEqual(network["allowedDomains"], [])

    def test_deny_read_is_absolute_and_omit_drops_exactly_one(self):
        runner = bare_runner()
        full = runner._settings()["filesystem"]["denyRead"]
        self.assertEqual(full, [str(runner.root / path) for path in PROTECTED])
        self.assertTrue(all(Path(item).is_absolute() and "~" not in item for item in full))
        omitted = runner._settings(omit="home/.ssh")["filesystem"]["denyRead"]
        self.assertEqual(omitted, full[1:])

    def test_filter_env_adds_token_deny_and_no_wildcards(self):
        runner = bare_runner()
        self.assertNotIn("credentials", runner._settings())
        env = runner._settings(filter_env=True)
        self.assertEqual(env["credentials"], {"envVars": [{"name": "KEEPOUT_FAKE_TOKEN", "mode": "deny"}]})
        for settings in (runner._settings(), env, bare_runner(True)._settings(omit="protected")):
            self.assertNotIn("*", json.dumps(settings))

    def test_settings_files_stay_outside_allow_write(self):
        runner = bare_runner()
        for item in runner._settings()["filesystem"]["allowWrite"]:
            self.assertNotEqual(Path(item), runner.root)
            self.assertFalse(runner.root.is_relative_to(Path(item)))


class RuleOmissionTests(unittest.TestCase):
    def test_rule_omission_fails_closed(self):
        runner = bare_runner()
        runner.omit_settings = {"omitted": True}
        runner.omit_settings_file = runner.root / "srt-settings-omit.json"
        runner._clean = lambda value: value
        runner.run = lambda check, sandboxed, settings_path=None: Observation(
            "EXPOSED" if not sandboxed or settings_path == runner.omit_settings_file else "BLOCKED", "evidence")
        result = runner.rule_omission()
        self.assertEqual((result["verdict"], result["probe_verdict_without_rule"]), ("PASS", "FAIL"))
        self.assertIn("omitted", result["omitted_profile_override"])
        runner.run = lambda check, sandboxed, settings_path=None: Observation(
            "EXPOSED" if not sandboxed else "BLOCKED", "evidence")
        self.assertEqual(runner.rule_omission()["verdict"], "INVALID")


class ClassificationTests(unittest.TestCase):
    def _run(self, returncode, stdout, stderr, sandboxed=True):
        runner = bare_runner()
        runner.settings_file = runner.root / "srt-settings.json"
        runner.env_settings_file = runner.root / "srt-settings-env.json"
        result = subprocess.CompletedProcess([], returncode, stdout, stderr)
        with mock.patch("keepout.probes.subprocess.run", return_value=result) as run:
            observed = runner.run(Check("x", "x", "allowed_command"), sandboxed)
        return observed, run.call_args.args[0]

    def test_rejected_settings_are_error_never_blocked(self):
        observed, command = self._run(1, "", "Refusing to run with the built-in defaults, which would drop x.")
        self.assertEqual(observed.state, "ERROR")
        self.assertIn("srt rejected settings", observed.evidence)
        self.assertEqual(command[:4], [bare_runner().node, bare_runner().srt, "--settings",
                                       "/private/tmp/keepout-test/srt-settings.json"])
        observed, _ = self._run(20, "", "Error: settings invalid; Operation not permitted")
        self.assertEqual(observed.state, "ERROR")

    def test_permission_denied_exit_20_is_blocked(self):
        observed, _ = self._run(20, "", "cat: x: Operation not permitted")
        self.assertEqual(observed.state, "BLOCKED")

    def test_unsandboxed_runs_probe_argv_only(self):
        _, command = self._run(0, "EXPOSED", "", sandboxed=False)
        self.assertEqual(command, ["/bin/echo", "EXPOSED"])

    def test_env_filter_miss_reason(self):
        runner = bare_runner()
        runner.run = lambda check, sandboxed: Observation("EXPOSED", "seen")
        result = evaluate(Check("filtered-token", "t", "env_filtered", expectation="env_filtered"), runner)
        self.assertEqual(result["verdict"], "UNMEASURED")
        self.assertIn("srt credentials.envVars", result["sandbox_evidence"])


    def test_settings_file_routing(self):
        runner = bare_runner()
        runner.settings_file = runner.root / "srt-settings.json"
        runner.env_settings_file = runner.root / "srt-settings-env.json"
        result = subprocess.CompletedProcess([], 0, "BLOCKED", "")
        with mock.patch("keepout.probes.subprocess.run", return_value=result) as run:
            runner.run(Check("f", "f", "env_filtered", expectation="env_filtered"), True)
            self.assertEqual(run.call_args.args[0][3], str(runner.env_settings_file))
            runner.run(Check("o", "o", "allowed_command"), True, runner.root / "srt-settings-omit.json")
            self.assertEqual(run.call_args.args[0][3], str(runner.root / "srt-settings-omit.json"))

    def test_strict_config_isolates_wildcard_rejection(self):
        runner = bare_runner()
        runner.settings = runner._settings()
        written = {}
        runner._write_settings = lambda name, settings: written.setdefault(name, settings) and runner.root / name
        rejected = subprocess.CompletedProcess([], 1, "", "Error: x does not hold a valid config — "
                                               "network.allowedDomains.0: Invalid domain pattern\nRefusing to run")
        with mock.patch("keepout.claude.subprocess.run", return_value=rejected):
            self.assertTrue(runner.strict_config_status().startswith("rejects invalid settings"))
        invalid = written["srt-settings-invalid.json"]
        self.assertEqual(invalid["network"]["allowedDomains"], ["*"])
        self.assertEqual(invalid["filesystem"], runner.settings["filesystem"])
        other = subprocess.CompletedProcess([], 1, "", "Error: x does not hold a valid config — filesystem: Required")
        with mock.patch("keepout.claude.subprocess.run", return_value=other):
            self.assertFalse(runner.strict_config_status().startswith("rejects"))


class AdjustTests(unittest.TestCase):
    def test_network_true_marks_external_routes_unmeasured(self):
        checks = make_checks(PROTECTED, True, False, True)
        adjusted = {check.id: check for check in bare_runner(True).adjust(checks)}
        for name in ("dns-lookup", "tcp-off-host"):
            self.assertIn("no full-network mode", adjusted[name].unsupported_reason)
        self.assertEqual(adjusted["tcp-loopback"].unsupported_reason, "")

    def test_network_false_unchanged(self):
        checks = make_checks(PROTECTED, False, False)
        self.assertEqual(bare_runner(False).adjust(checks), checks)


class FindSrtTests(unittest.TestCase):
    def test_missing_srt_names_install_command(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("KEEPOUT_SRT", None)
            with mock.patch("keepout.claude.shutil.which", return_value=None):
                with self.assertRaises(FileNotFoundError) as caught:
                    claude.find_srt()
        self.assertIn("npm install --ignore-scripts", str(caught.exception))
        self.assertIn("@anthropic-ai/sandbox-runtime@0.0.78", str(caught.exception))


class RedactionTests(unittest.TestCase):
    def test_receipt_has_no_root_marker_or_token(self):
        runner = bare_runner()
        runner.settings = runner._settings()
        runner.env_settings = runner._settings(filter_env=True)
        runner.version = lambda: "srt 0.0.78"
        runner.node_version = lambda: "v22"
        runner.strict_config_status = lambda: runner._clean(
            f"exit 0; {runner.root} {runner.marker} {runner.token} {runner.srt}")
        receipt = json.dumps(runner.receipt())
        for secret in (str(runner.root), runner.marker, runner.token, "keepout-srt"):
            self.assertNotIn(secret, receipt)
        self.assertEqual(runner.receipt()["unreachable_without_model_turn"], UNREACHABLE)


    def test_unresolved_temp_spellings_are_redacted(self):
        runner = bare_runner()
        cleaned = runner._clean("/tmp/keepout-test/a /var/folders/x/T/keepout-srt/b")
        self.assertEqual(cleaned, "<temp>/a <srt>/b")


class CliTests(unittest.TestCase):
    def test_parser_accepts_claude(self):
        args = build_parser().parse_args(["run", "--harness", "claude", "--policy", "policy.toml"])
        self.assertEqual(args.harness, "claude")


@unittest.skipUnless(os.environ.get("KEEPOUT_SRT"), "KEEPOUT_SRT not set; live srt run skipped")
class LiveSrtTests(unittest.TestCase):
    def test_live_harness(self):
        policy = load_policy(Path(__file__).resolve().parents[1] / "policy.toml")
        with ClaudeRunner(policy) as runner:
            planned = runner.adjust(make_checks(policy.protected_paths, policy.network,
                                                policy.inherit_fake_token, policy.external_routes))
            results = {check.id: evaluate(check, runner) for check in planned
                       if check.id.startswith("allowed-") or check.id == "read-shell:home/.ssh"}
            omission = runner.rule_omission()
        for name in ("allowed-read", "allowed-write", "allowed-command", "read-shell:home/.ssh"):
            self.assertEqual(results[name]["verdict"], "PASS", name)
        self.assertEqual(omission["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
