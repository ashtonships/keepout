import json
from pathlib import Path
import tempfile
import unittest

from keepout.checks import Check, Observation, evaluate
from keepout.policy import load_policy


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


if __name__ == "__main__":
    unittest.main()
