import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

from keepout import codexconfig as cc
from keepout import lint

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "lint"
REPO = Path(__file__).resolve().parents[1]
CANONICAL_ROOT = "/keepout-test-root"  # canonical on purpose: a /var/folders temp root would itself raise KO030

# Every fixture fires exactly these rule ids (nothing else).
EXPECTED = {
    "clean": set(), "KO011-control": set(), "KO020-fix": set(),
    "KO023": {"KO023", "KO030"},  # a same-path spelling needs a trailing slash, itself non-canonical
}


def materialize(name: str, root: str = CANONICAL_ROOT) -> Path:
    text = (FIXTURES / f"{name}.toml").read_text().replace("{R}", root)
    handle = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    handle.write(text)
    handle.close()
    return Path(handle.name)


def ids(name: str, profile: str | None = None) -> set[str]:
    path = materialize(name)
    try:
        return {item["id"] for item in lint.lint_file(path, profile)}
    finally:
        path.unlink()


class FixtureRuleTests(unittest.TestCase):
    def test_every_rule_has_a_fixture_that_fires_exactly_that_rule(self):
        for rule_id in lint.RULES:
            if rule_id == "KO090":  # only from --codex-check output
                continue
            with self.subTest(rule=rule_id):
                self.assertTrue((FIXTURES / f"{rule_id}.toml").is_file())
                self.assertEqual(ids(rule_id), EXPECTED.get(rule_id, {rule_id}))

    def test_clean_and_control_fixtures(self):
        for name in ("clean", "KO011-control", "KO020-fix"):
            with self.subTest(name=name):
                path = materialize(name)
                findings = lint.lint_file(path)
                path.unlink()
                self.assertFalse([item for item in findings if item["severity"] in ("error", "high")])
                self.assertEqual({item["id"] for item in findings}, EXPECTED[name])

    def test_fixture_placeholder_is_read_as_a_canonical_root(self):
        findings = lint.lint_file(FIXTURES / "clean.toml")
        self.assertEqual(findings, [])
        self.assertIn("{R}", {item["message"] for item in lint.lint_file(FIXTURES / "KO022.toml")}.pop())

    def test_profile_option_lints_its_chain_and_flags_undefined_names(self):
        self.assertEqual(ids("KO024", "c"), {"KO024"})
        self.assertEqual(ids("KO024", "p"), set())
        self.assertEqual(ids("clean", "nope"), {"KO042"})

    def test_finding_shape_line_and_exit_codes(self):
        path = materialize("KO020")
        try:
            findings = lint.lint_file(path)
        finally:
            path.unlink()
        item = findings[0]
        self.assertEqual(set(item) >= {"id", "severity", "title", "why", "fix", "line", "profile", "path",
                                      "measured", "evidence_fixture"}, True)
        self.assertEqual((item["line"], item["measured"]), (9, "codex-cli 0.156.1 macOS 2026-10-03"))
        self.assertEqual(item["evidence_fixture"], "tests/fixtures/lint/KO020.toml")
        text = lint.render(findings)
        self.assertRegex(text.splitlines()[0], r"^KO020 high \S+:9 ")
        self.assertIn("    why: ", text)
        self.assertIn("    fix: ", text)
        self.assertEqual(lint.exit_code(findings), 1)
        self.assertEqual(lint.exit_code([lint.finding("KO016", "x")]), 2)
        self.assertEqual(lint.exit_code([lint.finding("KO030", "x")]), 0)
        self.assertIsNone(lint.finding("KO051", "x")["measured"])

    def test_duplicate_key_is_a_parse_error_with_a_line(self):
        findings = lint.lint_file(FIXTURES / "KO001.toml")
        self.assertEqual([(item["id"], item["line"]) for item in findings], [("KO001", 10)])
        self.assertIn("duplicate key", findings[0]["message"])

    def test_cli_lint_exit_code_and_json(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "lint.json"
            result = subprocess.run([sys.executable, "-m", "keepout", "lint", str(FIXTURES / "KO020.toml"),
                                     "--profile", "p", "--json", str(out)], cwd=REPO, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual([item["id"] for item in json.loads(out.read_text())], ["KO020"])


class ResolveTests(unittest.TestCase):
    def load(self, text: str) -> cc.CodexConfig:
        handle = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        handle.write(text)
        handle.close()
        try:
            return cc.load_codex_config(handle.name)
        finally:
            os.unlink(handle.name)

    def test_child_entry_replaces_parent_and_records_the_override(self):
        cfg = self.load('[permissions.p]\nextends=":read-only"\n[permissions.p.filesystem]\n"/r/a"="deny"\n'
                        '"/r/b"="write"\n[permissions.c]\nextends="p"\n[permissions.c.filesystem]\n"/r/a/"="read"\n')
        resolved = cc.resolve(cfg, "c")
        self.assertEqual(resolved.chain, ["c", "p", ":read-only"])
        self.assertEqual(resolved.base, ":read-only")
        self.assertEqual(sorted((e.path, e.access) for e in resolved.filesystem), [("/r/a/", "read"), ("/r/b", "write")])
        (parent, child), = resolved.overridden
        self.assertEqual((parent.profile, parent.access, child.profile, child.access), ("p", "deny", "c", "read"))

    def test_cycle_and_bad_extends_are_errors(self):
        cfg = self.load('[permissions.a]\nextends="b"\n[permissions.b]\nextends="a"\n')
        with self.assertRaisesRegex(cc.ConfigError, "cycle"):
            cc.resolve(cfg, "a")
        cfg = self.load('[permissions.a]\nextends=":readonly"\n')
        with self.assertRaisesRegex(cc.ConfigError, "unsupported built-in"):
            cc.resolve(cfg, "a")
        cfg = self.load('[permissions.a]\nextends="zz"\n')
        with self.assertRaisesRegex(cc.ConfigError, "undefined profile"):
            cc.resolve(cfg, "a")

    def test_workspace_roots_subtable_entries(self):
        cfg = self.load('[permissions.p]\nextends=":read-only"\n[permissions.p.filesystem.":workspace_roots"]\n'
                        '"**/*.env"="deny"\n')
        entries = cfg.profiles["p"].filesystem
        self.assertEqual([(e.scope, e.path, e.access) for e in entries],
                         [("token", ":workspace_roots", "table"), ("workspace_roots", "**/*.env", "deny")])


class NormalizeTests(unittest.TestCase):
    def test_normalization_is_pure_string_work(self):
        cases = {
            "/tmp/x": "/private/tmp/x", "/tmp": "/private/tmp", "/var/folders/a": "/private/var/folders/a",
            "/etc/hosts": "/private/etc/hosts", "/a//b": "/a/b", "//a/b/": "/a/b", "/a/b/../c": "/a/c",
            "/a/./b/": "/a/b", "/tmpfoo": "/tmpfoo", "~/.ssh/": "~/.ssh", "~//x/../y": "~/y", "/private/tmp": "/private/tmp",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(cc.normalize(raw), expected)
        with mock.patch("os.stat", side_effect=AssertionError("normalize must not stat")):
            cc.normalize("/tmp/../var/x")

    def test_scope(self):
        self.assertEqual([cc.scope_of(p) for p in ("/a", "~/a", ":root", "a/b", "~")],
                         ["abs", "home", "token", "relative", "home"])


class SerializerTests(unittest.TestCase):
    def test_round_trip_through_tomllib(self):
        data = {"default_permissions": "p", "permissions": {"p": {
            "extends": ":read-only", "description": 'quote " and \\ backslash', "workspace_roots": ["/a", "/b"],
            "network": {"enabled": False, "allow_local_binding": True},
            "filesystem": {"/x y/z": "deny", ":minimal": "read", ":workspace_roots": {"**/*.env": "deny"}},
            "n": 3}}}
        self.assertEqual(tomllib.loads(cc.dumps(data)), data)

    def test_unsupported_types_are_refused(self):
        with self.assertRaises(TypeError):
            cc.dumps({"x": 1.5})


class RefusalTests(unittest.TestCase):
    def test_real_codex_and_config_paths_are_refused_before_reading(self):
        with mock.patch("pathlib.Path.read_bytes", side_effect=AssertionError("must not read")):
            for name in (".codex/config.toml", ".claude/settings.json", ".ssh/config", ".config/x/config.toml"):
                with self.subTest(name=name):
                    with self.assertRaises(cc.RefusedPath):
                        cc.load_codex_config(Path.home() / name)

    def test_owner_flag_reads_only_that_file(self):
        with tempfile.TemporaryDirectory() as temp:
            fake_home = Path(temp).resolve()
            target = fake_home / ".codex" / "config.toml"
            target.parent.mkdir()
            target.write_text('default_permissions = "p"\n[permissions.p]\nextends = ":read-only"\n')
            (target.parent / "auth.json").write_text("not-for-keepout")
            with mock.patch.dict(os.environ, {"HOME": str(fake_home)}):
                with self.assertRaises(cc.RefusedPath):
                    cc.load_codex_config(target)
                opened = []
                real = Path.read_bytes

                def spy(path):
                    opened.append(str(path))
                    return real(path)

                with mock.patch("pathlib.Path.read_bytes", spy):
                    cfg = cc.load_codex_config(target, i_own_this_file=True)
            self.assertEqual(opened, [str(target)])
            self.assertIn("p", cfg.profiles)


class CodexCheckTests(unittest.TestCase):
    def test_commands_use_a_dead_provider_and_a_sanitized_copy(self):
        text = ('model = "m"\nnotify = ["/bin/sh", "-c", "boom"]\nsandbox_permissions = ["disk-full-read-access"]\n'
                'default_permissions = "p"\n[mcp_servers.x]\ncommand = "/bin/false"\n[hooks.y]\ncommand = "boom"\n'
                '[model_providers.z]\nbase_url = "https://example.invalid"\n[profiles.q]\nmodel = "n"\n'
                '[shell_environment_policy]\nset = { A = "1" }\n[sandbox_workspace_write]\nnetwork_access = false\n'
                '[permissions.p]\nextends = ":read-only"\n[permissions.p.filesystem]\n":home" = "deny"\n')
        handle = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
        handle.write(text)
        handle.close()
        cfg = cc.load_codex_config(handle.name)
        os.unlink(handle.name)
        seen = []

        def fake_run(command, **kwargs):
            config = (Path(kwargs["env"]["CODEX_HOME"]) / "config.toml").read_text()
            seen.append((command, kwargs, config))
            out = ("warning: Configured filesystem path `:home` is not recognized by this version of Codex\n"
                   "Error: something new happened\n")
            return subprocess.CompletedProcess(command, 1, "", out)

        findings = lint.lint(cfg)
        receipt = lint.codex_check(cfg, findings, cli="/fake/codex", run=fake_run)
        self.assertEqual(len(seen), 2)
        self.assertIn("--strict-config", seen[0][0])
        self.assertNotIn("--strict-config", seen[1][0])
        for command, kwargs, config in seen:
            joined = " ".join(command)
            self.assertIn('base_url="http://127.0.0.1:9/v1"', joined)
            self.assertIn("model_provider=ko", joined)
            self.assertIn("--ephemeral", command)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"], 8)
            self.assertEqual(set(kwargs["env"]), {"PATH", "HOME", "CODEX_HOME", "TMPDIR", "LANG"})
            parsed = tomllib.loads(config)
            for key in ("mcp_servers", "hooks", "notify", "model_providers", "profiles", "shell_environment_policy"):
                self.assertNotIn(key, parsed)
            self.assertIn("permissions", parsed)
            self.assertIn("sandbox_workspace_write", parsed)
            self.assertIn("sandbox_permissions", parsed)
            self.assertTrue(Path(kwargs["env"]["CODEX_HOME"]).resolve().is_relative_to(
                Path(tempfile.gettempdir()).resolve()))
        ko013 = next(item for item in findings if item["id"] == "KO013")
        self.assertIn("not recognized", ko013["codex_said"])
        self.assertIn("KO090", {item["id"] for item in findings})
        self.assertIn("127.0.0.1:9", receipt["note"])


@unittest.skipUnless(os.environ.get("KEEPOUT_LIVE") == "1", "live Codex check: set KEEPOUT_LIVE=1")
class LiveLintTests(unittest.TestCase):
    def test_codex_check_names_sandbox_permissions(self):
        path = materialize("KO002")
        try:
            cfg = cc.load_codex_config(path)
            findings = lint.lint(cfg)
            lint.codex_check(cfg, findings)
        finally:
            path.unlink()
        ko002 = next(item for item in findings if item["id"] == "KO002")
        self.assertIn("sandbox_permissions", ko002.get("codex_said", ""))


if __name__ == "__main__":
    unittest.main()
