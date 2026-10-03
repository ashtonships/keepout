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
from keepout import imported
from keepout.checks import WITHHELD

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "lint"
REPO = Path(__file__).resolve().parents[1]
NO_CODEX = "/usr/bin/false"  # offline tests never start Codex


def load(name: str) -> cc.CodexConfig:
    return cc.load_codex_config(FIXTURES / f"{name}.toml")


class RemapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.layout = imported.Layout(Path(self.temp.name).resolve())

    def tearDown(self):
        self.temp.cleanup()

    def test_paths_map_inside_the_root_as_pure_string_work(self):
        root = self.layout.root
        with mock.patch("os.stat", side_effect=AssertionError("remap must not stat")):
            self.assertEqual(self.layout.map_path("abs", "/etc/x"), root / "abs/private/etc/x")
            self.assertEqual(self.layout.map_path("abs", "/tmp//y/"), root / "abs/private/tmp/y")
            self.assertEqual(self.layout.map_path("home", "~/.ssh"), root / "home/.ssh")
            self.assertEqual(self.layout.map_path("workspace_roots", "a/*.env"), root / "workspace/a/*.env")
        self.assertEqual(self.layout.map_path("token", ":tmpdir"), root / "tmp")
        self.assertEqual(self.layout.map_path("token", ":workspace_roots"), root / "workspace")
        self.assertIsNone(self.layout.map_path("token", ":root"))
        self.assertEqual(self.layout.config_key("home", "~/.ssh"), "~/.ssh")

    def test_dot_dot_is_refused_and_never_escapes(self):
        for scope, path in (("abs", "/../.."), ("abs", "/a/../../b"), ("abs", "/a/.."), ("home", "~/../x"),
                            ("workspace_roots", "../x")):
            with self.subTest(path=path):
                with self.assertRaises(imported.RemapError):
                    self.layout.map_path(scope, path)
        with self.assertRaises(imported.RemapError):
            self.layout.inside(self.layout.root / "abs" / ".." / ".." / "x")

    def test_plant_refuses_links(self):
        self.layout.make()
        link = self.layout.root / "abs" / "link"
        link.symlink_to(self.layout.root / "elsewhere")
        with self.assertRaises(imported.RemapError):
            self.layout.plant(link, "x")


class GlobTests(unittest.TestCase):
    def test_synthesis(self):
        self.assertEqual(imported.synth_glob("/r/**/*.env"), "/r/kd1/kd2/keepout.env")
        self.assertEqual(imported.synth_glob("/r/**/*.env", "s"), "/r/kd1s/kd2/keepouts.env")
        self.assertEqual(imported.synth_glob("a?b/*"), "akb/keepout")
        self.assertIsNone(imported.synth_glob("/r/[ab].env"))
        self.assertIsNone(imported.synth_glob("/r/{a,b}.env"))


class GeneratedConfigTests(unittest.TestCase):
    def test_only_the_permission_chain_is_carried_with_remapped_paths(self):
        cfg = cc.load_codex_config(REPO / "tests/fixtures/config/2026-09-26-failure-modes.toml")
        resolved = cc.resolve(cfg, "worker")
        with tempfile.TemporaryDirectory() as temp:
            layout = imported.Layout(Path(temp).resolve())
            text, dropped, verbatim = imported.build_config(cfg, resolved, layout)
            parsed = tomllib.loads(text)
            self.assertEqual(set(parsed), {"default_permissions", "permissions"})
            self.assertEqual(set(parsed["permissions"]), {"worker", "base"})
            self.assertEqual(parsed["default_permissions"], "worker")
            self.assertEqual(dropped, ["mcp_servers", "model", "sandbox_mode", "sandbox_permissions"])
            self.assertEqual(verbatim, [])
            for name in ("worker", "base"):
                for key in parsed["permissions"][name]["filesystem"]:
                    self.assertTrue(key.startswith((str(layout.root), "~/", ":")), key)
            self.assertIn("~/.ssh", parsed["permissions"]["base"]["filesystem"])
            self.assertEqual(parsed["permissions"]["worker"]["network"], {"mode": "full"})  # carried faithfully

    def test_private_tmp_deny_is_kept_verbatim_as_well(self):
        cfg = load("KO020-fix")
        with tempfile.TemporaryDirectory() as temp:
            layout = imported.Layout(Path(temp).resolve())
            text, _, verbatim = imported.build_config(cfg, cc.resolve(cfg, "p"), layout)
        fs = tomllib.loads(text)["permissions"]["p"]["filesystem"]
        self.assertEqual(verbatim, ["/private/tmp"])
        self.assertEqual(fs["/private/tmp"], "deny")
        self.assertEqual(fs[":root"], "deny")

    def test_omission_drops_exactly_one_entry(self):
        cfg = load("KO022")
        with tempfile.TemporaryDirectory() as temp:
            layout = imported.Layout(Path(temp).resolve())
            text, _, _ = imported.build_config(cfg, cc.resolve(cfg, "p"), layout,
                                               omit=("p", cc.FIXTURE_ROOT + "/prot"))
        self.assertEqual(list(tomllib.loads(text)["permissions"]["p"]["filesystem"].values()), ["write"])


class PlanTests(unittest.TestCase):
    def rows(self, name: str, profile: str = "p") -> dict[str, imported.Row]:
        with imported.ImportedRunner(load(name), profile, cli=NO_CODEX) as runner:
            self.assertFalse(str(runner.root).startswith("/private/tmp"))
            return {row.id: row for row in runner.rows}

    def test_deny_rows_have_dir_and_file_shapes_and_an_omission_rerun(self):
        rows = self.rows("clean")
        dir_rows = [key for key in rows if key.startswith("deny:") and "[dir]" in key]
        file_rows = [key for key in rows if key.startswith("deny:") and "[file]" in key]
        self.assertEqual(len(dir_rows), 3)
        self.assertEqual(len(file_rows), 3)
        self.assertEqual([key for key in rows if rows[key].omission], [dir_rows[0]])
        self.assertIn("allowed:echo", rows)
        self.assertEqual(rows["network:tcp-loopback"].expectation, "deny")

    def test_behavioural_rule_rows(self):
        self.assertEqual(self.rows("KO022")["carve-out:/keepout-fixture-root/prot/inner:write-new"].lint_id, "KO022")
        rows = self.rows("KO024", "c")
        self.assertIn("extends-relax:/keepout-fixture-root/protected:shell-read", rows)
        self.assertEqual(rows["overridden:p:/keepout-fixture-root/protected"].untestable_reason,
                         "replaced by child profile entry, see KO024")
        rows = self.rows("KO013")
        self.assertTrue(rows["token::home"].untestable_reason)
        self.assertIn("ignored-token::home:shell-read", rows)
        rows = self.rows("KO011")
        self.assertEqual(rows["ignored-network-key:tcp-loopback"].expectation, "intent_allow")
        self.assertEqual(self.rows("KO011-control")["network:tcp-loopback"].expectation, "allow")
        rows = self.rows("KO020")
        self.assertEqual(rows["minimal-tmp-exposure:shell-read"].lint_id, "KO020")
        self.assertIn("machine-wide", rows["token::root"].untestable_reason)
        self.assertIsNone(self.rows("KO020-fix")["minimal-tmp-exposure:shell-read"].lint_id)
        rows = self.rows("KO030")
        self.assertEqual(rows["deny:/tmp/x/protected[dir]:shell-read"].note, imported.TMP_NOTE)

    def test_minimal_canary_folder_is_removed(self):
        with imported.ImportedRunner(load("KO020"), "p", cli=NO_CODEX) as runner:
            folder = runner.min_dir
            self.assertTrue(folder.startswith("/private/tmp/keepout-min-"))
            self.assertTrue(Path(folder).is_dir())
        self.assertFalse(Path(folder).exists())

    def test_root_inside_private_tmp_is_refused(self):
        with mock.patch.object(imported.tempfile, "gettempdir", return_value="/private/tmp"):
            with imported.ImportedRunner(load("clean"), "p", cli=NO_CODEX) as runner:
                report = runner.run()
        self.assertEqual(report["status"], imported.INVALID_ROOT)
        self.assertEqual(imported.exit_code(report), 1)


class ControlAndHoldTests(unittest.TestCase):
    def runner(self) -> imported.ImportedRunner:
        runner = imported.ImportedRunner(load("KO022"), "p", cli=NO_CODEX)
        runner.fired = {"KO022", "KO020"}
        return runner

    def row(self, row_id, kind, verdict, expectation="deny", lint_id=None):
        return {"id": row_id, "description": "d", "expectation": expectation, "verdict": verdict,
                "classification": "pending_review" if verdict == "FAIL" else "configuration_outcome",
                "control_evidence": "c", "sandbox_evidence": "s", "kind": kind, "entry": "/a/b/c/secret",
                "lint_id": lint_id, "note": "", "tested": True, "untestable_reason": ""}

    def test_known_outcomes_are_published_and_unknown_fails_stay_held(self):
        runner = self.runner()
        results = [self.row("carve-out:x", "carve-out", "FAIL", lint_id="KO022"),
                   self.row("deny:/a/b/c/secret[dir]:shell-read", "deny", "FAIL"),
                   self.row("extends-relax:y", "extends-relax", "FAIL", lint_id="KO024")]  # KO024 did not fire
        runner.classify_fails(results)
        self.assertEqual([item["classification"] for item in results],
                         ["configuration_outcome", "pending_review", "pending_review"])
        self.assertIn("2026-10-03", results[0]["known_outcome"])
        report = {"remap": [], "generated_config": "", "lint": [], "checks": results}
        public = imported.public_report(report)["checks"]
        self.assertEqual(public[0]["id"], "carve-out:x")
        for held in public[1:]:
            self.assertEqual(held["id"], "suspected-bypass")
            self.assertEqual((held["sandbox_evidence"], held["entry"]), (WITHHELD, WITHHELD))
        self.assertNotIn("secret", json.dumps(public[1:]))

    def test_known_outcomes_table_is_the_reviewed_set(self):
        self.assertEqual(set(imported.KNOWN_OUTCOMES), {
            ("minimal-tmp-exposure", "KO020"), ("carve-out", "KO022"), ("extends-relax", "KO024"),
            ("ignored-network-key", "KO011"), ("ignored-token", "KO013")})
        self.assertTrue(all("2026-10-03" in receipt for receipt in imported.KNOWN_OUTCOMES.values()))

    def test_failed_echo_invalidates_denials_and_points_to_ko021(self):
        runner = self.runner()
        results = [self.row("allowed:echo", "allowed", "INVALID", "allow"), self.row("deny:x", "deny", "PASS"),
                   self.row("ignored-network-key:tcp", "ignored-network-key", "FAIL", "intent_allow")]
        status = runner.apply_controls(results, {"verdict": "PASS"})
        self.assertIn("KO021", status)
        self.assertEqual([item["verdict"] for item in results], ["INVALID", "INVALID", "INVALID"])

    def test_failed_run_wide_omission_invalidates_denials(self):
        results = [self.row("allowed:echo", "allowed", "PASS", "allow"), self.row("deny:x", "deny", "PASS")]
        status = self.runner().apply_controls(results, {"verdict": "INVALID"})
        self.assertEqual(status, "INVALID: omitted-rule control failed; denials prove nothing")
        self.assertEqual(results[1]["verdict"], "INVALID")

    def test_public_report_shrinks_original_paths_to_two_components(self):
        report = {"remap": [{"original": "/Users/someone/work/.secrets", "mapped": "<temp>/abs/Users/someone/work/.secrets"},
                            {"original": "~/.config/app/token", "mapped": "<temp>/home/.config/app/token"}],
                  "generated_config": '"<temp>/abs/Users/someone/work/.secrets" = "deny"', "lint": [], "checks": []}
        public = imported.public_report(report)
        self.assertEqual([item["original"] for item in public["remap"]], ["/.../work/.secrets", "~/.../app/token"])
        self.assertNotIn("someone", json.dumps(public))

    def test_denial_log_parsing(self):
        out = "x\n=== Sandbox denials ===\n(sh) sysctl-read kern.x\n(cat) file-read-data <temp>/dir-shape/home/.ssh/k\n"
        self.assertEqual(imported.parse_denials("r", out)["verdict"], "CAPTURED")
        self.assertEqual(imported.parse_denials("r", "nothing")["verdict"], "UNMEASURED")
        self.assertEqual(imported.parse_denials("r", "=== Sandbox denials ===\n(sh) sysctl-read k\n")["verdict"],
                         "UNMEASURED")

    def test_cli_policy_and_config_are_mutually_exclusive(self):
        result = subprocess.run([sys.executable, "-m", "keepout", "run", "--harness", "codex", "--policy",
                                 "policy.toml", "--config", str(FIXTURES / "clean.toml")], cwd=REPO,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("not allowed with", result.stderr)


@unittest.skipUnless(os.environ.get("KEEPOUT_LIVE") == "1", "live Codex runs: set KEEPOUT_LIVE=1")
class LiveImportedTests(unittest.TestCase):
    """One live run per behavioural rule. Results are recorded under results/2026-10-03-imported-*."""

    def run_fixture(self, name: str, profile: str = "p") -> dict:
        stem = REPO / "results" / f"2026-10-03-imported-{name}"
        result = subprocess.run([sys.executable, "-m", "keepout", "run", "--harness", "codex", "--config",
                                 str(FIXTURES / f"{name}.toml"), "--profile", profile, "--json", f"{stem}.json",
                                 "--md", f"{stem}.md"], cwd=REPO, capture_output=True, text=True, timeout=600)
        self.assertIn(result.returncode, (0, 1), result.stderr[-500:])
        report = json.loads(Path(f"{stem}.json").read_text())
        return {item["id"]: item for item in report["checks"]} | {"_report": report}

    def test_ko011_mode_full_stays_blocked_while_enabled_true_opens_loopback(self):
        rows = self.run_fixture("KO011")
        self.assertEqual(rows["network:tcp-loopback"]["verdict"], "PASS")
        self.assertIn("BLOCKED", rows["network:tcp-loopback"]["sandbox_evidence"])
        self.assertEqual((rows["ignored-network-key:tcp-loopback"]["verdict"],
                          rows["ignored-network-key:tcp-loopback"]["classification"]), ("FAIL", "configuration_outcome"))
        control = self.run_fixture("KO011-control")
        self.assertEqual(control["network:tcp-loopback"]["verdict"], "PASS")
        self.assertIn("EXPOSED", control["network:tcp-loopback"]["sandbox_evidence"])

    def test_ko013_unknown_token_leaves_the_fake_home_exposed(self):
        rows = self.run_fixture("KO013")
        self.assertFalse(rows["token::home"]["tested"])
        self.assertEqual((rows["ignored-token::home:shell-read"]["verdict"],
                          rows["ignored-token::home:shell-read"]["classification"]), ("FAIL", "configuration_outcome"))

    def test_ko020_minimal_exposes_private_tmp_and_the_fix_closes_it(self):
        rows = self.run_fixture("KO020")
        row = rows["minimal-tmp-exposure:shell-read"]
        self.assertEqual((row["verdict"], row["classification"]), ("FAIL", "configuration_outcome"))
        fixed = self.run_fixture("KO020-fix")
        self.assertEqual(fixed["minimal-tmp-exposure:shell-read"]["verdict"], "PASS")

    def test_ko021_root_deny_alone_cannot_start_commands(self):
        rows = self.run_fixture("KO021")
        self.assertTrue(rows["_report"]["status"].startswith("INVALID"))
        self.assertIn("KO021", rows["_report"]["status"])
        self.assertIn("exit 134", rows["allowed:echo"]["sandbox_evidence"])

    def test_ko022_inner_write_succeeds_inside_a_deny(self):
        row = self.run_fixture("KO022")["carve-out:/keepout-fixture-root/prot/inner:write-new"]
        self.assertEqual((row["verdict"], row["classification"]), ("FAIL", "configuration_outcome"))

    def test_ko024_child_relax_exposes_the_parent_deny(self):
        row = self.run_fixture("KO024", "c")["extends-relax:/keepout-fixture-root/protected:shell-read"]
        self.assertEqual(row["verdict"], "FAIL")
        self.assertIn("EXPOSED", row["sandbox_evidence"])

    def test_ko030_alias_deny_holds(self):
        rows = self.run_fixture("KO030")
        self.assertEqual(rows["deny:/tmp/x/protected[dir]:shell-read"]["verdict"], "PASS")

    def test_ko002_codex_sandbox_is_silent_about_sandbox_permissions(self):
        from keepout.codex import find_codex
        with tempfile.TemporaryDirectory(dir=tempfile.gettempdir()) as temp:
            root = Path(temp).resolve()
            (root / "home").mkdir()
            (root / "tmp").mkdir()
            (root / "home" / "config.toml").write_text(
                'sandbox_permissions = ["disk-full-read-access"]\n[permissions.p]\nextends = ":read-only"\n')
            env = {"PATH": "/usr/bin:/bin", "HOME": str(root / "home"), "CODEX_HOME": str(root / "home"),
                   "TMPDIR": str(root / "tmp")}
            result = subprocess.run([find_codex(), "sandbox", "-C", str(root), "-P", "p", "--", "/bin/echo", "hi"],
                                    env=env, cwd=root, capture_output=True, text=True, timeout=20)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "hi"))
        self.assertNotIn("ignored", result.stderr)


if __name__ == "__main__":
    unittest.main()
