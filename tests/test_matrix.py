import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from keepout import matrix
from keepout.__main__ import main


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
ROUND1 = "2026-09-27-macos-codex-0.156.1.json"
ROUND2 = "2026-09-27b-macos-codex-0.156.1.json"


def check(check_id, verdict="PASS", expectation="deny", classification="configuration_outcome",
          description=None, control="exit 0; stdout='EXPOSED'; stderr=''", sandbox="exit 0; stdout='BLOCKED'"):
    return {"id": check_id, "description": description or f"probe {check_id}", "expectation": expectation,
            "verdict": verdict, "classification": classification, "control_evidence": control,
            "sandbox_evidence": sandbox}


def run(version="codex-cli 0.157.0", date="2026-10-01T10:00:00+00:00", checks=None, **extra):
    data = {"harness": "codex sandbox named permission profile", "cli_version": version,
            "os": "macOS-27.0-arm64-arm-64bit-Mach-O", "date": date,
            "policy": {"protected_paths": ["protected"], "writable_paths": ["work"], "network": False,
                       "inherit_fake_token": False, "external_routes": False},
            "profile_receipt": {"generated_profile_network_mode": "limited"},
            "rule_omission": {"verdict": "PASS"},
            "checks": checks if checks is not None else [
                check("allowed-read", expectation="allow", control="not needed for allowed action",
                      sandbox="exit 0; stdout='EXPOSED'"),
                check("read-shell:protected"), check("read-python:protected")]}
    data.update(extra)
    return data


class MatrixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, data):
        path = self.dir / name
        path.write_text(json.dumps(data) if not isinstance(data, str) else data)
        return path

    def render(self, *paths):
        model = matrix.build_model(matrix.load_results([str(p) for p in paths]))
        return matrix.render_html(model), matrix.render_markdown(model)

    def test_real_results_render_and_superseded_round_one_is_history_only(self):
        html, md = self.render(RESULTS / ROUND1, RESULTS / ROUND2)
        self.assertIn("0.156.1", html)
        self.assertIn("<details>", html)
        self.assertIn("History", html)
        model = matrix.build_model(matrix.load_results([str(RESULTS / ROUND1), str(RESULTS / ROUND2)]))
        self.assertEqual([c["run"]["_file"] for c in model["columns"]], [ROUND2])
        self.assertEqual([r["_file"] for r in model["history"]], [ROUND1])
        whole = matrix.build_model(matrix.load_results([str(RESULTS)]))
        self.assertNotIn(ROUND1, [c["run"]["_file"] for c in whole["columns"]])
        self.assertIn(ROUND1, [r["_file"] for r in whole["history"]])
        self.assertIn("superseded by round 2", html.split("<h2>History</h2>")[1])
        self.assertNotIn(ROUND1, html.split("<h2>History</h2>")[0])
        self.assertIn("controls passed", html)

    def test_html_is_self_contained(self):
        html, _ = self.render(RESULTS)
        for banned in ("<script", "http://", "https://", "<link"):
            self.assertNotIn(banned, html)
        self.assertIn("prefers-color-scheme: dark", html)
        self.assertIn("<title>Keepout results</title>", html)

    def test_held_column_withholds_every_denial_cell(self):
        held = run(checks=[
            check("allowed-read", expectation="allow"),
            check("read-shell:protected", verdict="FAIL", classification="pending_review",
                  description="secret recipe", sandbox="raw bypass evidence"),
            check("read-python:protected"),
            check("inherited-token", verdict="EXPECTED-VISIBLE", expectation="env_visible",
                  classification="documented_behavior")])
        html, md = self.render(self.write("held.json", held))
        for text in (html, md):
            for secret in ("read-shell:protected", "raw bypass evidence", "secret recipe", "suspected-bypass"):
                self.assertNotIn(secret, text)
            self.assertIn("held for private vendor report", text)
        self.assertIn("| read-python:protected | held |", md)
        self.assertIn("| allowed-read | PASS |", md)
        self.assertIn("| inherited-token | EXPECTED-VISIBLE |", md)
        row = html.split('<th scope="row">read-python:protected</th>')[1].split("</tr>")[0]
        self.assertIn(">held<", row)
        self.assertNotIn("<details>", row)
        self.assertIn("1 checks held for private vendor report", md)

    def test_legacy_unclassified_fail_is_held(self):
        legacy = {"harness": "codex sandbox named permission profile", "cli_version": "codex-cli 0.150.0",
                  "os": "macOS-26.0-arm64", "date": "2026-09-01T00:00:00+00:00",
                  "checks": [{"id": "read-shell:protected", "description": "legacy secret", "verdict": "FAIL",
                              "control_evidence": "c", "sandbox_evidence": "legacy evidence"},
                             {"id": "read-python:protected", "description": "d", "verdict": "PASS",
                              "control_evidence": "c", "sandbox_evidence": "s"}]}
        html, md = self.render(self.write("legacy.json", legacy))
        for text in (html, md):
            self.assertNotIn("legacy evidence", text)
            self.assertNotIn("read-shell:protected", text)
            self.assertIn(matrix.LEGACY_STATUS, text)
        self.assertIn("| read-python:protected | held |", md)
        self.assertIn(f"| {matrix.ROW_CONTROLS} | — |", md)

    def test_leaks_refuse_render_and_write_nothing(self):
        leaks = ("/private/tmp/keepout-abc/x", "/Users/someone/.ssh", "keepout-" + "a1" * 24)
        for leak in leaks:
            with self.subTest(leak=leak):
                path = self.write("leak.json", run(checks=[check("read-shell:protected", sandbox=leak)]))
                with self.assertRaises(matrix.MatrixError):
                    self.render(path)
                html_out, md_out = self.dir / "m.html", self.dir / "m.md"
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    code = main(["matrix", str(path), "--html", str(html_out), "--md", str(md_out)])
                self.assertEqual(code, 2)
                self.assertIn("keepout matrix:", err.getvalue())
                self.assertNotIn(leak, err.getvalue())
                self.assertFalse(html_out.exists() or md_out.exists())

    def test_temp_home_placeholder_is_not_a_leak(self):
        path = self.write("ok.json", run(checks=[check("read-shell:home/.ssh",
                                                       sandbox="cat: <temp>/home/.ssh/id_test: denied")]))
        self.render(path)

    def test_description_is_escaped(self):
        path = self.write("xss.json", run(checks=[check("read-shell:protected",
                                                        description="<img src=x onerror=alert(1)>")]))
        html, _ = self.render(path)
        self.assertNotIn("<img", html)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)

    def test_rendering_is_deterministic(self):
        first = self.render(RESULTS, self.write("extra.json", run()))
        second = self.render(RESULTS, self.dir / "extra.json")
        self.assertEqual(first, second)

    def test_newest_run_for_a_key_wins_and_older_goes_to_history(self):
        old = self.write("a-old.json", run(date="2026-10-01T00:00:00+00:00"))
        new = self.write("b-new.json", run(date="2026-10-02T00:00:00+00:00"))
        model = matrix.build_model(matrix.load_results([str(new), str(old)]))
        self.assertEqual([c["run"]["_file"] for c in model["columns"]], ["b-new.json"])
        self.assertEqual([r["_file"] for r in model["history"]], ["a-old.json"])

    def test_columns_order_by_numeric_version(self):
        paths = [self.write(f"{v}.json", run(version=f"codex-cli {v}")) for v in ("0.200.0", "0.99.1", "0.156.1")]
        model = matrix.build_model(matrix.load_results([str(p) for p in paths]))
        self.assertEqual([c["header"]["version"] for c in model["columns"]], ["0.99.1", "0.156.1", "0.200.0"])
        self.assertEqual(model["columns"][0]["header"]["os"], "macOS 27.0")
        self.assertEqual(model["rows"][0], "allowed-read")

    def test_bad_json_names_the_file(self):
        path = self.write("broken.json", "{not json")
        with self.assertRaises(matrix.MatrixError) as ctx:
            matrix.load_results([str(path)])
        self.assertIn("broken.json", str(ctx.exception))
        missing = self.write("partial.json", {"harness": "x", "checks": []})
        with self.assertRaises(matrix.MatrixError) as ctx:
            matrix.load_results([str(missing)])
        self.assertIn("partial.json", str(ctx.exception))

    def test_malformed_rule_omission_is_a_matrix_error(self):
        path = self.write("odd.json", run(rule_omission="PASS"))
        with self.assertRaises(matrix.MatrixError):
            self.render(path)


if __name__ == "__main__":
    unittest.main()
