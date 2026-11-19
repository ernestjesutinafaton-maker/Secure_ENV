import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "env_guard.py"


class EnvGuardCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Env Guard test")

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def run_guard(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root), *args],
            check=False,
            text=True,
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_detects_missing_variable_and_masks_secret(self):
        self.write(".env.example", "PUBLIC_VALUE=\n")
        self.write(
            "app.py",
            'import os\nVALUE = os.getenv("MISSING_VALUE")\nAPI_KEY = "not-a-real-secret-value"\n',
        )
        self.git("add", ".")

        result = self.run_guard()

        self.assertEqual(result.returncode, 1)
        self.assertIn("MISSING_VALUE absente", result.stdout)
        self.assertIn("Secret potentiel", result.stdout)
        self.assertNotIn("not-a-real-secret-value", result.stdout)

    def test_only_scans_added_lines_for_secrets(self):
        path = self.write("app.py", 'PASSWORD = "old-test-value"\nOTHER = 1\n')
        self.git("add", ".")
        self.git("commit", "-qm", "Initial")
        path.write_text('PASSWORD = "old-test-value"\nOTHER = 2\n', encoding="utf-8")
        self.git("add", "app.py")

        result = self.run_guard()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_reports_tracked_env_file(self):
        self.write(".env", "PASSWORD=sample-placeholder\n")
        self.git("add", ".env")

        result = self.run_guard()

        self.assertEqual(result.returncode, 1)
        self.assertIn("Fichier .env suivi par Git", result.stdout)

    def test_all_mode_scans_unstaged_files(self):
        self.write(".env.example", "VALUE=\n")
        self.write("app.js", 'const value = process.env.MISSING_VALUE;\n')
        self.git("add", ".env.example")

        result = self.run_guard("--all")

        self.assertEqual(result.returncode, 1)
        self.assertIn("MISSING_VALUE absente", result.stdout)

    def test_all_mode_reports_missing_env_example(self):
        self.write("app.py", 'import os\nVALUE = os.getenv("VALUE")\n')

        result = self.run_guard("--all")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(".env.example absent", result.stdout)

    def test_all_mode_skips_deleted_and_binary_files(self):
        self.write("gone.py", "x = 1\n")
        (self.root / "image.bin").write_bytes(b"\x00\x01password=abc\x00")
        self.git("add", ".")
        (self.root / "gone.py").unlink()

        result = self.run_guard("--all")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_reports_unignored_env_file(self):
        self.write(".env", "DEBUG=1\n")

        result = self.run_guard()

        self.assertEqual(result.returncode, 1)
        self.assertIn("non ignoré", result.stdout)

        self.write(".gitignore", ".env\n")
        self.assertEqual(self.run_guard().returncode, 0)

    def test_detects_prefixed_secret_names(self):
        self.write("settings.py", 'DB_PASSWORD = "hunter2-value"\nSECRET_KEY = "abc123def456"\n')
        self.git("add", ".")

        result = self.run_guard()

        self.assertEqual(result.returncode, 1)
        self.assertIn("settings.py:1", result.stdout)
        self.assertIn("settings.py:2", result.stdout)
        self.assertNotIn("hunter2-value", result.stdout)

    def test_ignores_expressions_in_code(self):
        self.write(
            "auth.py",
            'import os\n'
            'password = request.form["password"]\n'
            'if password == "x":\n'
            '    pass\n'
            'tokenizer = "bert-base"\n'
            'API_KEY = os.getenv("API_KEY")\n'
            'API_URL = "<your-url>"\n',
        )
        self.write(".env.example", "API_KEY=\n")
        self.git("add", ".")

        result = self.run_guard()

        self.assertEqual(result.returncode, 0, result.stdout)

    def test_known_token_formats_and_url_credentials(self):
        self.write(
            "config.js",
            'const db = "postgres://admin:Sup3rPass@db.local/app";\n'
            'const gh = "ghp_' + "a" * 36 + '";\n',
        )
        self.git("add", ".")

        result = self.run_guard()

        self.assertIn("URL avec mot de passe", result.stdout)
        self.assertIn("jeton GitHub", result.stdout)

    def test_allowlist_suppresses_matching_line(self):
        self.write("tests/fixture.py", 'TOKEN = "fixture-token-value"\n')
        self.write(
            ".env-guard.json",
            '{"secret_allowlist": [{"path": "tests/*", "pattern": "fixture-token", "reason": "test"}]}',
        )
        self.git("add", ".")

        self.assertEqual(self.run_guard().returncode, 0)

    def test_install_hook_blocks_commit_with_secret(self):
        result = self.run_guard("--install-hook")
        self.assertEqual(result.returncode, 0, result.stderr)

        self.write("app.py", 'API_KEY = "real-looking-key-123"\n')
        self.git("add", ".")
        commit = subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "test"],
            text=True,
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertNotEqual(commit.returncode, 0)
        self.assertIn("Secret potentiel", commit.stdout + commit.stderr)

    def test_install_hook_does_not_overwrite_foreign_hook(self):
        hook = self.root / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

        result = self.run_guard("--install-hook")

        self.assertEqual(result.returncode, 2)
        self.assertIn("--force", result.stderr)


if __name__ == "__main__":
    unittest.main()
