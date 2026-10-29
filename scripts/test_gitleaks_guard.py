import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "scripts" / "gitleaks_guard.py"
SYNTHETIC_SECRET = "synthetic-only-credential-value-2026"


class GitleaksGuardTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="omp-gitleaks-test-")
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        shutil.copy2(ROOT / ".gitleaks.toml", self.repo / ".gitleaks.toml")
        self.git("init", "--quiet")
        self.git("config", "--local", "user.name", "OMP Test")
        self.git("config", "--local", "user.email", "omp-test@example.invalid")
        self.git("add", ".gitleaks.toml")
        self.git("commit", "--quiet", "-m", "initial")

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.repo, check=True, capture_output=True, text=True,
            env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull},
        ).stdout.strip()

    def guard(self, *args, path=None):
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
        if path is not None:
            env["PATH"] = path
        return subprocess.run(
            [sys.executable, str(GUARD), *args], cwd=self.repo, capture_output=True, text=True, env=env,
        )

    def use_pinned_source(self):
        temporary = tempfile.TemporaryDirectory(prefix="omp-pinned-source-test-")
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name) / "source"
        subprocess.run(
            ["git", "clone", "--shared", "--quiet", "--branch", "v18.12.6", str(ROOT), str(self.repo)],
            check=True, capture_output=True,
        )
        self.git("config", "--local", "user.name", "OMP Test")
        self.git("config", "--local", "user.email", "omp-test@example.invalid")
        self.git("remote", "remove", "origin")
        shutil.copy2(ROOT / ".gitleaks.toml", self.repo / ".gitleaks.toml")
        self.git("add", ".gitleaks.toml")
        self.git("commit", "--quiet", "-m", "guard config")

    def test_staged_secret_is_blocked_without_echoing_value(self):
        (self.repo / "token.txt").write_text(f'api_key = "{SYNTHETIC_SECRET}"\n')
        self.git("add", "token.txt")

        result = self.guard("staged")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("path-sha256=", result.stdout)
        self.assertNotIn(SYNTHETIC_SECRET, result.stdout + result.stderr)

    def test_staged_quoted_secret_with_punctuation_is_blocked(self):
        secret = "synthetic-only-credential!:2026"
        (self.repo / "token.txt").write_text(f'api_key = "{secret}"\n')
        self.git("add", "token.txt")

        result = self.guard("staged")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_staged_quoted_password_with_at_and_hash_is_blocked(self):
        secret = "synthetic@credential#value2026"
        (self.repo / "token.txt").write_text(f'password = "{secret}"\n')
        self.git("add", "token.txt")

        result = self.guard("staged")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_secret_in_finding_filename_is_not_echoed(self):
        name = f"api_key={SYNTHETIC_SECRET}.txt"
        (self.repo / name).write_text(f'api_key = "{SYNTHETIC_SECRET}"\n')
        self.git("add", name)

        result = self.guard("staged")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn(SYNTHETIC_SECRET, result.stdout + result.stderr)

    def test_secret_in_protected_filename_is_not_echoed(self):
        name = f".env.{SYNTHETIC_SECRET}"
        (self.repo / name).write_text("HARMLESS=value\n")
        self.git("add", "-f", name)

        result = self.guard("staged")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn(SYNTHETIC_SECRET, result.stdout + result.stderr)

    def test_protected_environment_path_is_blocked_even_without_pattern_match(self):
        (self.repo / ".env.production").write_text("HARMLESS=value\n")
        self.git("add", "-f", ".env.production")

        result = self.guard("staged")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Protected path(s): 1", result.stdout)

    def test_staged_project_indexes_are_blocked_even_without_secret(self):
        for directory in (".codegraph", "graphify-out", ".agentmemory"):
            with self.subTest(directory=directory):
                index = self.repo / directory / "project-files.json"
                index.parent.mkdir()
                index.write_text('{"root":"synthetic"}\n')
                self.git("add", "-f", f"{directory}/project-files.json")

                result = self.guard("staged")

                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("Protected path(s): 1", result.stdout)
                self.git("reset", "--quiet", "HEAD", f"{directory}/project-files.json")

    def test_range_blocks_protected_path_without_secret(self):
        base = self.git("rev-parse", "HEAD")
        (self.repo / ".env.production").write_text("HARMLESS=value\n")
        self.git("add", "-f", ".env.production")
        self.git("commit", "--quiet", "-m", "synthetic protected path")

        result = self.guard("range", f"{base}..HEAD")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Protected path(s): 1", result.stdout)

    def test_other_credential_and_database_paths_are_blocked(self):
        for name in (".aws/credentials", "service.env.production", "data.db-journal", "data.sqlite3-wal", "data.sqlite3-shm", ".runner", ".credentials", ".credentials_rsaparams"):
            with self.subTest(name=name):
                path = self.repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("HARMLESS=value\n")
                self.git("add", "-f", name)

                result = self.guard("staged")

                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("Protected path(s): 1", result.stdout)
                self.git("reset", "--quiet", "HEAD", name)
                path.unlink()

    def test_renamed_sqlite_blob_is_blocked_in_staged_and_history(self):
        path = self.repo / "archive.dat"
        path.write_bytes(b"SQLite format 3\0" + b"\0" * 32)
        self.git("add", "archive.dat")

        staged = self.guard("staged")
        self.assertEqual(staged.returncode, 1, staged.stderr)
        self.assertIn("Protected path(s): 1", staged.stdout)

        base = self.git("rev-parse", "HEAD")
        self.git("commit", "--quiet", "-m", "synthetic SQLite blob")
        path.unlink()
        self.git("add", "-u")
        self.git("commit", "--quiet", "-m", "remove synthetic SQLite blob")

        history = self.guard("range", f"{base}..HEAD")
        self.assertEqual(history.returncode, 1, history.stderr)
        self.assertIn("Protected path(s): 1", history.stdout)

    def test_type_change_to_protected_path_is_blocked(self):
        path = self.repo / ".env.production"
        path.write_text("HARMLESS=value\n")
        self.git("add", "-f", ".env.production")
        self.git("commit", "--quiet", "-m", "synthetic baseline")
        path.unlink()
        path.symlink_to("target-does-not-exist")
        self.git("add", "-f", ".env.production")

        result = self.guard("staged")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Protected path(s): 1", result.stdout)

    def test_range_allows_removal_of_protected_path(self):
        path = self.repo / ".env.production"
        path.write_text("HARMLESS=value\n")
        self.git("add", "-f", ".env.production")
        self.git("commit", "--quiet", "-m", "synthetic baseline")
        base = self.git("rev-parse", "HEAD")
        self.git("rm", "--quiet", ".env.production")
        self.git("commit", "--quiet", "-m", "remove protected path")

        result = self.guard("range", f"{base}..HEAD")

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_range_catches_secret_added_then_removed(self):
        base = self.git("rev-parse", "HEAD")
        (self.repo / "token.txt").write_text(f'api_key = "{SYNTHETIC_SECRET}"\n')
        self.git("add", "token.txt")
        self.git("commit", "--quiet", "-m", "add synthetic token")
        (self.repo / "token.txt").write_text("clean\n")
        self.git("add", "token.txt")
        self.git("commit", "--quiet", "-m", "remove synthetic token")

        result = self.guard("range", f"{base}..HEAD")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("path-sha256=", result.stdout)
        self.assertNotIn(SYNTHETIC_SECRET, result.stdout + result.stderr)

    def test_range_catches_secret_added_only_by_merge_result(self):
        base = self.git("rev-parse", "HEAD")
        self.git("checkout", "-b", "left")
        (self.repo / "left.txt").write_text("left\n")
        self.git("add", "left.txt")
        self.git("commit", "--quiet", "-m", "left")
        self.git("checkout", "-b", "right", base)
        (self.repo / "right.txt").write_text("right\n")
        self.git("add", "right.txt")
        self.git("commit", "--quiet", "-m", "right")
        self.git("checkout", "left")
        self.git("merge", "--no-ff", "--no-commit", "right")
        (self.repo / "token.txt").write_text(f'api_key = "{SYNTHETIC_SECRET}"\n')
        self.git("add", "token.txt")
        self.git("commit", "--quiet", "-m", "merge with synthetic token")

        result = self.guard("range", f"{base}..HEAD")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("path-sha256=", result.stdout)
        self.assertNotIn(SYNTHETIC_SECRET, result.stdout + result.stderr)

    def test_new_ref_excludes_reviewed_source_history_and_scans_new_commits(self):
        self.use_pinned_source()
        (self.repo / "note.txt").write_text("clean\n")
        self.git("add", "note.txt")
        self.git("commit", "--quiet", "-m", "new clean branch commit")

        clean = self.guard("range", self.git("rev-parse", "HEAD"))
        self.assertEqual(clean.returncode, 0, clean.stderr)

        (self.repo / "new-token.txt").write_text(f'api_key = "{SYNTHETIC_SECRET}"\n')
        self.git("add", "new-token.txt")
        self.git("commit", "--quiet", "-m", "new synthetic token")
        blocked = self.guard("range", self.git("rev-parse", "HEAD"))
        self.assertEqual(blocked.returncode, 1, blocked.stderr)
        self.assertNotIn(SYNTHETIC_SECRET, blocked.stdout + blocked.stderr)

    def test_new_ref_without_pinned_source_commit_fails_closed(self):
        result = self.guard("range", self.git("rev-parse", "HEAD"))

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn(SYNTHETIC_SECRET, result.stdout + result.stderr)

    def test_new_ref_cannot_skip_secret_by_moving_source_tag(self):
        self.use_pinned_source()
        (self.repo / "token.txt").write_text(f'api_key = "{SYNTHETIC_SECRET}"\n')
        self.git("add", "token.txt")
        self.git("commit", "--quiet", "-m", "new synthetic token")
        self.git("tag", "-f", "v18.12.6", "HEAD")

        result = self.guard("range", self.git("rev-parse", "HEAD"))

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Gitleaks blocked", result.stderr)

    def test_range_catches_secret_in_commit_body(self):
        base = self.git("rev-parse", "HEAD")
        self.git("commit", "--quiet", "--allow-empty", "-m", f'api_key = "{SYNTHETIC_SECRET}"')

        result = self.guard("range", f"{base}..HEAD")

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("omp-credential-assignment", result.stdout)
        self.assertNotIn(SYNTHETIC_SECRET, result.stdout + result.stderr)

    def test_missing_scanner_fails_closed(self):
        result = self.guard("staged", path="/usr/bin:/bin")

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Gitleaks unavailable", result.stderr)

    def test_pre_commit_hook_blocks_staged_secret(self):
        self.git("config", "--local", "core.hooksPath", str(ROOT / ".githooks"))
        before = self.git("rev-parse", "HEAD")
        (self.repo / "token.txt").write_text(f'api_key = "{SYNTHETIC_SECRET}"\n')
        self.git("add", "token.txt")

        result = subprocess.run(
            ["git", "commit", "-m", "attempt synthetic token"], cwd=self.repo, capture_output=True, text=True,
            env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull},
        )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.git("rev-parse", "HEAD"), before)
        self.assertNotIn(SYNTHETIC_SECRET, result.stdout + result.stderr)

    def test_pre_push_hook_catches_added_then_removed_secret(self):
        self.use_pinned_source()
        self.git("config", "--local", "core.hooksPath", str(ROOT / ".githooks"))
        remote = self.repo / "remote.git"
        subprocess.run(["git", "init", "--bare", "--quiet", str(remote)], check=True, capture_output=True)
        self.git("remote", "add", "origin", str(remote))
        (self.repo / "token.txt").write_text(f'api_key = "{SYNTHETIC_SECRET}"\n')
        self.git("add", "token.txt")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", "add synthetic token")
        (self.repo / "token.txt").write_text("clean\n")
        self.git("add", "token.txt")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", "remove synthetic token")

        result = subprocess.run(
            ["git", "push", "origin", "HEAD:refs/heads/main"], cwd=self.repo, capture_output=True, text=True,
            env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull},
        )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Gitleaks blocked", result.stderr)
        self.assertNotIn(SYNTHETIC_SECRET, result.stdout + result.stderr)

    def test_pre_push_hook_catches_annotated_tag_body(self):
        self.git("config", "--local", "core.hooksPath", str(ROOT / ".githooks"))
        remote = self.repo / "remote.git"
        subprocess.run(["git", "init", "--bare", "--quiet", str(remote)], check=True, capture_output=True)
        self.git("remote", "add", "origin", str(remote))
        self.git("tag", "-a", "audit-synthetic", "-m", f'api_key = "{SYNTHETIC_SECRET}"')

        result = subprocess.run(
            ["git", "push", "origin", "refs/tags/audit-synthetic"], cwd=self.repo, capture_output=True, text=True,
            env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull},
        )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn(SYNTHETIC_SECRET, result.stdout + result.stderr)

    def test_pre_push_hook_catches_nested_annotated_tag_body(self):
        self.git("config", "--local", "core.hooksPath", str(ROOT / ".githooks"))
        remote = self.repo / "remote.git"
        subprocess.run(["git", "init", "--bare", "--quiet", str(remote)], check=True, capture_output=True)
        self.git("remote", "add", "origin", str(remote))
        self.git("tag", "v18.12.6")
        self.git("tag", "-a", "inner", "-m", f'api_key = "{SYNTHETIC_SECRET}"')
        self.git("tag", "-a", "outer", "-m", "clean tag", "inner")
        inner = self.git("rev-parse", "refs/tags/inner")
        self.assertTrue(self.git("cat-file", "-p", "refs/tags/outer").startswith(f"object {inner}\n"))

        result = subprocess.run(
            ["git", "push", "origin", "refs/tags/outer"], cwd=self.repo, capture_output=True, text=True,
            env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull},
        )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Gitleaks blocked", result.stderr)
        self.assertNotIn(SYNTHETIC_SECRET, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
