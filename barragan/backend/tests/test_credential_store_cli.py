# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from app import create_app
from app.core.config import TestConfig
from app.services.credentials import CredentialValidationError, resolve_credential_secret, test_master_key as credential_test_master_key
from app.cli.credential_store import register_default_credential
from app.storage.credential_repository import SqlAlchemyCredentialRepository


ROOT_DIR = Path(__file__).resolve().parents[2]


class CredentialStoreCliTests(unittest.TestCase):
    def test_register_default_credential_creates_and_redacts(self):
        app = _app()
        secret = "do-token-sensitive-value"

        with app.storage_context():
            body = register_default_credential(
                provider="digitalocean",
                alias="do-barragan",
                description="DigitalOcean sketch token",
                secret=secret,
                repository=SqlAlchemyCredentialRepository(),
            )

            self.assertTrue(body["ok"])
            self.assertEqual(body["action"], "created")
            self.assertTrue(body["credential"]["isDefault"])
            self.assertEqual(resolve_credential_secret("digitalocean", "do-barragan"), secret)
            self.assertNotIn(secret, str(body))
            self.assertNotIn("encryptedSecret", str(body))

    def test_register_default_credential_accepts_namecheap_format_and_redacts(self):
        app = _app()
        secret = "api-user:super-secret-api-key"

        with app.storage_context():
            body = register_default_credential(
                provider="namecheap",
                alias="namecheap-barragan",
                description="Namecheap read-only domain inventory token",
                secret=secret,
                repository=SqlAlchemyCredentialRepository(),
            )

            self.assertTrue(body["ok"])
            self.assertEqual(body["action"], "created")
            self.assertEqual(body["credential"]["provider"], "namecheap")
            self.assertTrue(body["credential"]["isDefault"])
            self.assertTrue(body["secretAccepted"])
            self.assertFalse(body["secretEchoed"])
            self.assertEqual(resolve_credential_secret("namecheap", "namecheap-barragan"), secret)
            self.assertNotIn(secret, str(body))
            self.assertNotIn("super-secret-api-key", str(body))
            self.assertNotIn("encryptedSecret", str(body))

    def test_register_default_credential_rejects_malformed_namecheap_secret_without_echo(self):
        app = _app()
        secret = "super-secret-api-key"

        with app.storage_context():
            with self.assertRaises(CredentialValidationError) as raised:
                register_default_credential(
                    provider="namecheap",
                    alias="namecheap-barragan",
                    description="Namecheap read-only domain inventory token",
                    secret=secret,
                    repository=SqlAlchemyCredentialRepository(),
                )

            self.assertIn("namecheap secret must be formatted as username:apikey", raised.exception.errors)
            self.assertNotIn(secret, str(raised.exception.errors))

    def test_register_default_credential_requires_rotate_existing_for_replacement(self):
        app = _app()

        with app.storage_context():
            register_default_credential(
                provider="digitalocean",
                alias="do-barragan",
                description="old",
                secret="old-do-token-sensitive-value",
                repository=SqlAlchemyCredentialRepository(),
            )
            with self.assertRaises(CredentialValidationError) as raised:
                register_default_credential(
                    provider="digitalocean",
                    alias="do-barragan",
                    description="new",
                    secret="new-do-token-sensitive-value",
                    repository=SqlAlchemyCredentialRepository(),
                )
            self.assertIn("credential alias already exists; pass --rotate-existing to replace its secret", raised.exception.errors)
            body = register_default_credential(
                provider="digitalocean",
                alias="do-barragan",
                description="new",
                secret="new-do-token-sensitive-value",
                rotate_existing=True,
                repository=SqlAlchemyCredentialRepository(),
            )

            self.assertEqual(body["action"], "rotated")
            self.assertTrue(body["credential"]["isDefault"])
            self.assertEqual(resolve_credential_secret("digitalocean", "do-barragan"), "new-do-token-sensitive-value")
            self.assertNotIn("new-do-token-sensitive-value", str(body))

    def test_cli_reads_secret_from_stdin_and_does_not_echo(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env = _cli_env(Path(temp_dir) / "barragan.sqlite3")
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "app.cli.credential_store",
                    "register-default",
                    "--provider",
                    "digitalocean",
                    "--alias",
                    "do-barragan",
                    "--description",
                    "DigitalOcean sketch token",
                    "--stdin",
                ],
                input="do-token-sensitive-value\n",
                check=True,
                cwd=ROOT_DIR / "backend",
                text=True,
                capture_output=True,
                env=env,
            )

        body = json.loads(result.stdout)
        self.assertTrue(body["ok"])
        self.assertEqual(body["credential"]["provider"], "digitalocean")
        self.assertTrue(body["credential"]["isDefault"])
        self.assertNotIn("do-token-sensitive-value", result.stdout)
        self.assertNotIn("do-token-sensitive-value", result.stderr)

    def test_cli_accepts_namecheap_secret_file_and_does_not_echo(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            secret_file = root / "namecheap-token.txt"
            secret_file.write_text("api-user:super-secret-api-key\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "app.cli.credential_store",
                    "register-default",
                    "--provider",
                    "namecheap",
                    "--alias",
                    "namecheap-barragan",
                    "--description",
                    "Namecheap read-only domain inventory token",
                    "--secret-file",
                    str(secret_file),
                    "--pretty",
                ],
                check=True,
                cwd=ROOT_DIR / "backend",
                text=True,
                capture_output=True,
                env=_cli_env(root / "barragan.sqlite3"),
            )

        body = json.loads(result.stdout)
        self.assertTrue(body["ok"])
        self.assertEqual(body["credential"]["provider"], "namecheap")
        self.assertTrue(body["credential"]["isDefault"])
        self.assertNotIn("api-user:super-secret-api-key", result.stdout)
        self.assertNotIn("super-secret-api-key", result.stdout)
        self.assertNotIn("api-user:super-secret-api-key", result.stderr)
        self.assertNotIn("super-secret-api-key", result.stderr)

    def test_cli_reads_secret_from_file_and_does_not_echo(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            secret_file = root / "do-token.txt"
            secret_file.write_text("do-file-token-sensitive-value\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "app.cli.credential_store",
                    "register-default",
                    "--provider",
                    "digitalocean",
                    "--alias",
                    "do-file",
                    "--secret-file",
                    str(secret_file),
                    "--pretty",
                ],
                check=True,
                cwd=ROOT_DIR / "backend",
                text=True,
                capture_output=True,
                env=_cli_env(root / "barragan.sqlite3"),
            )

        body = json.loads(result.stdout)
        self.assertEqual(body["action"], "created")
        self.assertNotIn("do-file-token-sensitive-value", result.stdout)
        self.assertNotIn("do-file-token-sensitive-value", result.stderr)


def _app():
    import os

    os.environ["BARRAGAN_CREDENTIAL_MASTER_KEY"] = credential_test_master_key()
    app = create_app(TestConfig)
    app.config["TESTING"] = True
    return app


def _cli_env(database_path: Path):
    import os

    env = os.environ.copy()
    env["BARRAGAN_CREDENTIAL_MASTER_KEY"] = credential_test_master_key()
    env["BARRAGAN_DATABASE_URL"] = f"sqlite:///{database_path}"
    return env


if __name__ == "__main__":
    unittest.main()
