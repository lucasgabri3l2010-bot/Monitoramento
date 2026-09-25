"""Engine construction tests only: never connect or run migrations."""

import os
import pathlib
import subprocess
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
TAIL = "user:example@127.0.0.1:5432/monitor?sslmode=require"


class DatabaseDriverTests(unittest.TestCase):
    def probe(self, scheme, startup=False):
        environment = os.environ.copy()
        environment["DATABASE_URL"] = scheme + TAIL
        environment["AIVEN_DATABASE_URL"] = "postgresql://ignored:ignored@127.0.0.1/other"
        program = (
            "from config import Config; "
            "from sqlalchemy import create_engine; "
            "assert Config.SQLALCHEMY_DATABASE_URI == "
            "'postgresql+psycopg2://user:example@127.0.0.1:5432/monitor?sslmode=require'; "
            "engine = create_engine(Config.SQLALCHEMY_DATABASE_URI); "
            "assert engine.dialect.driver == 'psycopg2'; "
            "engine.dispose(); "
        )
        if startup:
            program += (
                "import servidor, migrate; "
                "assert servidor.app.config['SQLALCHEMY_DATABASE_URI'] == Config.SQLALCHEMY_DATABASE_URI; "
            )
        result = subprocess.run([sys.executable, "-c", program], cwd=ROOT,
                                env=environment, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_railway_psycopg_v3_scheme_uses_installed_psycopg2(self):
        self.probe("postgresql+psycopg://", startup=True)

    def test_legacy_postgres_scheme_remains_supported(self):
        self.probe("postgres://")

    def test_plain_postgresql_scheme_remains_supported(self):
        self.probe("postgresql://")

    def test_existing_psycopg2_scheme_remains_supported(self):
        self.probe("postgresql+psycopg2://")


if __name__ == "__main__":
    unittest.main()
