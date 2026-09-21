import os
import sys
import unittest
from unittest.mock import patch
import io

# Add the project root to path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from models import db, User
from scripts.reset_admin_password import main


class ResetAdminPasswordTestCase(unittest.TestCase):
    """Focused tests for the one-time admin password reset script."""

    @classmethod
    def setUpClass(cls):
        # Import app
        from servidor import app

        cls.app = app
        cls.db = db

        # Configure in-memory SQLite for isolated tests
        cls.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'

        # Create app and push context
        cls.app.app_context().push()

        # Create all tables (idempotent)
        db.create_all()

    @classmethod
    def tearDownClass(cls):
        # Clean up
        cls.db.session.remove()
        cls.db.drop_all()
        cls.app.app_context().pop()

    def setUp(self):
        # Use a unique username to avoid UNIQUE constraint conflicts
        # but the script uses Config.ADMIN_USERNAME defaulting to "admin"
        # So we must create the user with username "admin"
        self.test_username = "admin"
        # Ensure no existing user with this username exists
        existing = User.query.filter_by(username=self.test_username).first()
        if existing:
            db.session.delete(existing)
            db.session.commit()

        # Create a test admin user with a known password
        self.admin = User(username=self.test_username, role="admin")
        self.admin.set_password("old_password_123")
        db.session.add(self.admin)
        db.session.commit()

        # Store the admin ID for reuse
        self.admin_id = self.admin.id

    def tearDown(self):
        # Clean up: remove test admin user
        admin = User.query.filter_by(username=self.test_username).first()
        if admin:
            db.session.delete(admin)
            db.session.commit()

    def run_script_with_env(self, env_vars):
        """Helper to run the script with given env vars and capture output."""
        old_env = os.environ.copy()
        try:
            os.environ.update(env_vars)
            # Capture stdout
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            exit_code = 0
            try:
                try:
                    main()
                except SystemExit as e:
                    exit_code = e.code if e.code is not None else 0
            finally:
                output = sys.stdout.getvalue()
                sys.stdout = old_stdout
            # Restore environment
            os.environ.clear()
            os.environ.update(old_env)
            return output, exit_code
        finally:
            os.environ.clear()
            os.environ.update(old_env)

    def test_missing_admin_password_reset_env(self):
        """Test: script fails when ADMIN_PASSWORD_RESET is not defined."""
        output, exit_code = self.run_script_with_env({})
        # Should exit with code 1
        self.assertEqual(exit_code, 1)
        self.assertNotIn("Sucesso", output)
        # Script outputs in Portuguese: "falha: variavel de ambiente admin_password_reset nao definida ou vazia."
        self.assertIn("variavel de ambiente admin_password_reset", output.lower())

    def test_empty_password_reset_env(self):
        """Test: script fails when ADMIN_PASSWORD_RESET is empty string."""
        output, exit_code = self.run_script_with_env({"ADMIN_PASSWORD_RESET": ""})
        # Should exit with code 1
        self.assertEqual(exit_code, 1)
        self.assertNotIn("Sucesso", output)
        self.assertIn("vazia", output.lower())  # "vazia" is Portuguese for "empty"

    def test_admin_not_found(self):
        """Test: script fails safely when admin user does not exist."""
        with self.app.app_context():
            # Remove the admin user by deleting it
            admin = User.query.filter_by(username=self.test_username).first()
            if admin:
                db.session.delete(admin)
                db.session.commit()

            output, exit_code = self.run_script_with_env({"ADMIN_PASSWORD_RESET": "new_secure_pass"})
            # Should exit with code 1
            self.assertEqual(exit_code, 1)
            self.assertNotIn("Sucesso", output)
            self.assertIn("nao encontrado", output.lower())

    def test_successful_password_reset(self):
        """Test: script successfully resets the admin password."""
        with self.app.app_context():
            output, exit_code = self.run_script_with_env({"ADMIN_PASSWORD_RESET": "new_secure_pass"})
            # Should exit with code 0
            self.assertEqual(exit_code, 0)
            # Should print success
            self.assertIn("Sucesso", output)
            self.assertIn("senha do administrador", output.lower())

            # Verify the old password no longer works (within app context)
            with self.app.app_context():
                admin = User.query.get(self.admin_id)
                self.assertFalse(admin.check_password("old_password_123"))

                # Verify the new password works (within app context)
                self.assertTrue(admin.check_password("new_secure_pass"))

    def test_only_admin_password_changes(self):
        """Test: only the admin password hash is updated, other fields unchanged."""
        with self.app.app_context():
            output, exit_code = self.run_script_with_env({"ADMIN_PASSWORD_RESET": "new_secure_pass"})
            # Should exit with code 0
            self.assertEqual(exit_code, 0)

            # Verify other fields remain unchanged (within app context)
            with self.app.app_context():
                admin = User.query.get(self.admin_id)
                self.assertEqual(admin.username, self.test_username)
                self.assertEqual(admin.role, "admin")

                # Verify the new password works, old doesn't
                self.assertTrue(admin.check_password("new_secure_pass"))
                self.assertFalse(admin.check_password("old_password_123"))

    def test_role_other_fields_remain_unchanged(self):
        """Test: role and other fields are not modified."""
        with self.app.app_context():
            output, exit_code = self.run_script_with_env({"ADMIN_PASSWORD_RESET": "new_secure_pass"})
            # Should exit with code 0
            self.assertEqual(exit_code, 0)

            # Verify within app context
            with self.app.app_context():
                admin = User.query.get(self.admin_id)
                # Role should still be "admin"
                self.assertEqual(admin.role, "admin")
                # Username should still be the test username
                self.assertEqual(admin.username, self.test_username)
                # created_at should be preserved
                self.assertIsNotNone(admin.created_at)

    def test_check_password_hash_passes_afterward(self):
        """Test: check_password_hash() passes with new password after reset."""
        with self.app.app_context():
            output, exit_code = self.run_script_with_env({"ADMIN_PASSWORD_RESET": "verified_password"})
            # Should exit with code 0
            self.assertEqual(exit_code, 0)

            # Verify within app context
            with self.app.app_context():
                admin = User.query.get(self.admin_id)
                # The internal verification in the script should have passed
                # Now we verify independently
                self.assertTrue(admin.check_password("verified_password"))

    def test_no_password_hash_leakage_in_output(self):
        """Test: no password or hash is printed in output."""
        with self.app.app_context():
            output, exit_code = self.run_script_with_env({"ADMIN_PASSWORD_RESET": "secret_password"})
            # Should exit with code 0
            self.assertEqual(exit_code, 0)

            # Should not contain the new password
            self.assertNotIn("secret_password", output)
            # Should not contain any hash-like string (werkzeug hashes start with $)
            self.assertNotRegex(output, r'\$[2-9]\$')
            # Should not contain the old password either
            self.assertNotIn("old_password_123", output)


if __name__ == "__main__":
    unittest.main()