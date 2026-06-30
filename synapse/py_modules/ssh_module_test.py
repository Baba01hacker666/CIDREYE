import sys
import unittest
from unittest.mock import MagicMock, patch

# Inject a mock for paramiko before importing ssh_module
mock_paramiko = MagicMock()


class AuthenticationException(Exception):
    pass


mock_paramiko.AuthenticationException = AuthenticationException
sys.modules["paramiko"] = mock_paramiko

from py_modules import ssh_module


class TestSSHModule(unittest.TestCase):
    def setUp(self):
        self._orig_ssh_available = ssh_module.SSH_AVAILABLE
        ssh_module.SSH_AVAILABLE = True

    def tearDown(self):
        ssh_module.SSH_AVAILABLE = self._orig_ssh_available

    # ── run() edge cases ────────────────────────────────────────────

    def test_run_ssh_unavailable(self):
        ssh_module.SSH_AVAILABLE = False
        result = ssh_module.run("127.0.0.1", 22, credentials=[("admin", "admin")])
        self.assertIsNone(result)

    def test_run_incorrect_port(self):
        result = ssh_module.run("127.0.0.1", 2222, credentials=[("admin", "admin")])
        self.assertIsNone(result)

    def test_run_empty_credentials(self):
        result = ssh_module.run("127.0.0.1", 22)
        self.assertIsNone(result)
        result = ssh_module.run("127.0.0.1", 22, credentials=[])
        self.assertIsNone(result)

    # ── _attempt_login success ──────────────────────────────────────

    @patch("py_modules.ssh_module.paramiko.SSHClient")
    def test_attempt_login_success(self, mock_sshclient_class):
        mock_client = MagicMock()
        mock_sshclient_class.return_value = mock_client
        mock_client.connect.return_value = None

        success, msg = ssh_module._attempt_login("127.0.0.1", 22, "admin", "admin")

        self.assertTrue(success)
        self.assertIn("[CRITICAL] Default SSH credentials (admin:admin)", msg)
        self.assertIn("127.0.0.1", msg)
        mock_client.connect.assert_called_once_with(
            "127.0.0.1", port=22, username="admin", password="admin",
            timeout=3, allow_agent=False, look_for_keys=False
        )
        mock_client.close.assert_called_once()

    # ── _attempt_login failures ─────────────────────────────────────

    @patch("py_modules.ssh_module.paramiko.SSHClient")
    def test_attempt_login_auth_exception(self, mock_sshclient_class):
        mock_client = MagicMock()
        mock_sshclient_class.return_value = mock_client
        mock_client.connect.side_effect = AuthenticationException("Failed")

        success, msg = ssh_module._attempt_login("127.0.0.1", 22, "admin", "admin")

        self.assertFalse(success)
        self.assertIsNone(msg)

    @patch("py_modules.ssh_module.paramiko.SSHClient")
    def test_attempt_login_general_exception(self, mock_sshclient_class):
        mock_client = MagicMock()
        mock_sshclient_class.return_value = mock_client
        mock_client.connect.side_effect = Exception("Timeout")

        success, msg = ssh_module._attempt_login("127.0.0.1", 22, "admin", "admin")

        self.assertIsNone(success)
        self.assertIsNone(msg)

    # ── run() with patched _attempt_login ───────────────────────────

    @patch("py_modules.ssh_module._attempt_login")
    def test_run_with_successful_login(self, mock_attempt_login):
        mock_attempt_login.return_value = (
            True,
            "[CRITICAL] Default SSH credentials (admin:admin) found on 127.0.0.1",
        )

        result = ssh_module.run(
            "127.0.0.1", 22, credentials=[("admin", "admin")]
        )
        self.assertEqual(
            result,
            "[CRITICAL] Default SSH credentials (admin:admin) found on 127.0.0.1",
        )

    @patch("py_modules.ssh_module._attempt_login")
    def test_run_with_failed_logins(self, mock_attempt_login):
        mock_attempt_login.return_value = (False, None)

        result = ssh_module.run(
            "127.0.0.1", 22, credentials=[("admin", "admin"), ("root", "root")]
        )
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
