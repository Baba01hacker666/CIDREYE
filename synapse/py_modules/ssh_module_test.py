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
        # Ensure SSH_AVAILABLE is True for general testing
        self._orig_ssh_available = ssh_module.SSH_AVAILABLE
        ssh_module.SSH_AVAILABLE = True

    def tearDown(self):
        ssh_module.SSH_AVAILABLE = self._orig_ssh_available

    def test_run_ssh_unavailable(self):
        ssh_module.SSH_AVAILABLE = False
        result = ssh_module.run("192.168.1.1", 22, credentials=[("user", "pass")])
        self.assertIsNone(result)

    def test_run_incorrect_port(self):
        result = ssh_module.run("192.168.1.1", 2222, credentials=[("user", "pass")])
        self.assertIsNone(result)

    def test_run_empty_credentials(self):
        result = ssh_module.run("192.168.1.1", 22, credentials=[])
        self.assertIsNone(result)

    @patch("py_modules.ssh_module.paramiko.SSHClient")
    def test_attempt_login_success(self, mock_sshclient_class):
        mock_client = MagicMock()
        mock_sshclient_class.return_value = mock_client
        mock_client.connect.return_value = None

        success, msg = ssh_module._attempt_login("192.168.1.1", 22, "admin", "admin")

        self.assertTrue(success)
        self.assertIn("admin:admin", msg)
        self.assertIn("192.168.1.1", msg)
        mock_client.connect.assert_called_once()
        mock_client.close.assert_called_once()

    @patch("py_modules.ssh_module.paramiko.SSHClient")
    def test_attempt_login_auth_exception(self, mock_sshclient_class):
        mock_client = MagicMock()
        mock_sshclient_class.return_value = mock_client
        mock_client.connect.side_effect = ssh_module.paramiko.AuthenticationException(
            "Failed"
        )

        success, msg = ssh_module._attempt_login("192.168.1.1", 22, "admin", "admin")

        self.assertFalse(success)
        self.assertIsNone(msg)

    @patch("py_modules.ssh_module.paramiko.SSHClient")
    def test_attempt_login_general_exception(self, mock_sshclient_class):
        mock_client = MagicMock()
        mock_sshclient_class.return_value = mock_client
        mock_client.connect.side_effect = Exception("Timeout")

        success, msg = ssh_module._attempt_login("192.168.1.1", 22, "admin", "admin")

        self.assertIsNone(success)
        self.assertIsNone(msg)

    @patch("py_modules.ssh_module._attempt_login")
    def test_run_with_successful_login(self, mock_attempt_login):
        # Provide one successful login
        mock_attempt_login.return_value = (True, "Found admin:admin")

        result = ssh_module.run("192.168.1.1", 22, credentials=[("admin", "admin")])
        self.assertEqual(result, "Found admin:admin")

    @patch("py_modules.ssh_module._attempt_login")
    def test_run_with_failed_logins(self, mock_attempt_login):
        # Provide failed login
        mock_attempt_login.return_value = (False, None)

        result = ssh_module.run(
            "192.168.1.1", 22, credentials=[("admin", "admin"), ("root", "root")]
        )
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
