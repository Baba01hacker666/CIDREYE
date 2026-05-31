import sys
import unittest
from unittest.mock import MagicMock, patch

# Inject mock paramiko
mock_paramiko = MagicMock()
sys.modules['paramiko'] = mock_paramiko

class MockAuthException(Exception):
    pass
mock_paramiko.AuthenticationException = MockAuthException

from py_modules import ssh_module

class TestSSHModule(unittest.TestCase):
    def setUp(self):
        mock_paramiko.reset_mock()
        ssh_module.SSH_AVAILABLE = True

    def test_attempt_login_success(self):
        mock_client_instance = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client_instance

        success, result = ssh_module._attempt_login("127.0.0.1", 22, "admin", "admin")

        self.assertTrue(success)
        self.assertEqual(result, "[CRITICAL] Default SSH credentials (admin:admin) found on 127.0.0.1")
        mock_client_instance.connect.assert_called_once_with(
            "127.0.0.1", port=22, username="admin", password="admin",
            timeout=3, allow_agent=False, look_for_keys=False
        )
        mock_client_instance.close.assert_called_once()

    def test_attempt_login_authentication_exception(self):
        mock_client_instance = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client_instance
        mock_client_instance.connect.side_effect = MockAuthException()

        success, result = ssh_module._attempt_login("127.0.0.1", 22, "admin", "admin")

        self.assertFalse(success)
        self.assertIsNone(result)

    def test_attempt_login_other_exception(self):
        mock_client_instance = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client_instance
        mock_client_instance.connect.side_effect = Exception("Some other error")

        success, result = ssh_module._attempt_login("127.0.0.1", 22, "admin", "admin")

        self.assertIsNone(success)
        self.assertIsNone(result)

    def test_run_ssh_not_available(self):
        ssh_module.SSH_AVAILABLE = False
        result = ssh_module.run("127.0.0.1", 22, credentials=[("admin", "admin")])
        self.assertIsNone(result)

    def test_run_wrong_port(self):
        result = ssh_module.run("127.0.0.1", 2222, credentials=[("admin", "admin")])
        self.assertIsNone(result)

    def test_run_no_credentials(self):
        result = ssh_module.run("127.0.0.1", 22)
        self.assertIsNone(result)
        result = ssh_module.run("127.0.0.1", 22, credentials=[])
        self.assertIsNone(result)

    @patch("py_modules.ssh_module._attempt_login")
    def test_run_success(self, mock_attempt_login):
        mock_attempt_login.return_value = (True, "[CRITICAL] Default SSH credentials (admin:admin) found on 127.0.0.1")

        creds = [("admin", "admin")]
        result = ssh_module.run("127.0.0.1", 22, credentials=creds)
        self.assertEqual(result, "[CRITICAL] Default SSH credentials (admin:admin) found on 127.0.0.1")

    @patch("py_modules.ssh_module._attempt_login")
    def test_run_all_fail(self, mock_attempt_login):
        mock_attempt_login.return_value = (False, None)
        creds = [("admin", "admin"), ("root", "root")]

        result = ssh_module.run("127.0.0.1", 22, credentials=creds)
        self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main()
