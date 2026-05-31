import unittest
from unittest.mock import MagicMock, patch
import sys

# Mock smbclient before importing the module
mock_smbclient = MagicMock()
sys.modules["smbclient"] = mock_smbclient

# Now we can import the module
from py_modules import smb_module


class TestSMBModule(unittest.TestCase):
    def setUp(self):
        # Reset mocks before each test
        mock_smbclient.reset_mock()
        # Reset side effect
        mock_smbclient.list_shares.side_effect = None
        # Ensure SMB is marked as available for most tests
        smb_module.SMB_AVAILABLE = True

    def test_smb_not_available(self):
        smb_module.SMB_AVAILABLE = False
        result = smb_module.run("127.0.0.1", 445)
        self.assertIsNone(result)

    def test_invalid_port(self):
        result = smb_module.run("127.0.0.1", 80)
        self.assertIsNone(result)

    def test_successful_anonymous_shares(self):
        # Setup mock shares
        class MockShare:
            def __init__(self, name):
                self.name = name

        mock_smbclient.list_shares.return_value = [
            MockShare("IPC$"),
            MockShare("Public"),
        ]

        result = smb_module.run("127.0.0.1", 445)

        mock_smbclient.ClientConfig.assert_called_with(username="guest", password="")
        mock_smbclient.list_shares.assert_called_with("127.0.0.1", port=445, timeout=5)
        self.assertEqual(
            result, "[HIGH] Anonymous SMB shares found on 127.0.0.1: IPC$, Public"
        )

    def test_no_shares_found(self):
        mock_smbclient.list_shares.return_value = []

        result = smb_module.run("127.0.0.1", 445)
        self.assertIsNone(result)

    def test_exception_handled(self):
        mock_smbclient.list_shares.side_effect = Exception("Connection failed")

        result = smb_module.run("127.0.0.1", 445)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
