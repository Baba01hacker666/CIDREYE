import unittest
from unittest.mock import patch, MagicMock

from py_modules.ftp_module import run


class FTPModuleTests(unittest.TestCase):
    def test_run_wrong_port(self):
        result = run("127.0.0.1", 22)
        self.assertIsNone(result)

    @patch("py_modules.ftp_module.ftplib.FTP")
    def test_run_success(self, mock_ftp_class):
        mock_ftp_instance = MagicMock()
        mock_ftp_class.return_value = mock_ftp_instance

        result = run("127.0.0.1", 21)
        self.assertEqual(result, "[CRITICAL] Anonymous FTP access allowed on 127.0.0.1")
        mock_ftp_instance.connect.assert_called_once_with("127.0.0.1", 21, timeout=5)
        mock_ftp_instance.login.assert_called_once()
        mock_ftp_instance.quit.assert_called_once()

    @patch("py_modules.ftp_module.ftplib.FTP")
    def test_run_exception_on_connect(self, mock_ftp_class):
        mock_ftp_instance = MagicMock()
        mock_ftp_instance.connect.side_effect = Exception("Connection failed")
        mock_ftp_class.return_value = mock_ftp_instance

        result = run("127.0.0.1", 21)
        self.assertIsNone(result)

    @patch("py_modules.ftp_module.ftplib.FTP")
    def test_run_exception_on_login(self, mock_ftp_class):
        mock_ftp_instance = MagicMock()
        mock_ftp_instance.login.side_effect = Exception("Login failed")
        mock_ftp_class.return_value = mock_ftp_instance

        result = run("127.0.0.1", 21)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
