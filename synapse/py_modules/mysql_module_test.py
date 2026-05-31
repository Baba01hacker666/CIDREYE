import unittest
from unittest.mock import patch, MagicMock
from py_modules.mysql_module import run


class MySQLModuleTests(unittest.TestCase):
    def test_run_wrong_port(self):
        result = run("127.0.0.1", 8080)
        self.assertIsNone(result)

    @patch("py_modules.mysql_module.socket.create_connection")
    def test_run_success(self, mock_create_connection):
        mock_socket = MagicMock()
        mock_socket.__enter__.return_value = mock_socket
        mock_socket.recv.return_value = b"5.7.35-log"
        mock_create_connection.return_value = mock_socket

        result = run("127.0.0.1", 3306)
        self.assertEqual(
            result, "[INFO] MySQL/MariaDB handshake exposed on 127.0.0.1:3306"
        )
        mock_create_connection.assert_called_once_with(("127.0.0.1", 3306), timeout=3)
        mock_socket.recv.assert_called_once_with(256)

    @patch("py_modules.mysql_module.socket.create_connection")
    def test_run_no_banner(self, mock_create_connection):
        mock_socket = MagicMock()
        mock_socket.__enter__.return_value = mock_socket
        mock_socket.recv.return_value = b""
        mock_create_connection.return_value = mock_socket

        result = run("127.0.0.1", 3306)
        self.assertIsNone(result)

    @patch("py_modules.mysql_module.socket.create_connection")
    def test_run_exception(self, mock_create_connection):
        mock_create_connection.side_effect = Exception("Connection Refused")

        result = run("127.0.0.1", 3306)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
