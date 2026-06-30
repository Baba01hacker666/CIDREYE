import unittest
from unittest.mock import patch, MagicMock
from py_modules.http_module import run


class HttpModuleTests(unittest.TestCase):
    def test_run_ignored_port(self):
        result = run("127.0.0.1", 22)
        self.assertIsNone(result)

    @patch("py_modules.http_module.socket.create_connection")
    def test_run_http_success(self, mock_create_connection):
        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
        mock_create_connection.return_value.__enter__.return_value = mock_socket

        result = run("127.0.0.1", 80)

        self.assertEqual(result, "[INFO] HTTP service responded on 127.0.0.1:80")
        mock_socket.sendall.assert_called_once_with(
            b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"
        )

    @patch("py_modules.http_module.socket.create_connection")
    def test_run_http_fail_no_http_string(self, mock_create_connection):
        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"Some random data"
        mock_create_connection.return_value.__enter__.return_value = mock_socket

        result = run("127.0.0.1", 8080)

        self.assertIsNone(result)

    @patch("py_modules.http_module.socket.create_connection")
    def test_run_https_success(self, mock_create_connection):
        mock_socket = MagicMock()
        mock_create_connection.return_value.__enter__.return_value = mock_socket

        result = run("127.0.0.1", 443)

        self.assertEqual(result, "[INFO] HTTPS service appears open on 127.0.0.1:443")
        mock_socket.sendall.assert_not_called()

    @patch("py_modules.http_module.socket.create_connection")
    def test_run_os_error(self, mock_create_connection):
        mock_create_connection.side_effect = OSError("Connection refused")

        result = run("127.0.0.1", 80)

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
