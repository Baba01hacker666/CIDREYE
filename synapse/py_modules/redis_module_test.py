import unittest
from unittest.mock import patch, MagicMock
from py_modules.redis_module import run

class RedisModuleTests(unittest.TestCase):
    def test_run_wrong_port(self):
        result = run("127.0.0.1", 80)
        self.assertIsNone(result)

    @patch("py_modules.redis_module.socket.create_connection")
    def test_run_vulnerable(self, mock_create_connection):
        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"+PONG\r\n"
        mock_create_connection.return_value.__enter__.return_value = mock_socket

        result = run("127.0.0.1", 6379)
        self.assertEqual(result, "[HIGH] Redis responds to unauthenticated PING on 127.0.0.1:6379")
        mock_socket.sendall.assert_called_once_with(b"PING\r\n")

    @patch("py_modules.redis_module.socket.create_connection")
    def test_run_not_vulnerable(self, mock_create_connection):
        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"-NOAUTH Authentication required.\r\n"
        mock_create_connection.return_value.__enter__.return_value = mock_socket

        result = run("127.0.0.1", 6379)
        self.assertIsNone(result)

    @patch("py_modules.redis_module.socket.create_connection")
    def test_run_os_error(self, mock_create_connection):
        mock_create_connection.side_effect = OSError("Connection refused")

        result = run("127.0.0.1", 6379)
        self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main()
