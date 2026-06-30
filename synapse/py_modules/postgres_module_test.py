import unittest
from unittest.mock import patch, MagicMock

from py_modules import postgres_module

class PostgresModuleTests(unittest.TestCase):
    def test_wrong_port(self):
        result = postgres_module.run('127.0.0.1', 5433)
        self.assertIsNone(result)

    @patch('py_modules.postgres_module.socket.create_connection')
    def test_success_S(self, mock_create_connection):
        mock_socket = MagicMock()
        # mock socket as context manager
        mock_create_connection.return_value.__enter__.return_value = mock_socket
        mock_socket.recv.return_value = b'S'

        result = postgres_module.run('127.0.0.1', 5432)

        self.assertEqual(result, "[INFO] PostgreSQL server responded to SSLRequest on 127.0.0.1:5432")
        mock_create_connection.assert_called_once_with(('127.0.0.1', 5432), timeout=3)
        mock_socket.sendall.assert_called_once()
        mock_socket.recv.assert_called_once_with(1)

    @patch('py_modules.postgres_module.socket.create_connection')
    def test_success_N(self, mock_create_connection):
        mock_socket = MagicMock()
        mock_create_connection.return_value.__enter__.return_value = mock_socket
        mock_socket.recv.return_value = b'N'

        result = postgres_module.run('127.0.0.1', 5432)

        self.assertEqual(result, "[INFO] PostgreSQL server responded to SSLRequest on 127.0.0.1:5432")

    @patch('py_modules.postgres_module.socket.create_connection')
    def test_invalid_response(self, mock_create_connection):
        mock_socket = MagicMock()
        mock_create_connection.return_value.__enter__.return_value = mock_socket
        mock_socket.recv.return_value = b'X'

        result = postgres_module.run('127.0.0.1', 5432)

        self.assertIsNone(result)

    @patch('py_modules.postgres_module.socket.create_connection')
    def test_connection_exception(self, mock_create_connection):
        mock_create_connection.side_effect = Exception("Connection refused")

        result = postgres_module.run('127.0.0.1', 5432)

        self.assertIsNone(result)

if __name__ == '__main__':
    unittest.main()
