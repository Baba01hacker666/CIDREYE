import unittest
from unittest.mock import patch, MagicMock

from py_modules.service_detect_module import run

class ServiceDetectModuleTests(unittest.TestCase):
    @patch('py_modules.service_detect_module.socket.socket')
    def test_banner_grabbing_success(self, mock_socket):
        # Setup mock socket
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance
        mock_instance.recv.return_value = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"

        result = run("127.0.0.1", 22)

        # Verify socket operations
        mock_instance.connect.assert_called_once_with(("127.0.0.1", 22))
        mock_instance.sendall.assert_called_once()

        # Verify result
        self.assertEqual(result, "[INFO] Banner grab on 127.0.0.1:22 - SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")

    @patch('py_modules.service_detect_module.socket.socket')
    def test_banner_grabbing_long_banner(self, mock_socket):
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance
        # Banner longer than 50 chars
        mock_instance.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Length: 1234\r\n"

        result = run("127.0.0.1", 80)

        self.assertTrue(result.startswith("[INFO] Banner grab on 127.0.0.1:80 - HTTP/1.1 200 OK Server: Apache/2.4.41"))
        self.assertTrue(result.endswith("..."))

    @patch('py_modules.service_detect_module.socket.socket')
    def test_banner_grabbing_failure_fallback(self, mock_socket):
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance
        # Simulate connection failure (e.g. timeout)
        mock_instance.connect.side_effect = Exception("Connection refused")

        # 21 is in the SERVICE_BY_PORT dictionary (FTP)
        result = run("127.0.0.1", 21)

        self.assertEqual(result, "[INFO] FTP appears open on 127.0.0.1:21")

    @patch('py_modules.service_detect_module.socket.socket')
    def test_unknown_port_no_banner(self, mock_socket):
        mock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_instance
        # Simulate timeout on recv (empty banner)
        mock_instance.recv.return_value = b""

        # 9999 is not in the SERVICE_BY_PORT dictionary
        result = run("127.0.0.1", 9999)

        self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main()
