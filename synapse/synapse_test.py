import importlib
import unittest
from unittest import mock


class SynapseConfigTests(unittest.TestCase):
    def setUp(self):
        if importlib.util.find_spec("yaml") is None:
            self.skipTest("pyyaml not installed in environment")
        self.synapse = importlib.import_module("synapse")

    def test_load_config_file_not_found(self):
        with mock.patch("synapse.os.path.exists", return_value=False):
            self.assertEqual(self.synapse.load_config("missing.yaml"), {})

    def test_load_config_valid_yaml(self):
        with mock.patch("synapse.os.path.exists", return_value=True):
            with mock.patch(
                "builtins.open", mock.mock_open(read_data="foo: bar\nnum: 42")
            ):
                self.assertEqual(
                    self.synapse.load_config("valid.yaml"), {"foo": "bar", "num": 42}
                )

    def test_load_config_empty_yaml(self):
        with mock.patch("synapse.os.path.exists", return_value=True):
            with mock.patch("builtins.open", mock.mock_open(read_data="")):
                self.assertEqual(self.synapse.load_config("empty.yaml"), {})

    def test_has_web_ports_detects_http_https_and_common_alts(self):
        self.assertTrue(self.synapse._has_web_ports("80"))
        self.assertTrue(self.synapse._has_web_ports("443"))
        self.assertTrue(self.synapse._has_web_ports("8080"))
        self.assertTrue(self.synapse._has_web_ports("3000"))
        self.assertTrue(self.synapse._has_web_ports("1-1024"))
        self.assertFalse(self.synapse._has_web_ports("22,3306,5432"))

    def test_has_web_ports_handles_value_error(self):
        self.assertFalse(self.synapse._has_web_ports("abc"))
        self.assertFalse(self.synapse._has_web_ports("22,abc,3306"))
        self.assertFalse(self.synapse._has_web_ports("80-abc"))
        self.assertFalse(self.synapse._has_web_ports("abc-80"))
        self.assertFalse(self.synapse._has_web_ports("abc-def"))

    def test_config_has_nuclei_tags(self):
        self.assertTrue(
            self.synapse._config_has_nuclei_tags({"nuclei_tags": "cve,rce"})
        )
        self.assertTrue(
            self.synapse._config_has_nuclei_tags({"nuclei": {"tags": "xss"}})
        )
        self.assertFalse(self.synapse._config_has_nuclei_tags({}))

    def test_resolve_auto_cve_tag_preserves_default_enabled_behavior(self):
        self.assertTrue(self.synapse._resolve_auto_cve_tag({}))
        self.assertTrue(
            self.synapse._resolve_auto_cve_tag({"auto_cve_tag_for_http": True})
        )
        self.assertFalse(
            self.synapse._resolve_auto_cve_tag({"auto_cve_tag_for_http": False})
        )

    def test_resolve_auto_cve_tag_prefers_web_key_when_present(self):
        self.assertFalse(
            self.synapse._resolve_auto_cve_tag(
                {"auto_cve_tag_for_web": False, "auto_cve_tag_for_http": True}
            )
        )
        self.assertTrue(
            self.synapse._resolve_auto_cve_tag(
                {"auto_cve_tag_for_web": True, "auto_cve_tag_for_http": False}
            )
        )

    def test_send_telegram_skips_empty_message(self):
        with mock.patch("synapse.urllib.request.urlopen") as urlopen_mock:
            ok = self.synapse.send_telegram("token", "chat", "   ")
            self.assertTrue(ok)
            urlopen_mock.assert_not_called()

    def test_resolve_binary_path_uses_first_executable_candidate(self):
        with mock.patch("synapse.os.path.isfile", return_value=True), mock.patch(
            "synapse.os.access", return_value=True
        ):
            self.assertEqual(
                self.synapse.resolve_binary_path("/tmp/synapse"), "/tmp/synapse"
            )

    def test_resolve_binary_path_returns_none_when_missing(self):
        with mock.patch("synapse.os.path.isfile", return_value=False):
            self.assertIsNone(self.synapse.resolve_binary_path("/tmp/missing"))

    def test_run_synapse_does_not_append_cve_when_cli_tags_present(self):
        with mock.patch("synapse.subprocess.run") as run_mock, mock.patch(
            "synapse.os.path.exists", return_value=False
        ):
            run_mock.return_value.returncode = 0
            config = self.synapse.RunConfig(
                binary_path="/bin/syn",
                target="127.0.0.1",
                ports="80",
                extra_args=["--nuclei-tags", "rce"],
            )
            self.synapse.run_synapse(config)
            cmd = run_mock.call_args[0][0]
            self.assertEqual(cmd.count("--nuclei-tags"), 1)


if __name__ == "__main__":
    unittest.main()
