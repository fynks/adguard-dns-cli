import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agdns.api import AdGuardDNSClient, ApiError
from agdns.cli import main
from tests.mock_api import API_KEY, REQUESTS, MockServer


class CLITestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        os.environ["AGDNS_CONFIG_DIR"] = self.tmp.name
        os.environ.pop("AGDNS_API_KEY", None)
        self.server = MockServer()
        self.server.__enter__()
        self.addCleanup(self.server.__exit__, None, None, None)

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def set_key(self):
        self.run_cli("config", "set-key", API_KEY)
        # Point the CLI at the mock server.
        self.run_cli("config", "set-url", self.server.url)


class TestConfig(CLITestCase):
    def test_set_and_show_key(self):
        code, out, _ = self.run_cli("config", "set-key", "abc123")
        self.assertEqual(code, 0)
        self.assertIn("saved", out)

        code, out, _ = self.run_cli("config", "show", "--format", "json")
        data = json.loads(out)
        self.assertTrue(data["api_key_set"])
        self.assertEqual(data["api_key_source"], "file")

    def test_key_file_is_private(self):
        self.run_cli("config", "set-key", "abc123")
        path = Path(self.tmp.name) / "config.json"
        self.assertEqual(path.stat().st_mode & 0o077, 0)

    def test_clear_key(self):
        self.run_cli("config", "set-key", "abc123")
        self.run_cli("config", "clear-key")
        code, out, _ = self.run_cli("config", "show", "--format", "json")
        self.assertFalse(json.loads(out)["api_key_set"])

    def test_env_key_takes_precedence(self):
        os.environ["AGDNS_API_KEY"] = "from-env"
        code, out, _ = self.run_cli("config", "show", "--format", "json")
        self.assertEqual(json.loads(out)["api_key_source"], "environment")

    def test_missing_key_exits_with_message(self):
        code, _, err = self.run_cli("devices")
        self.assertEqual(code, 1)
        self.assertIn("No API key", err)

class TestDevices(CLITestCase):
    def test_list_devices(self):
        self.set_key()
        code, out, _ = self.run_cli("devices", "--format", "json")
        self.assertEqual(code, 0)
        items = json.loads(out)
        self.assertEqual(len(items), 5)
        self.assertEqual(items[0]["name"], "My Phone")

    def test_search_devices(self):
        self.set_key()
        code, out, _ = self.run_cli("devices", "--search", "tv", "--format", "json")
        items = json.loads(out)
        self.assertEqual([i["id"] for i in items], ["dev222"])


class TestBlocked(CLITestCase):
    def test_blocked_paginates_and_filters(self):
        self.set_key()
        code, out, _ = self.run_cli(
            "blocked", "My Phone", "--days", "30", "--format", "json"
        )
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["count"], 3)
        domains = [i["domain"] for i in data["items"]]
        self.assertEqual(domains, ["ads.example.com", "track.example.org", "banner.example.net"])
        self.assertEqual(data["devices"][0]["id"], "dev111")

    def test_blocked_table_output(self):
        self.set_key()
        code, out, _ = self.run_cli("blocked", "My Phone")
        self.assertEqual(code, 0)
        self.assertIn("ads.example.com", out)
        self.assertIn("DOMAIN", out)

    def test_blocked_csv_output(self):
        self.set_key()
        code, out, _ = self.run_cli("blocked", "My Phone", "--format", "csv")
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 4)
        self.assertTrue(lines[0].startswith("time_iso,"))

    def test_max_records(self):
        self.set_key()
        code, out, _ = self.run_cli(
            "blocked", "My Phone", "--max-records", "2", "--format", "json"
        )
        self.assertEqual(json.loads(out)["count"], 2)

    def test_summary(self):
        self.set_key()
        code, out, _ = self.run_cli("blocked", "My Phone", "--summary")
        self.assertIn("Summary by category", out)
        self.assertIn("Top domains", out)

    def test_unknown_device(self):
        self.set_key()
        code, _, err = self.run_cli("blocked", "Nonexistent")
        self.assertEqual(code, 1)
        self.assertIn("No device named", err)

    def test_ambiguous_device_name(self):
        self.set_key()
        code, _, err = self.run_cli("blocked", "Shared Device")
        self.assertEqual(code, 1)
        self.assertIn("Multiple devices match", err)

    def test_case_sensitive_name_prefers_exact_match(self):
        self.set_key()
        code, out, _ = self.run_cli("blocked", "my phone", "--format", "json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["devices"][0]["id"], "dev333")

    def test_device_id_can_be_used(self):
        self.set_key()
        code, out, _ = self.run_cli(
            "blocked", "dev111", "--format", "json"
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["count"], 3)

    def test_status_filter(self):
        self.set_key()
        code, out, _ = self.run_cli(
            "blocked", "My Phone", "--status", "REQUEST_BLOCKED", "--format", "json"
        )
        items = json.loads(out)["items"]
        self.assertTrue(all(i["filtering_info"]["filtering_status"] == "REQUEST_BLOCKED" for i in items))
        self.assertEqual(len(items), 2)


class TestClient(CLITestCase):
    def test_bad_api_key(self):
        with AdGuardDNSClient(api_key="wrong", api_url=self.server.url) as client:
            with self.assertRaises(ApiError) as ctx:
                client.list_devices()
        self.assertEqual(ctx.exception.status, 401)

    def test_resolve_device(self):
        with AdGuardDNSClient(api_key=API_KEY, api_url=self.server.url) as client:
            device = client.resolve_device("Living Room TV")
        self.assertEqual(device.id, "dev222")

    def test_device_list_is_fetched_once(self):
        """Resolving several devices must not re-fetch the device list."""
        with AdGuardDNSClient(api_key=API_KEY, api_url=self.server.url) as client:
            with mock.patch.object(
                AdGuardDNSClient, "_request", wraps=client._request
            ) as spy:
                client.resolve_device("My Phone")
                client.resolve_device("Living Room TV")
        paths = [c.args[0] for c in spy.call_args_list]
        self.assertEqual(paths.count("/oapi/v2/devices"), 1)

    def test_requests_use_gzip(self):
        """Responses must be requested compressed to cut bandwidth."""
        with AdGuardDNSClient(api_key=API_KEY, api_url=self.server.url) as client:
            client.list_devices()
        self.assertTrue(REQUESTS)
        self.assertIn("gzip", REQUESTS[-1]["accept_encoding"])

    def test_connection_is_reused(self):
        """A keep-alive connection must be shared across requests."""
        with AdGuardDNSClient(api_key=API_KEY, api_url=self.server.url) as client:
            conns = []
            original = client._transport.get

            def spy(path, headers):
                result = original(path, headers)
                conns.append(id(client._transport._conn))
                return result

            client._transport.get = spy
            client.list_devices()
            client.list_devices()
        self.assertEqual(len(conns), 2)
        self.assertEqual(len(set(conns)), 1)

    def test_page_size_capped_by_max_records(self):
        """The API must not be asked for more rows than are wanted."""
        with AdGuardDNSClient(api_key=API_KEY, api_url=self.server.url) as client:
            list(
                client.iter_query_log(
                    time_from_millis=0,
                    time_to_millis=1,
                    max_items=1,
                    limit=1000,
                )
            )
        log_req = [r for r in REQUESTS if r["path"] == "/oapi/v1/query_log"][-1]
        self.assertEqual(log_req["query"]["limit"], ["1"])

    def test_retry_after_header_is_honoured(self):
        """A 429 with Retry-After must pause instead of hammering."""
        from agdns.api import _retry_delay

        self.assertEqual(_retry_delay({"Retry-After": "3"}, 0), 3.0)
        self.assertEqual(_retry_delay({"retry-after": "2"}, 0), 2.0)
        self.assertEqual(_retry_delay({}, 0), 1.0)
        self.assertEqual(_retry_delay({"Retry-After": "999"}, 0), 60.0)
        self.assertEqual(_retry_delay({"Retry-After": "soon"}, 0), 1.0)


if __name__ == "__main__":
    unittest.main()
