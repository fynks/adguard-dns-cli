"""Mock AdGuard DNS API server used by the test suite."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

API_KEY = "test-api-key"

DEVICES = [
    {
        "id": "dev111",
        "name": "My Phone",
        "dns_server_id": "srv1",
        "device_type": "phone",
        "dns_addresses": {},
        "settings": {},
    },
    {
        "id": "dev222",
        "name": "Living Room TV",
        "dns_server_id": "srv1",
        "device_type": "tv",
        "dns_addresses": {},
        "settings": {},
    },
    {
        "id": "dev333",
        "name": "my phone",
        "dns_server_id": "srv1",
        "device_type": "tablet",
        "dns_addresses": {},
        "settings": {},
    },
    {
        "id": "dev444",
        "name": "Shared Device",
        "dns_server_id": "srv1",
        "device_type": "phone",
        "dns_addresses": {},
        "settings": {},
    },
    {
        "id": "dev555",
        "name": "Shared Device",
        "dns_server_id": "srv1",
        "device_type": "phone",
        "dns_addresses": {},
        "settings": {},
    },
]


def _item(domain: str, device_id: str, millis: int, status: str, category: str = "ADS"):
    return {
        "time_millis": millis,
        "time_iso": "2024-05-01T10:00:00Z",
        "domain": domain,
        "device_id": device_id,
        "dns_server_id": "srv1",
        "category_type": category,
        "company_id": "example",
        "dnssec": False,
        "filtering_info": {
            "filtering_status": status,
            "filtering_type": "FILTER_LIST",
            "filter_id": "adguard_dns_filter",
            "filter_rule": f"||{domain}^",
        },
    }


# Two pages of query log entries.
PAGE_ONE = [
    _item("ads.example.com", "dev111", 1714560000000, "REQUEST_BLOCKED"),
    _item("track.example.org", "dev111", 1714563600000, "RESPONSE_BLOCKED"),
]
PAGE_TWO = [
    _item("banner.example.net", "dev111", 1714567200000, "REQUEST_BLOCKED"),
]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence the server
        pass

    def _send(self, status: int, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if self.headers.get("Authorization") != f"ApiKey {API_KEY}":
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if parsed.path == "/oapi/v2/devices":
            search = (query.get("search") or [None])[0]
            items = DEVICES
            if search:
                needle = search.lower()
                items = [d for d in items if needle in d["name"].lower() or d["id"] == search]
            self._send(200, {"items": items, "navigation": {}})
            return

        if parsed.path == "/oapi/v1/query_log":
            cursor = (query.get("cursor") or [None])[0]
            devices = query.get("devices") or []
            statuses = query.get("statuses") or []

            if cursor is None:
                items = PAGE_ONE
                pages = [
                    {"current": True, "page_cursor": "c1", "page_number": 1},
                    {"current": False, "page_cursor": "c2", "page_number": 2},
                ]
            elif cursor == "c2":
                items = PAGE_TWO
                pages = [
                    {"current": True, "page_cursor": "c2", "page_number": 2},
                ]
            else:
                items = []
                pages = []

            if devices:
                items = [i for i in items if i["device_id"] in devices]
            if statuses:
                items = [i for i in items if i["filtering_info"]["filtering_status"] in statuses]

            self._send(200, {"items": items, "pages": pages})
            return

        self._send(404, {"message": "not found"})


class MockServer:
    def __init__(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "MockServer":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
