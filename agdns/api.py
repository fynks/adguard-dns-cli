"""Thin client for the AdGuard DNS API (https://api.adguard-dns.io).

Only the endpoints needed by this CLI are implemented:

- ``GET /oapi/v2/devices``   -- list / search devices by name or ID.
- ``GET /oapi/v1/query_log`` -- fetch query log entries for a time range.
"""

from __future__ import annotations

import gzip
import http.client
import json
import time
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Iterator

DEFAULT_TIMEOUT = 60.0
DEFAULT_PAGE_LIMIT = 1000

# Filtering statuses reported by the API.
STATUS_REQUEST_BLOCKED = "REQUEST_BLOCKED"
STATUS_RESPONSE_BLOCKED = "RESPONSE_BLOCKED"
BLOCKED_STATUSES = (STATUS_REQUEST_BLOCKED, STATUS_RESPONSE_BLOCKED)


class ApiError(RuntimeError):
    """Raised when the API returns an error response."""

    def __init__(self, status: int, message: str, body: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.body = body


@dataclass
class Device:
    """A device known to the AdGuard DNS account."""

    id: str
    name: str
    dns_server_id: str = ""
    device_type: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Device:
        return cls(
            id=str(data.get("id", "")),
            name=str(data.get("name", "")),
            dns_server_id=str(data.get("dns_server_id", "")),
            device_type=str(data.get("device_type", "")),
            raw=data,
        )


@dataclass
class QueryLogItem:
    """A single query log entry."""

    time_millis: int
    time_iso: str
    domain: str
    device_id: str
    dns_server_id: str
    category_type: str
    company_id: str
    filtering_status: str
    filtering_type: str
    filter_id: str
    filter_rule: str
    filtering_category_id: str
    blocked_service_id: str
    client_country: str
    response_country: str
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> QueryLogItem:
        info = data.get("filtering_info") or {}
        return cls(
            time_millis=int(data.get("time_millis") or 0),
            time_iso=str(data.get("time_iso") or ""),
            domain=str(data.get("domain") or ""),
            device_id=str(data.get("device_id") or ""),
            dns_server_id=str(data.get("dns_server_id") or ""),
            category_type=str(data.get("category_type") or ""),
            company_id=str(data.get("company_id") or ""),
            filtering_status=str(info.get("filtering_status") or ""),
            filtering_type=str(info.get("filtering_type") or ""),
            filter_id=str(info.get("filter_id") or ""),
            filter_rule=str(info.get("filter_rule") or ""),
            filtering_category_id=str(info.get("filtering_category_id") or ""),
            blocked_service_id=str(info.get("blocked_service_id") or ""),
            client_country=str(data.get("client_country") or ""),
            response_country=str(data.get("response_country") or ""),
            raw=data,
        )


def _retry_delay(headers: dict[str, str], attempt: int) -> float:
    """Back-off delay before retrying, honouring ``Retry-After`` if sent."""
    retry_after = headers.get("Retry-After") or headers.get("retry-after")
    if retry_after:
        try:
            return min(float(retry_after), 60.0)
        except ValueError:
            pass
    return min(2**attempt, 8)


def _next_page_cursor(pages: list[dict[str, Any]]) -> str | None:
    """Pick the cursor of the page following the current one.

    The API returns a list of page descriptors, each with a page number and a
    cursor.  The descriptor flagged as ``current`` is the page that was just
    served, so the cursor of the next page number is the one to follow.
    """
    if not pages:
        return None

    current_number: int | None = None
    for page in pages:
        if page.get("current"):
            current_number = int(page.get("page_number") or 0)
            break

    if current_number is not None:
        for page in pages:
            if int(page.get("page_number") or 0) == current_number + 1:
                cursor = page.get("page_cursor")
                return str(cursor) if cursor else None
        return None

    # No page flagged as current: fall back to the last descriptor.
    last = pages[-1]
    cursor = last.get("page_cursor")
    return str(cursor) if cursor else None


class _Transport:
    """HTTP transport that reuses one connection and negotiates gzip.

    A fresh TLS handshake per request is expensive when pulling a long query
    log, and the JSON payloads compress by roughly 20x.  This keeps a single
    connection alive across requests and asks the server for gzip.
    """

    def __init__(self, base_url: str, timeout: float) -> None:
        parts = urllib.parse.urlsplit(base_url)
        self.scheme = parts.scheme or "https"
        self.host = parts.hostname or "api.adguard-dns.io"
        self.port = parts.port
        self.prefix = parts.path.rstrip("/")
        self.timeout = timeout
        self._conn: http.client.HTTPConnection | None = None

    def _connection(self) -> http.client.HTTPConnection:
        if self._conn is None:
            if self.scheme == "https":
                self._conn = http.client.HTTPSConnection(
                    self.host, self.port, timeout=self.timeout
                )
            else:
                self._conn = http.client.HTTPConnection(
                    self.host, self.port, timeout=self.timeout
                )
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def get(self, path: str, headers: dict[str, str]) -> tuple[int, bytes, dict[str, str]]:
        """Perform a GET request, returning the status code, body and headers.

        Retries once on a dropped keep-alive connection, since the server may
        close an idle connection between requests.
        """
        target = f"{self.prefix}{path}"
        last_exc: Exception | None = None
        for attempt in range(2):
            conn = self._connection()
            try:
                conn.request("GET", target, headers=headers)
                response = conn.getresponse()
                body = response.read()
                if response.getheader("Content-Encoding", "").lower() == "gzip":
                    body = gzip.decompress(body)
                return response.status, body, dict(response.getheaders())
            except (http.client.HTTPException, OSError) as exc:
                # The pooled connection may have been closed by the server.
                self.close()
                last_exc = exc
                if attempt == 0:
                    continue
                raise urllib.error.URLError(last_exc) from exc
        raise urllib.error.URLError(last_exc)


class AdGuardDNSClient:
    """Minimal AdGuard DNS API client."""

    def __init__(
        self,
        api_key: str,
        api_url: str = "https://api.adguard-dns.io",
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = 3,
        account_id: int | None = None,
    ) -> None:
        self.api_key = api_key
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout
        self.retries = max(1, retries)
        self.account_id = account_id
        self._transport = _Transport(self.api_url, timeout)
        self._devices_cache: list[Device] | None = None

    def close(self) -> None:
        self._transport.close()

    def __enter__(self) -> "AdGuardDNSClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- plumbing ---------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"ApiKey {self.api_key}",
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "Connection": "keep-alive",
            "User-Agent": "agdns-cli/1.0",
        }
        if self.account_id is not None:
            headers["X-Account-Id"] = str(self.account_id)
        return headers

    def _request(self, path: str, params: dict[str, Any] | None = None) -> Any:
        if params:
            # ``None`` values are skipped, lists are repeated (Go style).
            pairs: list[tuple[str, str]] = []
            for key, value in params.items():
                if value is None:
                    continue
                if isinstance(value, (list, tuple, set)):
                    for item in value:
                        pairs.append((key, str(item)))
                else:
                    pairs.append((key, str(value)))
            query = urllib.parse.urlencode(pairs)
            if query:
                path = f"{path}?{query}"

        last_error: Exception | None = None
        for attempt in range(self.retries):
            try:
                status, raw, resp_headers = self._transport.get(path, self._headers())
            except urllib.error.URLError as exc:
                last_error = exc
                if attempt < self.retries - 1:
                    time.sleep(min(2**attempt, 8))
                    continue
                break

            if status == 200:
                if not raw:
                    return None
                return json.loads(raw.decode("utf-8"))

            body = raw.decode("utf-8", errors="replace")
            if status in (401, 403):
                raise ApiError(
                    status,
                    "Authentication failed: check your API key and account permissions.",
                    body,
                )
            if status == 404:
                raise ApiError(status, f"Endpoint not found: {path}", body)
            if status == 429 or status >= 500:
                last_error = ApiError(status, f"API request failed ({status}).", body)
                if attempt < self.retries - 1:
                    time.sleep(_retry_delay(resp_headers, attempt))
                    continue
                raise last_error
            raise ApiError(status, f"API request failed ({status}).", body)

        if isinstance(last_error, ApiError):
            raise last_error
        raise ApiError(0, f"Could not reach the AdGuard DNS API: {last_error}")

    # -- devices ----------------------------------------------------------

    def list_devices(self, search: str | None = None, limit: int = 1000) -> list[Device]:
        """List devices, optionally filtered by a name/ID search term."""
        devices: list[Device] = []
        cursor: str | None = None
        while True:
            data = self._request(
                "/oapi/v2/devices",
                {"search": search, "limit": limit, "cursor": cursor},
            )
            items = (data or {}).get("items") or []
            devices.extend(Device.from_json(item) for item in items)
            navigation = (data or {}).get("navigation") or {}
            nxt = navigation.get("next") or {}
            cursor = nxt.get("page_cursor")
            if not cursor:
                break
        return devices

    def all_devices(self) -> list[Device]:
        """Return every device, fetching the list only once per client."""
        if self._devices_cache is None:
            self._devices_cache = self.list_devices()
        return self._devices_cache

    def find_devices_by_name(self, name: str) -> list[Device]:
        """Return devices matching ``name``.

        Exact (case-sensitive) name matches win over case-insensitive ones.
        A device ID is also accepted and always resolves to that device.
        """
        all_devices = self.all_devices()

        by_id = [d for d in all_devices if d.id == name]
        if by_id:
            return by_id

        exact = [d for d in all_devices if d.name == name]
        if exact:
            return exact

        return [d for d in all_devices if d.name.lower() == name.lower()]

    def resolve_device(self, name: str) -> Device:
        """Resolve a device name (or ID) to exactly one device."""
        candidates = self.find_devices_by_name(name)
        if not candidates:
            raise LookupError(f'No device named "{name}" was found in your account.')
        if len(candidates) > 1:
            names = ", ".join(f"{d.name} ({d.id})" for d in candidates)
            raise LookupError(
                f'Multiple devices match "{name}": {names}. Use the device ID instead.'
            )
        return candidates[0]

    # -- query log --------------------------------------------------------

    def iter_query_log(
        self,
        time_from_millis: int,
        time_to_millis: int,
        devices: list[str] | None = None,
        statuses: list[str] | None = None,
        search: str | None = None,
        limit: int = DEFAULT_PAGE_LIMIT,
        max_items: int | None = None,
    ) -> Iterator[QueryLogItem]:
        """Yield query log entries, transparently following pagination cursors."""
        # Never ask for more rows than the caller intends to keep.
        if max_items is not None:
            limit = max(1, min(limit, max_items))

        cursor: str | None = None
        seen_cursors: set[str] = set()
        produced = 0
        while True:
            data = self._request(
                "/oapi/v1/query_log",
                {
                    "time_from_millis": time_from_millis,
                    "time_to_millis": time_to_millis,
                    "devices": devices,
                    "statuses": statuses,
                    "search": search,
                    "limit": limit,
                    "cursor": cursor,
                },
            )
            items = (data or {}).get("items") or []
            for item in items:
                yield QueryLogItem.from_json(item)
                produced += 1
                if max_items is not None and produced >= max_items:
                    return

            if not items:
                return

            pages = (data or {}).get("pages") or []
            next_cursor = _next_page_cursor(pages)
            if not next_cursor or next_cursor in seen_cursors:
                return
            seen_cursors.add(next_cursor)
            cursor = next_cursor
