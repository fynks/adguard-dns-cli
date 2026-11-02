"""Command line interface for the AdGuard DNS CLI."""

import argparse
import json
import os
import sys
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from .api import (
    BLOCKED_STATUSES,
    AdGuardDNSClient,
    ApiError,
    Device,
    QueryLogItem,
)
from . import config

DEFAULT_DAYS = 30


class CliError(Exception):
    """A user-facing error that should be reported without a traceback."""


# -- helpers ---------------------------------------------------------------


def _client(args: argparse.Namespace) -> AdGuardDNSClient:
    api_key = config.get_api_key()
    if not api_key:
        raise CliError(
            "No API key found.\n"
            "  Set one with:  agdns config set-key <API_KEY>\n"
            f"  Or export {config.ENV_API_KEY}=<API_KEY>."
        )
    client = AdGuardDNSClient(
        api_key=api_key,
        api_url=config.get_api_url(),
        account_id=getattr(args, "account_id", None),
    )
    # Stashed so main() can release the pooled connection on any exit path.
    setattr(args, "_client", client)
    return client


def _time_range(args: argparse.Namespace) -> tuple[int, int]:
    now = datetime.now(UTC)
    if args.since:
        start = _parse_time(args.since)
    else:
        start = now - timedelta(days=args.days)
    end = _parse_time(args.until) if args.until else now
    return int(start.timestamp() * 1000), int(end.timestamp() * 1000)


def _parse_time(value: str) -> datetime:
    value = value.strip()
    if value.isdigit():
        seconds = int(value)
        return datetime.fromtimestamp(seconds, tz=UTC)
    try:
        # Python 3.11+ parses both "Z" and "+00:00" suffixes natively.
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise SystemExit(f'Invalid time "{value}". Use YYYY-MM-DD or an ISO-8601 timestamp.') from exc


def _fmt_time(millis: int) -> str:
    if not millis:
        return ""
    return datetime.fromtimestamp(millis / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")


# -- output ----------------------------------------------------------------


def _print_table(items: Sequence[QueryLogItem]) -> None:
    if not items:
        return
    headers = ["TIME", "DOMAIN", "STATUS", "CATEGORY", "RULE"]
    rows = [
        [
            _fmt_time(item.time_millis),
            item.domain,
            item.filtering_status,
            item.category_type,
            item.filter_rule or item.filtering_category_id or item.blocked_service_id or "",
        ]
        for item in items
    ]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def line(cells: Sequence[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells)).rstrip()

    print(line(headers))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print(line(row))


def _print_json(payload: Any, stream: Any) -> None:
    json.dump(payload, stream, indent=2, ensure_ascii=False)
    stream.write("\n")


class _Accumulator:
    """Collects aggregate counts while records stream past."""

    def __init__(self) -> None:
        self.total = 0
        self.by_status: dict[str, int] = {}
        self.by_category: dict[str, int] = {}
        self.by_domain: dict[str, int] = {}

    def add(self, item: QueryLogItem) -> None:
        self.total += 1
        status = item.filtering_status or "UNKNOWN"
        category = item.category_type or "UNKNOWN"
        self.by_status[status] = self.by_status.get(status, 0) + 1
        self.by_category[category] = self.by_category.get(category, 0) + 1
        self.by_domain[item.domain] = self.by_domain.get(item.domain, 0) + 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "by_status": dict(sorted(self.by_status.items(), key=lambda kv: -kv[1])),
            "by_category": dict(sorted(self.by_category.items(), key=lambda kv: -kv[1])),
            "by_domain": dict(
                sorted(self.by_domain.items(), key=lambda kv: (-kv[1], kv[0]))
            ),
        }


# -- commands --------------------------------------------------------------


def cmd_config(args: argparse.Namespace) -> int:
    if args.config_action == "set-key":
        if not args.value:
            raise SystemExit("Usage: agdns config set-key <API_KEY>")
        config.set_api_key(args.value)
        print(f"API key saved to {config.config_file()}")
        return 0

    if args.config_action == "set-url":
        if not args.value:
            raise SystemExit("Usage: agdns config set-url <API_URL>")
        config.set_api_url(args.value)
        print(f"API URL set to {config.get_api_url()}")
        return 0

    if args.config_action == "clear-key":
        config.clear_api_key()
        print("API key removed.")
        return 0

    # show
    api_key = config.get_api_key()
    data = {
        "config_file": str(config.config_file()),
        "api_url": config.get_api_url(),
        "api_key_set": api_key is not None,
        "api_key_source": (
            "environment"
            if os.environ.get(config.ENV_API_KEY)
            else ("file" if api_key else None)
        ),
    }
    if args.format == "json":
        _print_json(data, sys.stdout)
    else:
        print(f"Config file : {data['config_file']}")
        print(f"API URL     : {data['api_url']}")
        print(f"API key set : {data['api_key_set']} (source: {data['api_key_source']})")
    return 0


def cmd_devices(args: argparse.Namespace) -> int:
    client = _client(args)
    devices = client.list_devices(search=args.search)
    client.close()
    if args.format == "json":
        _print_json([d.raw for d in devices], sys.stdout)
        return 0
    if not devices:
        print("No devices found.")
        return 0
    width = max(len(d.id) for d in devices)
    for device in devices:
        print(f"{device.id.ljust(width)}  {device.name}  [{device.device_type}]")
    return 0


def cmd_blocked(args: argparse.Namespace) -> int:
    client = _client(args)
    time_from, time_to = _time_range(args)
    device_ids, devices_info = _resolve_devices(client, args.device)

    statuses = args.status if args.status else list(BLOCKED_STATUSES)
    records = client.iter_query_log(
        time_from_millis=time_from,
        time_to_millis=time_to,
        devices=device_ids,
        statuses=statuses,
        search=args.search,
        limit=args.page_size,
        max_items=args.max_records,
    )

    acc = _Accumulator()
    items: list[QueryLogItem] = []
    for item in records:
        acc.add(item)
        items.append(item)
    client.close()

    if args.format == "json":
        payload: Any = {
            "devices": [
                {"id": d.id, "name": d.name, "device_type": d.device_type} for d in devices_info
            ],
            "time_from_millis": time_from,
            "time_to_millis": time_to,
            "statuses": statuses,
            "count": acc.total,
            "items": [item.raw for item in items],
        }
        if args.summary:
            payload["summary"] = acc.as_dict()
        _print_json(payload, sys.stdout)
        return 0

    # Table
    device_label = ", ".join(d.name for d in devices_info)
    print(
        f"Blocked queries for {device_label} "
        f"({_fmt_time(time_from)} .. {_fmt_time(time_to)}): {acc.total}"
    )
    _print_table(items)

    if args.summary:
        summary = acc.as_dict()
        print()
        print("Summary by category:")
        for name, count in summary["by_category"].items():
            print(f"  {name.ljust(14)} {count}")
        print()
        print("Top domains:")
        for name, count in list(summary["by_domain"].items())[:20]:
            print(f"  {count:>6}  {name}")
    return 0


def _resolve_devices(client: AdGuardDNSClient, names: list[str]) -> tuple[list[str], list[Device]]:
    """Resolve device names/IDs to unique IDs plus their Device records."""
    device_ids: list[str] = []
    devices_info: list[Device] = []
    for name in names:
        device = client.resolve_device(name)
        devices_info.append(device)
        if device.id not in device_ids:
            device_ids.append(device.id)
    return device_ids, devices_info


def cmd_blocklist(args: argparse.Namespace) -> int:
    """Emit the list of domains blocked for one or more devices.

    Uses the aggregated domain statistics endpoint, so the output stays tiny
    compared to a full query-log pull: one domain per line, nothing else.
    """
    client = _client(args)
    time_from, time_to = _time_range(args)
    device_ids, _ = _resolve_devices(client, args.device)

    domains = (
        stat.domain
        for stat in client.iter_domain_stats(
            time_from_millis=time_from,
            time_to_millis=time_to,
            devices=device_ids,
            limit=args.page_size,
        )
        if stat.blocked > 0
    )
    for domain in domains:
        sys.stdout.write(f"{domain}\n")
    client.close()
    return 0


# -- parser ----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agdns",
        description="Pull blocked DNS requests per device from the AdGuard DNS API.",
    )
    parser.add_argument(
        "--account-id",
        type=int,
        default=None,
        help="Operate on a specific account ID (X-Account-Id header).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    cfg = subparsers.add_parser("config", help="Manage the locally stored API key.")
    cfg.add_argument(
        "config_action",
        choices=("set-key", "set-url", "clear-key", "show"),
        help="Action to perform.",
    )
    cfg.add_argument("value", nargs="?", help="Value for set-key / set-url.")
    cfg.add_argument("--format", choices=("text", "json"), default="text")
    cfg.set_defaults(func=cmd_config)

    devices = subparsers.add_parser("devices", help="List devices in your account.")
    devices.add_argument("--search", help="Filter devices by name or ID.")
    devices.add_argument("--format", choices=("text", "json"), default="text")
    devices.set_defaults(func=cmd_devices)

    blocked = subparsers.add_parser(
        "blocked", help="Show blocked requests for a device over a time range."
    )
    blocked.add_argument("device", nargs="+", help="Device name or device ID.")
    blocked.add_argument(
        "--days", type=int, default=DEFAULT_DAYS, help="Look back this many days (default: 30)."
    )
    blocked.add_argument("--since", help="Start of the range (YYYY-MM-DD or ISO-8601).")
    blocked.add_argument("--until", help="End of the range (YYYY-MM-DD or ISO-8601).")
    blocked.add_argument(
        "--status",
        action="append",
        choices=(
            "REQUEST_BLOCKED",
            "RESPONSE_BLOCKED",
            "REQUEST_ALLOWED",
            "RESPONSE_ALLOWED",
            "MODIFIED",
            "NONE",
        ),
        help="Filtering status to include (repeatable). Default: blocked only.",
    )
    blocked.add_argument("--search", help="Filter by domain name substring.")
    blocked.add_argument(
        "--max-records", type=int, default=None, help="Stop after this many entries."
    )
    blocked.add_argument(
        "--page-size", type=int, default=1000, help="Entries per API request (max 1000)."
    )
    blocked.add_argument("--summary", action="store_true", help="Print aggregate statistics.")
    blocked.add_argument(
        "--format", choices=("table", "json"), default="table", help="Output format."
    )
    blocked.set_defaults(func=cmd_blocked)

    blocklist = subparsers.add_parser(
        "blocklist",
        help="Print the domains blocked for one or more devices, one per line.",
        description=(
            "Export the domains blocked for one or more devices, deduplicated, "
            "one domain per line, using the aggregated domain-statistics "
            "endpoint."
        ),
    )
    blocklist.add_argument("device", nargs="+", help="Device name or device ID.")
    blocklist.add_argument(
        "--days", type=int, default=DEFAULT_DAYS, help="Look back this many days (default: 30)."
    )
    blocklist.add_argument("--since", help="Start of the range (YYYY-MM-DD or ISO-8601).")
    blocklist.add_argument("--until", help="End of the range (YYYY-MM-DD or ISO-8601).")
    blocklist.add_argument(
        "--page-size", type=int, default=1000, help="Entries per API request (max 1000)."
    )
    blocklist.set_defaults(func=cmd_blocklist)

    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.func(args) or 0)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ApiError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except LookupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    finally:
        # Release the pooled keep-alive connection.
        client = getattr(args, "_client", None)
        if client is not None:
            client.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
