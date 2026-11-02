# agdns-cli

A small CLI that pulls filtering data from the [AdGuard DNS API](https://adguard-dns.io/kb/private-dns/api/overview/):

- `blocklist`: the blocked domains for a device, deduplicated, one per line.
  Ready to combine with other lists, e.g. to build hosts-format blocklists.
- `blocked`: every blocked query for a device with timestamp, domain, filter
  rule, and status, for detail over short ranges.

It has no third-party dependencies. The API key is stored locally with file
mode `0600`. Requests reuse one keep-alive connection, ask for gzip, and
follow pagination cursors automatically.

## Requirements

- Python 3.12+
- An AdGuard DNS (Private DNS) account with an API key

## Install

### Arch / EndeavourOS

Python 3.14 already ships in `core/python`, and the tool has no third-party
dependencies, so nothing extra is required. Because Arch's system Python is
externally managed (PEP 668), use `pipx`:

```bash
yay -S python-pipx          # only if pipx is not installed yet
pipx install .
agdns --help
```

The command lands in `~/.local/bin` (already on `PATH` on EndeavourOS).
To reinstall after editing the code:

```bash
pipx install --force .
```

### Other platforms

```bash
pip install -e .            # or: pipx install .
# or run it without installing:
python -m agdns --help
```

## Setup

Create an API key in the AdGuard DNS dashboard: *User preferences*, *API keys*.
Then:

```bash
agdns config set-key <API_KEY>
agdns config show          # confirm it was saved
```

The key is written to `~/.config/agdns-cli/config.json`. Override the directory
with `AGDNS_CONFIG_DIR` or `XDG_CONFIG_HOME`. The `AGDNS_API_KEY` environment
variable takes precedence over the file.

## Usage

```bash
# List devices and their IDs
agdns devices
agdns devices --search phone
agdns devices --format json

# Blocked domains for a device: deduplicated, one per line (default: last 30 days)
agdns blocklist "My Phone" > myphone-blocklist.txt
agdns blocklist "My Phone" --days 7
agdns blocklist "My Phone" "Living Room TV"        # several devices, merged

# Detail view: every blocked query with timestamps and rules
agdns blocked "My Phone"
agdns blocked "My Phone" --days 7
agdns blocked "My Phone" --since 2024-05-01 --until 2024-05-31
agdns blocked "My Phone" --search ads.             # only domains matching "ads."
agdns blocked "My Phone" --max-records 500
agdns blocked "My Phone" --format json > blocked.json
agdns blocked "My Phone" --summary                 # per-category and per-domain totals

# By device ID instead of name
agdns blocklist dev111
agdns blocked dev111 --format json
```

Device names match case-sensitively first. If a name is ambiguous, the CLI
errors out and lists the candidates so you can pass the device ID instead.

## Commands

| Command | Description |
| --- | --- |
| `agdns devices` | List devices (`--search`, `--format`) |
| `agdns blocklist <device>...` | Deduplicated blocked domains, one per line |
| `agdns blocked <device>...` | Blocked requests with full detail |
| `agdns config set-key <key>` | Store the API key locally |
| `agdns config set-url <url>` | Override the API base URL (for testing or proxies) |
| `agdns config show` | Show the current configuration |
| `agdns config clear-key` | Remove the stored API key |

### `blocklist` options

Uses the aggregated per-domain statistics endpoint, so it is much lighter than
pulling every log entry. Multi-device runs merge into one list; the API
aggregates per domain, so no sorting or `uniq` is needed afterward.

| Option | Default | Description |
| --- | --- | --- |
| `--days N` | `30` | Look back N days |
| `--since` / `--until` | – | Explicit range (see below) |
| `--page-size N` | `1000` | Entries per API request (max 1000) |

### `blocked` options

| Option | Default | Description |
| --- | --- | --- |
| `--days N` | `30` | Look back N days |
| `--since` / `--until` | – | Explicit range (see below) |
| `--status` | `REQUEST_BLOCKED`, `RESPONSE_BLOCKED` | Filtering status to include (repeatable). Other values: `REQUEST_ALLOWED`, `RESPONSE_ALLOWED`, `MODIFIED`, `NONE` |
| `--search` | – | Domain substring filter |
| `--max-records N` | unlimited | Stop after N entries |
| `--page-size N` | `1000` | Entries per API request (max 1000) |
| `--summary` | off | Print per-category and per-domain totals |
| `--format` | `table` | `table` or `json` |

### Time ranges

`--days`, `--since`, and `--until` work the same way on `blocklist` and
`blocked`:

- `--since` / `--until` accept `YYYY-MM-DD`, ISO 8601 timestamps
  (`2024-05-01T10:00:00Z`), or epoch seconds (`1714560000`).
- A bare date means midnight UTC, not the machine's local zone.
- The range is validated: `--days` must be 1 or more, and the start must not
  come after the end.

## API endpoints

Every request is authenticated with an `Authorization: ApiKey <key>` header.
Pass `--account-id` (before the subcommand) to operate on a specific account,
sent as the `X-Account-Id` header.

- `GET /oapi/v2/devices`: resolve device names to IDs
- `GET /oapi/v1/stats/domains`: aggregated per-domain query counts, filtered
  by devices; entries with `blocked > 0` form the `blocklist` output
- `GET /oapi/v1/query_log`: per-query detail for a time range, filtered by
  devices and statuses; used by `blocked`

## Tests

```bash
python -m unittest discover -s tests -t .
```

The suite runs against a local mock of the AdGuard DNS API, so no network or
real credentials are needed.
