# agdns-cli

A small CLI to pull **blocked DNS requests per device** from the [AdGuard DNS API](https://adguard-dns.io/kb/private-dns/api/overview).

The API key is stored locally (file mode `0600`), and the tool fetches every blocked
query for a given device over the past 30 days (configurable), following pagination
cursors automatically.

## Requirements

- Python 3.12+
- An AdGuard DNS account (Private DNS) with an API key
- Query log access on the account

## Install

### Arch / EndeavourOS

Python 3.14 is already provided by `core/python`, and this tool has **no third-party
dependencies**, so nothing extra is required. Because Arch's system Python is
"externally managed" (PEP 668), use `pipx` to install the command:

```bash
yay -S python-pipx
pipx install .
agdns --help
```

The command lands in `~/.local/bin` .

To reinstall after editing the code:

```bash
pipx install --force .
```

### Other platforms

```bash
pip install -e .           
```

Or run it without installing:

```bash
python -m agdns --help
```

## Setup

Create an API key in *AdGuard DNS → User preferences → API keys*, then:

```bash
agdns config set-key <API_KEY>
agdns config show 
```

The key is written to `~/.config/agdns-cli/config.json` (override the directory with
`AGDNS_CONFIG_DIR`, or `XDG_CONFIG_HOME`). `AGDNS_API_KEY` takes precedence over the
file if set.

## Usage

```bash
# List devices and their IDs
agdns devices
agdns devices --search phone

# Blocked requests for a device over the last 30 days (default)
agdns blocked "My Phone"

# Explicit time range and extra filters
agdns blocked "My Phone" --days 7
agdns blocked "My Phone" --since 2024-05-01 --until 2024-05-31
agdns blocked "My Phone" --search ads.          # only domains matching "ads."
agdns blocked "My Phone" --max-records 500

# Output formats
agdns blocked "My Phone" --format json > blocked.json

# Aggregate view
agdns blocked "My Phone" --summary

# Several devices at once, or by device ID
agdns blocked "My Phone" "Living Room TV"
agdns blocked dev111

# Plain blocked-domain list, deduplicated, one domain per line
agdns blocklist "My Phone" > blocked.txt
agdns blocklist "My Phone" "Living Room TV"   # merged, deduplicated
```

Device names are matched case-sensitively first; if that is ambiguous the CLI errors
out and lists the candidates so you can pass the device ID instead.

Time-range notes: bare dates (`--since 2024-05-01`) are interpreted as midnight
UTC, not the machine's local zone. `--days` must be 1 or more, and the start of
the range must not come after its end.

## Commands

| Command | Description |
| --- | --- |
| `agdns devices` | List devices (`--search`, `--format`) |
| `agdns blocked <device>...` | Blocked requests for one or more devices |
| `agdns blocklist <device>...` | Deduplicated blocked domains, one per line |
| `agdns config set-key <key>` | Store the API key locally |
| `agdns config set-url <url>` | Override the API base URL (for testing/proxies) |
| `agdns config show` | Show the current configuration |
| `agdns config clear-key` | Remove the stored API key |

### `blocked` options

| Option | Default | Description |
| --- | --- | --- |
| `--days N` | `30` | Look back N days |
| `--since` / `--until` | – | Explicit range (`YYYY-MM-DD` or ISO-8601) |
| `--status` | blocked only | repeatable filtering statuses |
| `--search` | – | Domain substring filter |
| `--page-size N` | `1000` | Entries per API request (max 1000) |
| `--summary` | off | Print per-category and per-domain totals |
| `--format` | `table` | `table` or `json` |

### `blocklist` options

The `blocklist` command is the cheap path to "which domains got blocked":
it uses aggregated per-domain statistics instead of pulling every log entry,
and prints just the list of blocked domains, one per line — ready to be
combined with other lists (e.g. to build hosts-format blocklists elsewhere).

| Option | Default | Description |
| --- | --- | --- |
| `--days N` / `--since` / `--until` | `30` | Same time range options as `blocked` |
| `--page-size N` | `1000` | Entries per API request (max 1000) |

## API used

- `GET /oapi/v2/devices` — resolve a device name to its ID
- `GET /oapi/v1/query_log` — fetch entries for the time range, filtered by
  `devices` and `statuses` (`blocked` command)
- `GET /oapi/v1/stats/domains` — aggregated per-domain query counts filtered by
  `devices`; entries with `blocked > 0` form the blocklist (`blocklist` command)

Authentication is the `Authorization: ApiKey <key>` header. Use `--account-id` to
operate on a specific account (`X-Account-Id`).

## Tests

```bash
python -m unittest discover -s tests -t .
```

The suite runs against a local mock of the AdGuard DNS API, so no network or real
credentials are needed.
