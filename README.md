# Log Analyzer

A command-line tool that analyzes web server access logs (Combined Log Format) and generates traffic statistics, error rates, and anomaly reports — designed to handle large log files efficiently by processing them line by line instead of loading them into memory.

Built with Python's standard library only — no third-party log-parsing packages.

## Features

- **Streaming processing** — reads the log file line by line, so memory usage stays flat regardless of file size (tested on 500k+ lines with ~14MB peak memory).
- **Robust parsing** — extracts IP, timestamp, HTTP method, endpoint, protocol, status code, and response size from each line using a custom regex parser (no log-parsing libraries).
- **Malformed line handling** — invalid or corrupted lines are detected, counted, and skipped without crashing the program.
- **Core statistics** — total requests, unique IP addresses, top N most-requested endpoints, and error rate (percentage of 4xx/5xx responses).
- **Hourly traffic histogram** — a 24-hour breakdown of request volume with a scaled ASCII bar chart.
- **Anomaly detection** (optional):
  - Flags IP addresses with a suspiciously high number of failed login attempts (possible brute-force activity).
  - Detects time windows where the 5xx error rate spikes as a statistical outlier compared to the rest of the log.
- **Time-range filtering** — restrict analysis to a specific start/end window.
- **Gzip support** — reads `.gz` compressed logs transparently, same as plain text.
- **JSON export** — machine-readable output, printed to stdout and optionally saved to a file.
- **Execution timing** — reports how long processing took.
- **Unit tests** — parser and statistics logic are covered by an automated test suite (`unittest`, standard library only).

## Requirements

- Python 3.9+
- No external dependencies

## Installation

```bash
git clone <this-repo-url>
cd log-analyzer
```

Nothing to install — it runs directly with the Python standard library.

## Usage

```bash
python -m log_analyzer <path-to-logfile> [options]
```

### Basic example

```bash
python -m log_analyzer access.log
```

### Compressed logs

```bash
python -m log_analyzer access.log.gz
```

## Commands & Options

| Option                         | Description                                                                                                     |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| `logfile`                      | Path to the access log file (plain text or `.gz`). Required.                                                    |
| `--top N`                      | Number of top endpoints to show (default: `10`).                                                                |
| `--json`                       | Output the report as JSON instead of a human-readable table.                                                    |
| `-o`, `--output PATH`          | File path to save the JSON report to (default: `output/report.json`). Only used with `--json`.                  |
| `--start TIME`                 | Only include entries at or after this time. Accepts `YYYY-MM-DD`, `YYYY-MM-DD HH:MM`, or `YYYY-MM-DD HH:MM:SS`. |
| `--end TIME`                   | Only include entries at or before this time. Same formats as `--start`.                                         |
| `--show-invalid-samples`       | Print a few example lines that failed to parse.                                                                 |
| `--timing`                     | Print how long processing took.                                                                                 |
| `--detect-anomalies`           | Enable anomaly detection (suspicious IPs + 5xx error spikes).                                                   |
| `--min-failed-auth N`          | Minimum failed-login count before an IP is flagged (default: `5`).                                              |
| `--auth-status CODE`           | Status code treated as a failed login attempt (default: `401`).                                                 |
| `--auth-endpoint-keyword TEXT` | Substring identifying login endpoints, case-insensitive (default: `login`).                                     |
| `--spike-window SECONDS`       | Time window size for 5xx spike detection (default: `60`).                                                       |
| `--spike-zscore Z`             | Standard deviations above the mean required to flag a spike (default: `2.0`).                                   |

### Examples

Show only the top 5 endpoints:

```bash
python -m log_analyzer access.log --top 5
```

Export a JSON report to a custom path:

```bash
python -m log_analyzer access.log --json --output reports/october.json
```

Analyze only a specific time range:

```bash
python -m log_analyzer access.log --start "2024-01-01 09:00" --end "2024-01-01 17:00"
```

Run with anomaly detection, using a stricter login-failure threshold:

```bash
python -m log_analyzer access.log --detect-anomalies --min-failed-auth 3
```

Show example lines that failed to parse, plus execution time:

```bash
python -m log_analyzer access.log --show-invalid-samples --timing
```

## Running Tests

```bash
python -m unittest discover -s tests -v
```

## Project Structure

```
log-analyzer/
├── log_analyzer/
│   ├── __main__.py      # entry point for `python -m log_analyzer`
│   ├── cli.py            # argument parsing and orchestration
│   ├── parser.py          # turns one raw log line into a structured record
│   ├── processor.py        # streams the log file line by line
│   ├── stats.py              # aggregates parsed entries into statistics
│   ├── anomalies.py            # suspicious-IP and error-spike detection
│   └── report.py                # formats and prints the final report
└── sample/
│   ├── access.log          # sample file that is tested by program
│   └── access.log.gz       # .gz format of sample file
└── tests/
    ├── test_parser.py
    └── test_stats.py
```

## Design Decisions

- **Streaming over loading**: the file is iterated line by line (`for line in f`) rather than read fully into memory, so the tool scales to large logs without a memory ceiling.
- **Regex-based parsing over a log library**: per the project constraints, no library auto-parses access logs — a hand-written, well-documented regex handles the Combined Log Format directly, with extra validation (IP shape, status code range) beyond what the regex alone guarantees.
- **Separation of concerns**: parsing, streaming, aggregation, anomaly detection, and report formatting each live in their own module with no circular knowledge of each other — this made the statistics and parsing logic straightforward to unit test in isolation, without needing real files.
- **Never raise on bad data**: `parse_line()` returns `None` instead of raising on malformed input, so a single corrupted line can never crash a run over hundreds of thousands of lines.

## Implementation Challenge

One of the trickier parts was the 5xx error-spike detector. An early version simply flagged any time window with 5xx errors, which produced far too many false positives on logs with a small, constant background error rate. The fix was to bucket requests into fixed time windows, compute the _mean and standard deviation_ of the error rate across all windows, and only flag windows that are statistical outliers (a configurable number of standard deviations above the mean) — while also requiring a minimum request count and minimum error rate per window, so a single error in a nearly-empty window isn't mistaken for a 100% outage.
