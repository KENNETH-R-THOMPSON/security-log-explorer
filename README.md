# Security Log Explorer

[![Java 17 CI](https://github.com/KENNETH-R-THOMPSON/security-log-explorer/actions/workflows/java-ci.yml/badge.svg)](https://github.com/KENNETH-R-THOMPSON/security-log-explorer/actions/workflows/java-ci.yml)

A Java 17+ portfolio and practice project prepared for Kenneth Thompson with AI assistance. Analyze synthetic sign-in logs and flag addresses with repeated failed logins. Supports either full-file counts or a configurable rolling time window. No external libraries, network access, or account credentials are required.

## Setup and run

Install JDK 17 or newer and run these commands from the project folder:

```sh
./test.sh
./run.sh
./run.sh sample/login-events.csv 4
./run.sh sample/login-events.csv 3 2
./run.sh sample/login-events.csv 3 1
./run.sh sample/login-events.csv 3 2 --json
```

The command format is `./run.sh <events.csv> [failure-threshold] [window-minutes] [--json]`. The default threshold is 3. Omit `window-minutes` to count all failures in the file. A positive integer `window-minutes` activates rolling-window detection; specify the threshold when specifying a window. For the sample, the 2-minute window flags `192.0.2.10` with 3 failures, while a 1-minute window with threshold 3 reports no alerts. Exit 0 means analysis completed, even when alerts exist. Exit 2 means invalid input or file access failure.

## How rolling windows work

The analyzer groups failures by address and sorts each address's timestamps. It then finds the highest number of failures in any interval lasting at most the requested number of minutes. Both endpoints are included, so failures exactly two minutes apart count together in a 2-minute window. Input events may be out of timestamp order. Successes don't count as failures or reset earlier failures. The reported alert count is the highest count in one window, not the total across the file. The total, successful, and failed event counts still cover the entire file.

## JSON reports

Add `--json` as the final argument to print one JSON object instead of the text report. The output includes `total`, `successful`, `failed`, `threshold`, `windowMinutes` (null when no window is set), and `alerts` (an object mapping addresses to failure counts). Addresses are sorted, and quotes, backslashes, and control characters are escaped. An empty alert list becomes `"alerts":{}`.

Example:

```sh
./run.sh sample/login-events.csv 3 2 --json
```

```json
{"total":6,"successful":2,"failed":4,"threshold":3,"windowMinutes":2,"alerts":{"192.0.2.10":3}}
```

A successful analysis exits 0, including when there are no alerts. Invalid arguments and unreadable input exit 2 and print an error to stderr. JSON is only written on success. This makes the report usable with a script or a local dashboard without parsing the text output.

## IntelliJ IDEA

Open this folder. Choose **Demo - sample login report** in the run menu, then Run. Choose **Tests - all checks** for the test suite. If asked for an SDK, select an installed JDK 17 or newer. The executable scripts work independently of IntelliJ's build configuration. To try rolling windows in the IDE, add `3 2` after `sample/login-events.csv` in the Demo program arguments.

Start with [PRACTICE.md](PRACTICE.md). Source: `Main` handles CLI/reporting, `LogParser` validates input, `LoginEvent` models an event, and `SecurityAnalyzer` produces immutable report results. Tests use a small explicit-check harness with no dependency downloads.

## Input and limitations

CSV header: `timestamp,user,address,result`. Timestamps must parse as ISO instants; result is exactly SUCCESS or FAILURE. Fields cannot be blank, quoted, or padded with whitespace. This intentionally supports a simple CSV subset; embedded commas and multiline fields are unsupported. The address is an opaque grouping key, not a validated IP address. Blank lines are ignored. The command-line analyzer reads CSV events one at a time. Full-file mode keeps failure counts per address; rolling-window mode keeps failure timestamps per address and sorts them. The `LogParser.read` method still returns a list for callers that need one. Use synthetic practice datasets; large rolling-window inputs can still use substantial memory. Alerts are investigation leads, not proof of an attack. Sample names and documentation-range IP addresses are synthetic. Don't publish real authentication logs.

## Tests and verification

Run `./test.sh` to compile with `javac --release 17` and execute the dependency-free test harness. The automated checks cover parsing, original full-file behavior, rolling-window boundaries, out-of-order timestamps, address isolation, input validation, immutable reports, JSON escaping, and CLI behavior. The earlier October 31 buffered-parser pull request passed 48 checks on a hosted Java 17 runner in [GitHub Actions](https://github.com/KENNETH-R-THOMPSON/security-log-explorer/actions/runs/41192777174). The October 31 streaming-summary update passed all 52 checks on hosted Java 17 in [GitHub Actions](https://github.com/KENNETH-R-THOMPSON/security-log-explorer/actions/runs/41196866020). This is hosted CI evidence, not a new test on my Mac. See [VERIFICATION.md](VERIFICATION.md) for previous local results and the current CI evidence. Live security monitoring and real log ingestion have not been tested.

## Portfolio demonstration

Run the default sample, explain the result, then run the same sample with 2-minute and 1-minute windows. Show why the alert count changes. Run the tests, describe the inclusive boundary, and explain why repeated failures require investigation before being labeled malicious.

## Future improvements

1. Measure memory use on larger synthetic files, especially rolling-window mode.
2. Add per-user analysis without revealing personal information.
3. Consider a bounded-memory window approach when input timestamps are sorted.

## Sharing

Use [LINKEDIN.md](LINKEDIN.md) after reviewing and practicing the code. This is a personal project, independent of school and team repositories. Repository: https://github.com/KENNETH-R-THOMPSON/security-log-explorer
