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
./run.sh sample/login-events.csv 3 2 --by-user --json
./run.sh sample/login-events.csv 3 2 --sorted --by-user --json
```

The command format is `./run.sh <events.csv> [failure-threshold] [window-minutes] [--sorted] [--by-user] [--json]`. The default threshold is 3. Omit `window-minutes` to count all failures in the file. A positive integer `window-minutes` activates rolling-window detection; specify the threshold when specifying a window. For the sample, the 2-minute window flags `192.0.2.10` with 3 failures, while a 1-minute window with threshold 3 reports no alerts. Exit 0 means analysis completed, even when alerts exist. Exit 2 means invalid input or file access failure.

## How rolling windows work

The analyzer groups failures by address and sorts each address's timestamps. It then finds the highest number of failures in any interval lasting at most the requested number of minutes. Both endpoints are included, so failures exactly two minutes apart count together in a 2-minute window. Input events may be out of timestamp order. Successes don't count as failures or reset earlier failures. The reported alert count is the highest count in one window, not the total across the file. The total, successful, and failed event counts still cover the entire file.

## Chronological streaming mode

For CSV files already sorted by timestamp, add `--sorted` after the required threshold and window. For example:

```sh
./run.sh sample/login-events.csv 3 2 --sorted
./run.sh sample/login-events.csv 3 2 --sorted --by-user --json
```

This mode processes each row in order and removes failures that have left the current time window. It tracks the highest count seen for each address or username. The memory used for recent events depends on the number of failures within the current window, plus the number of grouping keys with recorded maxima. Equal timestamps are accepted. All rows, including successful logins, must be in nondecreasing timestamp order; an out-of-order row causes an error and exit code 2. The command never sorts or modifies the CSV. The JSON report includes `"sortedInput":true` when this mode is selected.

The default rolling-window mode still accepts unsorted CSV files. It retains all failure timestamps until reporting. Chronological mode is useful for large fictional files with timestamps already in order, but a burst of many failures within one window can still require substantial memory.

## Optional per-user grouping

Add `--by-user` after the numeric arguments to group failed logins by fictional username instead of address. It works with full-file counts and rolling windows. Run `./run.sh sample/login-events.csv 3 2 --by-user --json` to see `alex` with three failures. Put `--json` last. User-grouped JSON adds `"groupBy":"user"`; default address-based JSON stays unchanged.

This mode combines failures for one username across addresses. It doesn't normalize usernames, identify a real person, or establish malicious activity. Use fictional records.

## JSON reports

Add `--json` as the final argument to print one JSON object instead of the text report. The output includes `total`, `successful`, `failed`, `threshold`, `windowMinutes` (null when no window is set), and `alerts` (an object mapping addresses to failure counts). Addresses are sorted, and quotes, backslashes, and control characters are escaped. An empty alert list becomes `"alerts":{}`.

Example:

```sh
./run.sh sample/login-events.csv 3 2 --json
```

```json
{"total":6,"successful":2,"failed":4,"threshold":3,"windowMinutes":2,"alerts":{"192.0.2.10":3}}
```

A successful analysis exits 0, including when there are no alerts. Invalid arguments and unreadable input exit 2 and print an error to stderr. JSON is only written on success. CLI errors escape control and Unicode formatting characters in untrusted argument or file error text before writing to the terminal. This makes the report usable with a script or a local dashboard without parsing the text output.

## Quoted CSV demonstration

Run `./run.sh sample/quoted-login-events.csv 3 2 --json`. The four fictional rows include usernames with commas and escaped quotes. The result has three failures, one success, and one alert for `192.0.2.10` with a count of three. The parser handles one physical line per event and rejects malformed or multiline quoted fields. No real account records are included.

Some CSV exports include a UTF-8 byte order mark (BOM) at the start. The parser accepts that mark before the exact header. Try `./run.sh sample/bom-login-events.csv 2 --json` for a fictional CRLF example with two failures and one success. The parser still rejects an incorrect header, even with a BOM.

## IntelliJ IDEA

Open this folder. Choose **Demo - sample login report** in the run menu, then Run. Choose **Tests - all checks** for the test suite. If asked for an SDK, select an installed JDK 17 or newer. The executable scripts work independently of IntelliJ's build configuration. To try rolling windows in the IDE, add `3 2` after `sample/login-events.csv` in the Demo program arguments.

Start with [PRACTICE.md](PRACTICE.md). Source: `Main` handles CLI/reporting, `LogParser` validates input, `LoginEvent` models an event, and `SecurityAnalyzer` produces immutable report results. Tests use a small explicit-check harness with no dependency downloads.

## Input and limitations

CSV header: `timestamp,user,address,result` (an initial UTF-8 BOM is accepted). Timestamps must parse as ISO instants; result is exactly SUCCESS or FAILURE. Fields cannot be blank or padded with whitespace. Single-line quoted CSV fields are supported, including commas and doubled double quotes (for example, `"sam, jr"` or `"sam ""junior"""`). Malformed quoting, extra columns and multiline fields are rejected with a physical line number. The address is an opaque grouping key, not a validated IP address. Text reports escape control characters and Unicode formatting characters in address labels using `\uXXXX` notation. Literal backslashes are doubled, so text that looks like an escaped control character stays distinguishable from a real control character. This prevents ambiguous alert labels and raw terminal escape sequences. JSON reports retain address values as data with JSON escaping; consumers must still handle untrusted strings safely. Blank lines are ignored. The command-line analyzer reads CSV events one at a time. Full-file mode keeps failure counts per selected grouping key. Default rolling-window mode keeps failure timestamps per selected grouping key and sorts its private timestamp lists in place, avoiding an additional full list of references during reporting. The opt-in chronological mode uses one sliding queue and checks that every input timestamp is in order. The `LogParser.read` method still returns a list for callers that need one. The `LogParser.forEach` callback runs after CSV parsing succeeds; if a caller's callback throws, the original exception is preserved rather than reported as a malformed CSV row. Use synthetic practice datasets; large rolling-window inputs can still use substantial memory. Alerts are investigation leads, not proof of an attack. Sample names and documentation-range IP addresses are synthetic. Don't publish real authentication logs.

## Tests and verification

Run `./test.sh` to compile with `javac --release 17` and run the dependency-free tests. They cover CSV parsing, full-file and rolling-window analysis, JSON reports, malformed input, and safe terminal output. The suite includes 50,000 reverse-ordered fictional failures for both address and username windows. CI also reruns the tests with a 64 MB Java heap. This checks one constrained workload; it doesn't establish a fixed memory ceiling for other inputs.

On November 1, [PR #20](https://github.com/KENNETH-R-THOMPSON/security-log-explorer/pull/20) changed rolling-window analysis to sort its private timestamp lists in place. Two new checks exercise 50,000 reverse-ordered fictional failures for address and username grouping. All **83 checks** passed twice on hosted Java 17, including one run with a 64 MB Java heap. The existing sample, rolling-window, JSON, quoted CSV and BOM workflow steps passed in [merged-main GitHub Actions](https://github.com/KENNETH-R-THOMPSON/security-log-explorer/actions/runs/41382945615). The previous 81-check result is historical. See [VERIFICATION.md](VERIFICATION.md) for the checks and limits.

On November 1, [PR #22](https://github.com/KENNETH-R-THOMPSON/security-log-explorer/pull/22) added optional chronological streaming windows. All **95 checks** passed in both the regular and 64 MB heap test runs on hosted Java 17. The sample CLI, JSON, quoted CSV and BOM workflow steps passed in [merged-main CI](https://github.com/KENNETH-R-THOMPSON/security-log-explorer/actions/runs/41388126648). The earlier 83-check result is historical. This is a workload-specific test, not a universal memory limit.

This is hosted CI evidence. The updated code hasn't been tested on the owner's Mac or with real authentication logs, and live monitoring hasn't been verified.

## Portfolio demonstration

Run the default sample, explain the result, then run the same sample with 2-minute and 1-minute windows. Show why the alert count changes. Run the tests, describe the inclusive boundary, and explain why repeated failures require investigation before being labeled malicious.

## Future improvements

1. Measure memory use on larger synthetic files, especially rolling-window mode.
2. Compare user and address grouping on larger fictional files.
3. Compare chronological mode and default rolling windows on larger fictional files, recording the workload and heap limits.

## Sharing

Use [LINKEDIN.md](LINKEDIN.md) after reviewing and practicing the code. This is a personal project, independent of school and team repositories. Repository: https://github.com/KENNETH-R-THOMPSON/security-log-explorer
