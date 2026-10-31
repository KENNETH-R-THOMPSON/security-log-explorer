# Verification

## October 25, 2026 (original project)

The original version was reported as compiled with OpenJDK 25 using `--release 17`. Its 18 checks and sample CLI report passed. IntelliJ build and Demo run were reported successful with OpenJDK 25.0.2.

## October 26, 2026 (rolling-window update)

Environment: OpenJDK 21.0.12.1, `javac --release 17`, Linux. This verifies Java 17 language compatibility at compile time; execution on an installed Java 17 runtime was not separately tested.

- `./test.sh`: 37 checks passed, exit 0.
- `./run.sh`: 6 events, 2 successes, 4 failures, one address alert with 3 failures.
- `./run.sh sample/login-events.csv 3 2`: one alert for `192.0.2.10` with 3 failures within any 2-minute window.
- `./run.sh sample/login-events.csv 3 1`: no alerts with threshold 3 in any 1-minute window.

Checks cover original full-file behavior, inclusive window boundaries, out-of-order timestamps, distant failure clusters, address separation, empty input, successful events, invalid windows, immutable reports, parser validation, and CLI errors. No external dependencies or network calls were needed for these local tests.

GitHub Actions and IntelliJ verification of this update remain unverified until independently run. Live authentication logs and production security monitoring were not tested.

## October 31, 2026 (JSON report)

Local environment: OpenJDK 21.0.12.1 on Linux, compiled with `javac --release 17`. The local run used a current working copy of the October 26 source and the JSON feature changes. Java 17 runtime execution is checked separately by GitHub Actions.

- `sh ./test.sh`: all 45 checks passed, exit 0. Eight new checks cover default JSON, rolling-window JSON, empty alerts, escaping, sorted keys, invalid flag positions, and error output.
- `sh ./run.sh sample/login-events.csv 3 2 --json`: produced the expected one-line JSON report.
- Piped the two-minute and one-minute JSON examples into Python 3 `json.load` and checked expected values. Both checks passed.
- Existing plain-text behavior was included in the 45 checks.

These are local results. GitHub Actions for this branch must pass before merging. No production logs, live monitoring, or target Mac run were tested.

## October 31, 2026 (buffered CSV input)

The parser now reads raw CSV lines with a buffered reader. It still retains parsed events in memory. Three new checks cover 5,000 fictional events, analysis totals, and an invalid event at physical line 5002.

- Pull request: https://github.com/KENNETH-R-THOMPSON/security-log-explorer/pull/4
- GitHub Actions pull-request run: https://github.com/KENNETH-R-THOMPSON/security-log-explorer/actions/runs/41192777174
- Hosted Temurin Java 17: all 48 checks passed, exit 0. Sample reports and JSON parsing also passed.
- This is CI evidence for the pull-request commit, not a new local or target Mac test. Full streaming analysis and live monitoring remain unimplemented.
