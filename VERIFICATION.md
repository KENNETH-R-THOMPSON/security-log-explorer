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
