# Verification — October 25, 2026

Compiled with installed OpenJDK 25 using --release 17.

- All 18 automated checks passed via ./test.sh.
- ./run.sh produced 6 total events, 2 successes, 4 failures, and one address alert with 3 failures.
- No external dependencies or network calls required.

The test harness covers sample totals, threshold boundaries, grouping, empty input, success-only input, invalid thresholds, immutable reports, malformed headers/timestamps/results/fields, unsupported quoted CSV, blank rows, and CLI behavior.

IntelliJ verification: project opened with OpenJDK 25.0.2; IDE build completed successfully and the Demo run printed the expected report and finished with exit code 0.

A local Git repository is initialized for practice. Publication is tracked in the Git history.
