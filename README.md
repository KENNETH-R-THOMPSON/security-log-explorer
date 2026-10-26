# Security Log Explorer

A Java portfolio and practice project prepared for Kenneth Thompson with AI assistance. Analyze synthetic sign-in logs and flag addresses with repeated failed logins. Java 17+, no external libraries, no network or account credentials.

## Quick start

```sh
./run.sh
./test.sh
./run.sh sample/login-events.csv 4
```

The sample has 6 events: 2 successful, 4 failed. With threshold 3, address `192.0.2.10` is flagged with 3 failures; threshold 4 produces no alerts. Exit 0 means analysis completed, even when alerts exist. Exit 2 means invalid input or file access failure.

## IntelliJ IDEA

Open this folder. Choose **Demo - sample login report** in the run menu, then Run. Choose **Tests - all checks** for the test suite. If asked for an SDK, select the installed OpenJDK 25; source language is Java 17. The executable scripts work independently of IntelliJ's build configuration.

Start with [PRACTICE.md](PRACTICE.md). Source: `Main` handles CLI/reporting, `LogParser` validates input, `LoginEvent` models an event, and `SecurityAnalyzer` produces immutable report results. Tests use a small explicit-check harness, with no dependency downloads.

## Input and limits

CSV header: `timestamp,user,address,result`. Timestamps must parse as ISO instants; result is exactly SUCCESS or FAILURE. Fields cannot be blank, quoted, or padded with whitespace. This intentionally supports a simple CSV subset; embedded commas and multiline fields are unsupported. The address is an opaque grouping key, not a validated IP address. Blank lines are ignored. Counts cover the entire file, not a time window; a success does not reset earlier failures. The parser reads the file into memory and is intended for small practice datasets. Alerts are investigation leads, not proof of an attack. Sample names and documentation-range IP addresses are synthetic.

## Portfolio demonstration

Run the sample, explain the result, change the threshold to 4, then run the tests. Walk through how malformed input is rejected. Explain why a rolling time window would improve detection and why a high failure count alone does not establish malicious activity.

## Next features to implement yourself

1. Count failed attempts by username as well as address.
2. Add a configurable rolling time window with boundary tests.
3. Stream large inputs instead of loading all lines.
4. Add a JSON output mode and test escaping.

## Sharing

Use [LINKEDIN.md](LINKEDIN.md) after reviewing and practicing the code. Do not publish input logs from real systems. This is a personal project, independent of school/team repositories. Repository: https://github.com/KENNETH-R-THOMPSON/security-log-explorer
