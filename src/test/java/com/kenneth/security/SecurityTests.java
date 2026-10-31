package com.kenneth.security;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Dependency-free tests: explicit checks work even without JVM assertions enabled. */
public final class SecurityTests {
    private static int passed;
    private static void check(boolean condition, String name) {
        if (!condition) throw new AssertionError(name);
        passed++;
        System.out.println("PASS " + name);
    }
    private static void rejects(String contents, String name) throws Exception {
        Path file = Files.createTempFile("security-test-", ".csv");
        try {
            Files.writeString(file, contents);
            try { LogParser.read(file); throw new AssertionError(name); }
            catch (IllegalArgumentException expected) { check(true, name); }
        } finally { Files.deleteIfExists(file); }
    }
    private static LoginEvent failed(String timestamp, String address) {
        return new LoginEvent(Instant.parse(timestamp), "test-user", address, false);
    }
    public static void main(String[] args) throws Exception {
        String header = "timestamp,user,address,result\n";
        var sample = LogParser.read(Path.of("sample/login-events.csv"));
        var report = SecurityAnalyzer.analyze(sample, 3);
        check(report.total() == 6 && report.successful() == 2 && report.failed() == 4, "sample totals");
        check(report.alerts().equals(Map.of("192.0.2.10", 3)), "inclusive threshold and grouping");
        check(SecurityAnalyzer.analyze(sample, 4).alerts().isEmpty(), "higher threshold excludes address");
        check(SecurityAnalyzer.analyze(List.of(), 1).total() == 0, "empty input");
        var ok = new LoginEvent(Instant.EPOCH, "user", "address", true);
        check(SecurityAnalyzer.analyze(List.of(ok), 1).alerts().isEmpty(), "success does not count as failure");
        try { SecurityAnalyzer.analyze(sample, 0); throw new AssertionError("zero threshold"); }
        catch (IllegalArgumentException expected) { check(true, "reject zero threshold"); }
        try { report.alerts().put("other", 9); throw new AssertionError("mutable report"); }
        catch (UnsupportedOperationException expected) { check(true, "immutable alert map"); }
        rejects("bad header\n", "reject incorrect header");
        rejects(header + "not-a-time,u,a,FAILURE\n", "reject timestamp");
        rejects(header + "2026-10-25T12:00:00Z,u,a,UNKNOWN\n", "reject result");
        rejects(header + "2026-10-25T12:00:00Z,,a,FAILURE\n", "reject empty user");
        rejects(header + "2026-10-25T12:00:00Z,u,a,FAILURE,extra\n", "reject extra column");
        rejects(header + "2026-10-25T12:00:00Z,\"u\",a,FAILURE\n", "reject unsupported quoting");
        Path empty = Files.createTempFile("security-empty-", ".csv");
        try {
            Files.writeString(empty, header + "\n");
            check(LogParser.read(empty).isEmpty(), "header-only and blank rows");
        } finally { Files.deleteIfExists(empty); }
        var outBytes = new ByteArrayOutputStream();
        var errBytes = new ByteArrayOutputStream();
        var out = new PrintStream(outBytes);
        var err = new PrintStream(errBytes);
        check(Main.run(new String[]{"sample/login-events.csv"}, out, err) == 0
                && outBytes.toString().contains("192.0.2.10 : 3 failures"), "CLI sample report");
        check(Main.run(new String[]{}, out, err) == 2, "CLI missing argument");
        check(Main.run(new String[]{"sample/login-events.csv", "bad"}, out, err) == 2, "CLI invalid threshold");
        check(Main.run(new String[]{"sample/login-events.csv", "-1"}, out, err) == 2, "CLI negative threshold");

        var twoMinutes = Duration.ofMinutes(2);
        var oneMinute = Duration.ofMinutes(1);
        check(SecurityAnalyzer.analyze(sample, 3, twoMinutes).alerts().equals(Map.of("192.0.2.10", 3)),
                "window includes exact two-minute boundary");
        check(SecurityAnalyzer.analyze(sample, 3, oneMinute).alerts().isEmpty(),
                "shorter window excludes third failure");
        check(SecurityAnalyzer.analyze(sample, 2, oneMinute).alerts().equals(Map.of("192.0.2.10", 2)),
                "window reports maximum count, not total failures");
        var unordered = List.of(
                failed("2026-10-25T12:02:00Z", "192.0.2.10"),
                failed("2026-10-25T12:00:00Z", "192.0.2.10"),
                failed("2026-10-25T12:01:00Z", "192.0.2.10"));
        check(SecurityAnalyzer.analyze(unordered, 3, twoMinutes).alerts().get("192.0.2.10") == 3,
                "window sorts out-of-order timestamps");
        var separated = List.of(
                failed("2026-10-25T12:00:00Z", "192.0.2.10"),
                failed("2026-10-25T12:10:00Z", "192.0.2.10"),
                failed("2026-10-25T12:11:00Z", "192.0.2.10"));
        check(SecurityAnalyzer.analyze(separated, 3, twoMinutes).alerts().isEmpty(),
                "distant failures do not combine in window");
        check(SecurityAnalyzer.analyze(separated, 2, twoMinutes).alerts().equals(Map.of("192.0.2.10", 2)),
                "window finds latest cluster");
        check(SecurityAnalyzer.analyze(List.of(
                failed("2026-10-25T12:00:00Z", "a"),
                failed("2026-10-25T12:01:00Z", "b")), 2, twoMinutes).alerts().isEmpty(),
                "window keeps addresses separate");
        check(SecurityAnalyzer.analyze(List.of(ok), 1, twoMinutes).alerts().isEmpty(),
                "window ignores successful logins");
        check(SecurityAnalyzer.analyze(List.of(), 1, twoMinutes).alerts().isEmpty(),
                "window accepts empty input");
        try { SecurityAnalyzer.analyze(sample, 1, Duration.ZERO); throw new AssertionError("zero window"); }
        catch (IllegalArgumentException expected) { check(true, "reject zero window"); }
        try { SecurityAnalyzer.analyze(sample, 1, Duration.ofSeconds(-1)); throw new AssertionError("negative window"); }
        catch (IllegalArgumentException expected) { check(true, "reject negative window"); }
        try { SecurityAnalyzer.analyze(sample, 1, null); throw new AssertionError("null window"); }
        catch (IllegalArgumentException expected) { check(true, "reject null window"); }
        var windowReport = SecurityAnalyzer.analyze(sample, 2, oneMinute);
        try { windowReport.alerts().clear(); throw new AssertionError("mutable window report"); }
        catch (UnsupportedOperationException expected) { check(true, "window report is immutable"); }
        outBytes.reset(); errBytes.reset();
        check(Main.run(new String[]{"sample/login-events.csv", "3", "2"}, out, err) == 0
                && outBytes.toString().contains("within any 2-minute window")
                && outBytes.toString().contains("192.0.2.10 : 3 failures"), "CLI window report");
        outBytes.reset(); errBytes.reset();
        check(Main.run(new String[]{"sample/login-events.csv", "3", "1"}, out, err) == 0
                && outBytes.toString().contains("None"), "CLI short window has no alerts");
        check(Main.run(new String[]{"sample/login-events.csv", "3", "0"}, out, err) == 2,
                "CLI rejects zero window");
        check(Main.run(new String[]{"sample/login-events.csv", "3", "abc"}, out, err) == 2,
                "CLI rejects nonnumeric window");
        check(Main.run(new String[]{"sample/login-events.csv", "3", "-5"}, out, err) == 2,
                "CLI rejects negative window");
        check(Main.run(new String[]{"sample/login-events.csv", "3", "2", "extra"}, out, err) == 2,
                "CLI rejects extra arguments");
        outBytes.reset(); errBytes.reset();
        check(Main.run(new String[]{"sample/login-events.csv", "--json"}, out, err) == 0
                && outBytes.toString().trim().equals(
                        "{\"total\":6,\"successful\":2,\"failed\":4,\"threshold\":3,\"windowMinutes\":null,\"alerts\":{\"192.0.2.10\":3}}")
                && errBytes.size() == 0, "CLI JSON full-file report");
        outBytes.reset(); errBytes.reset();
        check(Main.run(new String[]{"sample/login-events.csv", "3", "2", "--json"}, out, err) == 0
                && outBytes.toString().trim().equals(
                        "{\"total\":6,\"successful\":2,\"failed\":4,\"threshold\":3,\"windowMinutes\":2,\"alerts\":{\"192.0.2.10\":3}}"),
                "CLI JSON rolling-window report");
        outBytes.reset(); errBytes.reset();
        check(Main.run(new String[]{"sample/login-events.csv", "3", "1", "--json"}, out, err) == 0
                && outBytes.toString().contains("\"alerts\":{}"), "CLI JSON empty alerts");
        check(Main.toJson(new SecurityAnalyzer.Report(2, 0, 2,
                Map.of("quote\"slash\\tab\tline\n", 2)), 2, null)
                .contains("\"quote\\\"slash\\\\tab\\u0009line\\u000a\":2"),
                "JSON escapes quotes, backslashes and control characters");
        check(Main.toJson(new SecurityAnalyzer.Report(2, 0, 2,
                Map.of("z", 1, "a", 1)), 1, null).contains("\"a\":1,\"z\":1"),
                "JSON alert keys have deterministic order");
        outBytes.reset(); errBytes.reset();
        check(Main.run(new String[]{"--json"}, out, err) == 2
                && outBytes.size() == 0, "CLI rejects JSON flag without a file");
        outBytes.reset(); errBytes.reset();
        check(Main.run(new String[]{"sample/login-events.csv", "--json", "3"}, out, err) == 2
                && outBytes.size() == 0, "CLI rejects misplaced JSON flag");
        outBytes.reset(); errBytes.reset();
        check(Main.run(new String[]{"missing.csv", "--json"}, out, err) == 2
                && outBytes.size() == 0 && errBytes.size() > 0, "CLI JSON failure stays on stderr");
        Path manyEvents = Files.createTempFile("security-many-events-", ".csv");
        try {
            StringBuilder input = new StringBuilder(header);
            for (int i = 0; i < 5000; i++) {
                input.append("2026-10-25T12:00:00Z,test,192.0.2.10,")
                        .append(i % 3 == 0 ? "FAILURE" : "SUCCESS").append('\n');
            }
            Files.writeString(manyEvents, input.toString());
            var parsed = LogParser.read(manyEvents);
            check(parsed.size() == 5000, "read 5000 synthetic events");
            check(SecurityAnalyzer.analyze(parsed, 1).total() == 5000,
                    "analyze all synthetic events");
            Files.writeString(manyEvents, input.append("invalid,row\n").toString());
            try {
                LogParser.read(manyEvents);
                throw new AssertionError("missing invalid line error");
            } catch (IllegalArgumentException expected) {
                check(expected.getMessage().contains("line 5002"),
                        "report physical line number after many rows");
            }
        } finally {
            Files.deleteIfExists(manyEvents);
        }
        System.out.println("All " + passed + " checks passed.");
    }
}
