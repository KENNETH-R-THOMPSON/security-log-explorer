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
        check(SecurityAnalyzer.analyzeFile(Path.of("sample/login-events.csv"), 3).equals(report),
                "streamed full-file report matches list analysis");
        check(SecurityAnalyzer.analyze(sample, 4).alerts().isEmpty(), "higher threshold excludes address");
        check(SecurityAnalyzer.analyze(List.of(), 1).total() == 0, "empty input");
        var ok = new LoginEvent(Instant.EPOCH, "user", "address", true);
        check(SecurityAnalyzer.analyze(List.of(ok), 1).alerts().isEmpty(), "success does not count as failure");
        try { SecurityAnalyzer.analyze(sample, 0); throw new AssertionError("zero threshold"); }
        catch (IllegalArgumentException expected) { check(true, "reject zero threshold"); }
        try { report.alerts().put("other", 9); throw new AssertionError("mutable report"); }
        catch (UnsupportedOperationException expected) { check(true, "immutable alert map"); }
        rejects("bad header\n", "reject incorrect header");
        Path bomFile = Files.createTempFile("security-bom-", ".csv");
        try {
            Files.writeString(bomFile, "\uFEFFtimestamp,user,address,result\r\n"
                    + "2026-10-25T12:00:00Z,u,198.51.100.2,FAILURE\r\n");
            var bomEvents = LogParser.read(bomFile);
            check(bomEvents.size() == 1 && bomEvents.get(0).address().equals("198.51.100.2"),
                    "read UTF-8 BOM header with CRLF lines");
            check(SecurityAnalyzer.analyzeFile(bomFile, 1).alerts().equals(Map.of("198.51.100.2", 1)),
                    "stream BOM-prefixed CSV into analyzer");
        } finally { Files.deleteIfExists(bomFile); }
        rejects("\uFEFFwrong,user,address,result\n", "reject incorrect BOM-prefixed header");
        rejects(header + "not-a-time,u,a,FAILURE\n", "reject timestamp");
        rejects(header + "2026-10-25T12:00:00Z,u,a,UNKNOWN\n", "reject result");
        rejects(header + "2026-10-25T12:00:00Z,,a,FAILURE\n", "reject empty user");
        rejects(header + "2026-10-25T12:00:00Z,u,a,FAILURE,extra\n", "reject extra column");
        Path quoted = Files.createTempFile("security-quoted-", ".csv");
        try {
            Files.writeString(quoted, header
                    + "\"2026-10-25T12:00:00Z\",\"sam, jr\",\"192.0.2.10\",FAILURE\n"
                    + "2026-10-25T12:01:00Z,\"sam \"\"junior\"\"\",192.0.2.10,SUCCESS\n");
            var quotedEvents = LogParser.read(quoted);
            check(quotedEvents.size() == 2 && quotedEvents.get(0).user().equals("sam, jr"),
                    "read quoted commas");
            check(quotedEvents.get(1).user().equals("sam \"junior\""),
                    "read escaped CSV quotes");
            check(SecurityAnalyzer.analyzeFile(quoted, 1)
                    .equals(SecurityAnalyzer.analyze(quotedEvents, 1)),
                    "streamed quoted CSV matches list analysis");
            try {
                LogParser.forEach(quoted, event -> {
                    throw new IllegalStateException("consumer failed");
                });
                throw new AssertionError("consumer failure was swallowed");
            } catch (IllegalStateException expected) {
                check("consumer failed".equals(expected.getMessage()),
                        "preserve consumer exception type and message");
            }
            try {
                LogParser.forEach(quoted, event -> {
                    throw new IllegalArgumentException("caller rejected event");
                });
                throw new AssertionError("consumer rejection was swallowed");
            } catch (IllegalArgumentException expected) {
                check("caller rejected event".equals(expected.getMessage()),
                        "do not label consumer rejection as invalid CSV");
            }
        } finally { Files.deleteIfExists(quoted); }
        rejects(header + "2026-10-25T12:00:00Z,\"unfinished,a,FAILURE\n",
                "reject unclosed quoted field");
        rejects(header + "2026-10-25T12:00:00Z,\"sam\"extra,a,FAILURE\n",
                "reject characters after quoted field");
        rejects(header + "2026-10-25T12:00:00Z,sam\"bad,a,FAILURE\n",
                "reject quote inside unquoted field");
        rejects(header + "2026-10-25T12:00:00Z,\"sam\",a,FAILURE,extra\n",
                "reject extra column after quoted field");
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
        check(Main.printableAddress("192.0.2.10").equals("192.0.2.10"),
                "ordinary address stays readable");
        check(Main.printableAddress("192.0.2.10\\tag").equals("192.0.2.10\\\\tag"),
                "escape literal backslash in text address");
        check(!Main.printableAddress("192.0.2.10\\u001b")
                .equals(Main.printableAddress("192.0.2.10" + (char) 27)),
                "literal escape text differs from a control character");
        String unsafeAddress = "192.0.2.10" + (char) 27 + "[31m" + (char) 0x202e;
        String escapedAddress = "192.0.2.10" + "\\" + "u001b[31m" + "\\" + "u202e";
        check(Main.printableAddress(unsafeAddress).equals(escapedAddress),
                "escape terminal and bidirectional controls");
        Path controlFile = Files.createTempFile("security-control-address-", ".csv");
        try {
            Files.writeString(controlFile, header
                    + "2026-10-25T12:00:00Z,test," + unsafeAddress + ",FAILURE\n");
            outBytes.reset();
            errBytes.reset();
            check(Main.run(new String[]{controlFile.toString(), "1"}, out, err) == 0
                    && outBytes.toString().contains(escapedAddress + " : 1 failures")
                    && !outBytes.toString().contains(unsafeAddress),
                    "CLI text report escapes unsafe address");
            outBytes.reset();
            errBytes.reset();
            check(Main.run(new String[]{controlFile.toString(), "1", "--json"}, out, err) == 0
                    && outBytes.toString().contains("\\u001b")
                    && outBytes.toString().contains(String.valueOf((char) 0x202e)),
                    "JSON report preserves machine-readable address");
        } finally {
            Files.deleteIfExists(controlFile);
        }
        check(Main.run(new String[]{}, out, err) == 2, "CLI missing argument");
        check(Main.run(new String[]{"sample/login-events.csv", "bad"}, out, err) == 2, "CLI invalid threshold");
        outBytes.reset(); errBytes.reset();
        String unsafeThreshold = "bad" + (char) 27 + "[31m";
        check(Main.run(new String[]{"sample/login-events.csv", unsafeThreshold}, out, err) == 2
                && outBytes.size() == 0
                && !errBytes.toString().contains(String.valueOf((char) 27))
                && errBytes.toString().contains("\\u001b[31m"),
                "CLI error escapes terminal control characters");
        outBytes.reset(); errBytes.reset();
        String bidiThreshold = "bad" + (char) 0x202e;
        check(Main.run(new String[]{"sample/login-events.csv", bidiThreshold}, out, err) == 2
                && outBytes.size() == 0
                && !errBytes.toString().contains(String.valueOf((char) 0x202e))
                && errBytes.toString().contains("\\u202e"),
                "CLI error escapes bidirectional formatting characters");

        check(Main.run(new String[]{"sample/login-events.csv", "-1"}, out, err) == 2, "CLI negative threshold");

        var twoMinutes = Duration.ofMinutes(2);
        var oneMinute = Duration.ofMinutes(1);
        check(SecurityAnalyzer.analyzeFile(Path.of("sample/login-events.csv"), 3, twoMinutes)
                .equals(SecurityAnalyzer.analyze(sample, 3, twoMinutes)),
                "streamed rolling-window report matches list analysis");
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
            check(SecurityAnalyzer.analyzeFile(manyEvents, 1).total() == 5000,
                    "stream 5000 events without building a list");
            Files.writeString(manyEvents, input.append("invalid,row\n").toString());
            try {
                LogParser.read(manyEvents);
                throw new AssertionError("missing invalid line error");
            } catch (IllegalArgumentException expected) {
                check(expected.getMessage().contains("line 5002"),
                        "report physical line number after many rows");
            }
            try {
                SecurityAnalyzer.analyzeFile(manyEvents, 1);
                throw new AssertionError("missing streamed invalid line error");
            } catch (IllegalArgumentException expected) {
                check(expected.getMessage().contains("line 5002"),
                        "streaming reports physical line number after many rows");
            }
        } finally {
            Files.deleteIfExists(manyEvents);
        }
        var mixedUsers = List.of(
                new LoginEvent(Instant.parse("2026-10-25T12:00:00Z"), "sam", "192.0.2.1", false),
                new LoginEvent(Instant.parse("2026-10-25T12:01:00Z"), "sam", "192.0.2.2", false),
                new LoginEvent(Instant.parse("2026-10-25T12:02:00Z"), "alex", "192.0.2.1", false));
        check(SecurityAnalyzer.analyzeByUser(mixedUsers, 2).alerts().equals(Map.of("sam", 2)),
                "user grouping combines different addresses");
        check(SecurityAnalyzer.analyze(mixedUsers, 2).alerts().equals(Map.of("192.0.2.1", 2)),
                "default grouping remains address-based");
        check(SecurityAnalyzer.analyzeByUser(mixedUsers, 2, Duration.ofMinutes(1))
                .alerts().equals(Map.of("sam", 2)), "user window includes exact boundary");
        check(SecurityAnalyzer.analyzeByUser(mixedUsers, 2, Duration.ofSeconds(30))
                .alerts().isEmpty(), "short user window excludes distant failures");
        check(SecurityAnalyzer.analyzeFileByUser(Path.of("sample/login-events.csv"), 3)
                .equals(SecurityAnalyzer.analyzeByUser(sample, 3)),
                "streamed user summary matches list analysis");
        check(SecurityAnalyzer.analyzeFileByUser(Path.of("sample/login-events.csv"), 3, twoMinutes)
                .equals(SecurityAnalyzer.analyzeByUser(sample, 3, twoMinutes)),
                "streamed user window matches list analysis");
        outBytes.reset(); errBytes.reset();
        check(Main.run(new String[]{"sample/login-events.csv", "3", "--by-user"}, out, err) == 0
                && outBytes.toString().contains("Users with at least 3 failures")
                && outBytes.toString().contains("alex : 3 failures"),
                "CLI user text report");
        outBytes.reset(); errBytes.reset();
        check(Main.run(new String[]{"sample/login-events.csv", "3", "2", "--by-user", "--json"},
                out, err) == 0 && outBytes.toString().contains("\"groupBy\":\"user\"")
                && outBytes.toString().contains("\"alerts\":{\"alex\":3}"),
                "CLI user rolling JSON report");
        outBytes.reset(); errBytes.reset();
        check(Main.run(new String[]{"sample/login-events.csv", "--by-user", "--json"},
                out, err) == 0 && outBytes.toString().contains("\"alerts\":{\"alex\":3}"),
                "CLI user default threshold");
        outBytes.reset(); errBytes.reset();
        check(Main.run(new String[]{"sample/login-events.csv", "--json", "--by-user"},
                out, err) == 2 && outBytes.size() == 0,
                "reject flag after JSON");
        System.out.println("All " + passed + " checks passed.");
    }
}
