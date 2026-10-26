package com.kenneth.security;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

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
    public static void main(String[] args) throws Exception {
        String header = "timestamp,user,address,result\n";
        var sample = LogParser.read(Path.of("sample/login-events.csv"));
        var report = SecurityAnalyzer.analyze(sample, 3);
        check(report.total() == 6 && report.successful() == 2 && report.failed() == 4, "sample totals");
        check(report.alerts().equals(java.util.Map.of("192.0.2.10", 3)), "inclusive threshold and grouping");
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
        System.out.println("All " + passed + " checks passed.");
    }
}
