package com.kenneth.security;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.time.Duration;

public final class Main {
    private Main() {}

    public static void main(String[] args) {
        int result = run(args, System.out, System.err);
        if (result != 0) System.exit(result);
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        boolean json = args.length > 0 && args[args.length - 1].equals("--json");
        int valueCount = args.length - (json ? 1 : 0);
        if (valueCount < 1 || valueCount > 3) {
            err.println("Usage: Main <events.csv> [failure-threshold] [window-minutes] [--json]");
            return 2;
        }
        try {
            int threshold = valueCount >= 2 ? Integer.parseInt(args[1]) : 3;
            Integer windowMinutes = valueCount == 3 ? Integer.parseInt(args[2]) : null;
            var path = Path.of(args[0]);
            var report = windowMinutes == null
                    ? SecurityAnalyzer.analyzeFile(path, threshold)
                    : SecurityAnalyzer.analyzeFile(path, threshold, Duration.ofMinutes(windowMinutes));
            if (json) {
                out.println(toJson(report, threshold, windowMinutes));
                return 0;
            }
            out.println("Security Log Explorer");
            out.printf("Events: %d | Successful: %d | Failed: %d%n",
                    report.total(), report.successful(), report.failed());
            String scope = windowMinutes != null
                    ? "within any " + args[2] + "-minute window"
                    : "across this file";
            out.println("Addresses with at least " + threshold + " failures " + scope + ":");
            if (report.alerts().isEmpty()) out.println("None");
            report.alerts().forEach((address, count) -> out.println(address + " : " + count + " failures"));
            out.println("Alerts are investigation leads, not proof of an attack.");
            return 0;
        } catch (IOException | IllegalArgumentException error) {
            err.println("Error: " + error.getMessage());
            return 2;
        }
    }

    /** One-line JSON for tools that need to read the report. */
    static String toJson(SecurityAnalyzer.Report report, int threshold, Integer windowMinutes) {
        StringBuilder json = new StringBuilder();
        json.append("{\"total\":").append(report.total())
                .append(",\"successful\":").append(report.successful())
                .append(",\"failed\":").append(report.failed())
                .append(",\"threshold\":").append(threshold)
                .append(",\"windowMinutes\":");
        json.append(windowMinutes == null ? "null" : windowMinutes);
        json.append(",\"alerts\":{");
        boolean first = true;
        for (var alert : report.alerts().entrySet()) {
            if (!first) json.append(',');
            first = false;
            json.append('"').append(escapeJson(alert.getKey())).append("\":")
                    .append(alert.getValue());
        }
        return json.append("}}").toString();
    }

    private static String escapeJson(String value) {
        StringBuilder escaped = new StringBuilder();
        String hex = "0123456789abcdef";
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch == '"' || ch == '\\') {
                escaped.append('\\').append(ch);
            } else if (ch < 0x20) {
                escaped.append("\\u00").append(hex.charAt(ch >> 4)).append(hex.charAt(ch & 15));
            } else {
                escaped.append(ch);
            }
        }
        return escaped.toString();
    }
}
