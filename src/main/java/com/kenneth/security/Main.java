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
        if (args.length < 1 || args.length > 3) {
            err.println("Usage: Main <events.csv> [failure-threshold] [window-minutes]");
            return 2;
        }
        try {
            int threshold = args.length >= 2 ? Integer.parseInt(args[1]) : 3;
            var events = LogParser.read(Path.of(args[0]));
            var report = args.length == 3
                    ? SecurityAnalyzer.analyze(events, threshold, Duration.ofMinutes(
                            Integer.parseInt(args[2])))
                    : SecurityAnalyzer.analyze(events, threshold);
            out.println("Security Log Explorer");
            out.printf("Events: %d | Successful: %d | Failed: %d%n",
                    report.total(), report.successful(), report.failed());
            String scope = args.length == 3
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
}
