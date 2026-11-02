package com.kenneth.security;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Summarizes sign-in events and detects repeated failures by address. */
public final class SecurityAnalyzer {
    private SecurityAnalyzer() {}

    public record Report(int total, int successful, int failed, Map<String, Integer> alerts) {
        public Report {
            alerts = java.util.Collections.unmodifiableMap(new TreeMap<>(alerts));
        }
    }

    /** Existing behavior: count failures across the entire input file. */
    public static Report analyze(List<LoginEvent> events, int threshold) {
        return analyzeInternal(events, threshold, null, false);
    }

    /** Alert on the maximum number of failures in any inclusive rolling window. */
    public static Report analyze(List<LoginEvent> events, int threshold, Duration window) {
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("Window must be a positive duration");
        }
        return analyzeInternal(events, threshold, window, false);
    }

    /** Analyze a CSV file without building a list of all login events. */
    public static Report analyzeFile(Path path, int threshold) throws IOException {
        return analyzeFileInternal(path, threshold, null, false);
    }

    public static Report analyzeFile(Path path, int threshold, Duration window) throws IOException {
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("Window must be a positive duration");
        }
        return analyzeFileInternal(path, threshold, window, false);
    }

    /** Count failures by fictional username instead of network address. */
    public static Report analyzeByUser(List<LoginEvent> events, int threshold) {
        return analyzeInternal(events, threshold, null, true);
    }

    public static Report analyzeByUser(List<LoginEvent> events, int threshold, Duration window) {
        if (window == null || window.isZero() || window.isNegative())
            throw new IllegalArgumentException("Window must be a positive duration");
        return analyzeInternal(events, threshold, window, true);
    }

    public static Report analyzeFileByUser(Path path, int threshold) throws IOException {
        return analyzeFileInternal(path, threshold, null, true);
    }

    public static Report analyzeFileByUser(Path path, int threshold, Duration window) throws IOException {
        if (window == null || window.isZero() || window.isNegative())
            throw new IllegalArgumentException("Window must be a positive duration");
        return analyzeFileInternal(path, threshold, window, true);
    }

    private static Report analyzeFileInternal(Path path, int threshold, Duration window, boolean byUser) throws IOException {
        if (threshold < 1) throw new IllegalArgumentException("Threshold must be at least 1");
        Summary summary = new Summary(window, byUser);
        LogParser.forEach(path, summary::accept);
        return summary.report(threshold);
    }

    private static Report analyzeInternal(List<LoginEvent> events, int threshold, Duration window, boolean byUser) {
        if (threshold < 1) throw new IllegalArgumentException("Threshold must be at least 1");
        Summary summary = new Summary(window, byUser);
        for (LoginEvent event : events) summary.accept(event);
        return summary.report(threshold);
    }

    /** Full-file mode keeps counts; window mode keeps only failure timestamps. */
    private static final class Summary {
        private final Duration window;
        private final boolean byUser;
        private final Map<String, Integer> counts = new TreeMap<>();
        private final Map<String, List<Instant>> timestamps = new TreeMap<>();
        private int total;
        private int successful;

        private Summary(Duration window, boolean byUser) {
            this.window = window;
            this.byUser = byUser;
        }

        private void accept(LoginEvent event) {
            total++;
            if (event.success()) {
                successful++;
            } else {
                String key = byUser ? event.user() : event.address();
                if (window == null) {
                    counts.merge(key, 1, Integer::sum);
                } else {
                    timestamps.computeIfAbsent(key, name -> new ArrayList<>()).add(event.timestamp());
                }
            }
        }

        private Report report(int threshold) {
            Map<String, Integer> alerts = new TreeMap<>();
            if (window == null) {
                for (var entry : counts.entrySet()) {
                    if (entry.getValue() >= threshold) alerts.put(entry.getKey(), entry.getValue());
                }
            } else {
                for (var entry : timestamps.entrySet()) {
                    int maximum = maxFailuresInWindow(entry.getValue(), window);
                    if (maximum >= threshold) alerts.put(entry.getKey(), maximum);
                }
            }
            return new Report(total, successful, total - successful, alerts);
        }
    }

    private static int maxFailuresInWindow(List<Instant> timestamps, Duration window) {
        // Summary owns this list, so sorting it here avoids a second list of references.
        timestamps.sort(Instant::compareTo);
        int left = 0;
        int maximum = 0;
        for (int right = 0; right < timestamps.size(); right++) {
            while (Duration.between(timestamps.get(left), timestamps.get(right)).compareTo(window) > 0) {
                left++;
            }
            maximum = Math.max(maximum, right - left + 1);
        }
        return maximum;
    }
}
