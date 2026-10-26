package com.kenneth.security;

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
        return analyzeInternal(events, threshold, null);
    }

    /** Alert on the maximum number of failures in any inclusive rolling window. */
    public static Report analyze(List<LoginEvent> events, int threshold, Duration window) {
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("Window must be a positive duration");
        }
        return analyzeInternal(events, threshold, window);
    }

    private static Report analyzeInternal(List<LoginEvent> events, int threshold, Duration window) {
        if (threshold < 1) throw new IllegalArgumentException("Threshold must be at least 1");
        int successful = 0;
        Map<String, List<Instant>> failures = new TreeMap<>();
        for (LoginEvent event : events) {
            if (event.success()) {
                successful++;
            } else {
                failures.computeIfAbsent(event.address(), key -> new ArrayList<>())
                        .add(event.timestamp());
            }
        }

        Map<String, Integer> alerts = new TreeMap<>();
        for (var entry : failures.entrySet()) {
            int count = window == null ? entry.getValue().size()
                    : maxFailuresInWindow(entry.getValue(), window);
            if (count >= threshold) alerts.put(entry.getKey(), count);
        }
        return new Report(events.size(), successful, events.size() - successful, alerts);
    }

    private static int maxFailuresInWindow(List<Instant> timestamps, Duration window) {
        List<Instant> ordered = new ArrayList<>(timestamps);
        ordered.sort(Instant::compareTo);
        int left = 0;
        int maximum = 0;
        for (int right = 0; right < ordered.size(); right++) {
            while (Duration.between(ordered.get(left), ordered.get(right)).compareTo(window) > 0) {
                left++;
            }
            maximum = Math.max(maximum, right - left + 1);
        }
        return maximum;
    }
}
