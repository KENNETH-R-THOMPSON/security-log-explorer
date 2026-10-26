package com.kenneth.security;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Counts failures across the complete input, not a rolling time window. */
public final class SecurityAnalyzer {
    private SecurityAnalyzer() {}

    public record Report(int total, int successful, int failed, Map<String, Integer> alerts) {
        public Report {
            alerts = java.util.Collections.unmodifiableMap(new TreeMap<>(alerts));
        }
    }

    public static Report analyze(List<LoginEvent> events, int threshold) {
        if (threshold < 1) throw new IllegalArgumentException("Threshold must be at least 1");
        int successful = 0;
        Map<String, Integer> failures = new TreeMap<>();
        for (LoginEvent event : events) {
            if (event.success()) successful++;
            else failures.merge(event.address(), 1, Integer::sum);
        }
        Map<String, Integer> alerts = new TreeMap<>();
        failures.forEach((address, count) -> {
            if (count >= threshold) alerts.put(address, count);
        });
        return new Report(events.size(), successful, events.size() - successful, alerts);
    }
}
