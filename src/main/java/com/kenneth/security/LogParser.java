package com.kenneth.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** Strict four-column CSV parser; quoted fields are deliberately unsupported. */
public final class LogParser {
    private LogParser() {}

    public static List<LoginEvent> read(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path);
        if (lines.isEmpty() || !lines.get(0).equals("timestamp,user,address,result")) {
            throw new IllegalArgumentException("Expected header: timestamp,user,address,result");
        }
        List<LoginEvent> events = new ArrayList<>();
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isBlank()) continue;
            String[] fields = line.split(",", -1);
            try {
                if (fields.length != 4) throw new IllegalArgumentException();
                for (String field : fields) {
                    if (field.isBlank() || field.contains("\"") || !field.equals(field.trim())) {
                        throw new IllegalArgumentException();
                    }
                }
                if (!fields[3].equals("SUCCESS") && !fields[3].equals("FAILURE")) {
                    throw new IllegalArgumentException();
                }
                events.add(new LoginEvent(Instant.parse(fields[0]), fields[1], fields[2],
                        fields[3].equals("SUCCESS")));
            } catch (RuntimeException error) {
                throw new IllegalArgumentException("Invalid event at line " + (i + 1), error);
            }
        }
        return List.copyOf(events);
    }
}
