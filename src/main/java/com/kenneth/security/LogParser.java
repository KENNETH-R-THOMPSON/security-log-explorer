package com.kenneth.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/** Strict four-column CSV parser; quoted fields are deliberately unsupported. */
public final class LogParser {
    private LogParser() {}

    public static List<LoginEvent> read(Path path) throws IOException {
        List<LoginEvent> events = new ArrayList<>();
        forEach(path, events::add);
        return List.copyOf(events);
    }

    /** Validate and pass each event to the caller without storing the whole file. */
    public static void forEach(Path path, Consumer<LoginEvent> accept) throws IOException {
        try (var reader = Files.newBufferedReader(path)) {
            if (!"timestamp,user,address,result".equals(reader.readLine())) {
                throw new IllegalArgumentException("Expected header: timestamp,user,address,result");
            }
            String line;
            int lineNumber = 1;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
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
                    accept.accept(new LoginEvent(Instant.parse(fields[0]), fields[1], fields[2],
                            fields[3].equals("SUCCESS")));
                } catch (RuntimeException error) {
                    throw new IllegalArgumentException("Invalid event at line " + lineNumber, error);
                }
            }
        }
    }
}
