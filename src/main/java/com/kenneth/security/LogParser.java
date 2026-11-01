package com.kenneth.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/** Reads four-column CSV login events, including quoted fields on one line. */
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
            String header = reader.readLine();
            // Some CSV exports include a UTF-8 byte order mark before the header.
            if (header != null && header.startsWith("\uFEFF")) {
                header = header.substring(1);
            }
            if (!"timestamp,user,address,result".equals(header)) {
                throw new IllegalArgumentException("Expected header: timestamp,user,address,result");
            }
            String line;
            int lineNumber = 1;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (line.isBlank()) continue;
                LoginEvent event;
                try {
                    List<String> fields = splitCsvLine(line);
                    if (fields.size() != 4) throw new IllegalArgumentException();
                    for (String field : fields) {
                        if (field.isBlank() || !field.equals(field.trim())) {
                            throw new IllegalArgumentException();
                        }
                    }
                    if (!fields.get(3).equals("SUCCESS") && !fields.get(3).equals("FAILURE")) {
                        throw new IllegalArgumentException();
                    }
                    event = new LoginEvent(Instant.parse(fields.get(0)), fields.get(1),
                            fields.get(2), fields.get(3).equals("SUCCESS"));
                } catch (RuntimeException error) {
                    throw new IllegalArgumentException("Invalid event at line " + lineNumber, error);
                }
                // Caller failures are not malformed CSV records.
                accept.accept(event);
            }
        }
    }

    /** A small CSV reader for one physical line. Multiline fields aren't supported. */
    private static List<String> splitCsvLine(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder value = new StringBuilder();
        boolean inQuotes = false;
        boolean afterQuote = false;
        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);
            if (inQuotes) {
                if (ch == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        value.append('"');
                        i++;
                    } else {
                        inQuotes = false;
                        afterQuote = true;
                    }
                } else {
                    value.append(ch);
                }
            } else if (ch == ',') {
                fields.add(value.toString());
                value.setLength(0);
                afterQuote = false;
            } else if (afterQuote) {
                throw new IllegalArgumentException("Text after quoted field");
            } else if (ch == '"') {
                if (value.length() != 0) throw new IllegalArgumentException("Quote in unquoted field");
                inQuotes = true;
            } else {
                value.append(ch);
            }
        }
        if (inQuotes) throw new IllegalArgumentException("Unclosed quoted field");
        fields.add(value.toString());
        return fields;
    }
}
