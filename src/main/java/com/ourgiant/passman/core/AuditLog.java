package com.ourgiant.passman.core;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public final class AuditLog {

    private static final Path LOG_PATH = AppPaths.getAppDataDir().resolve("audit.log");

    private AuditLog() {}

    public static void log(String message) {
        try {
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
            String logEntry = timestamp + " - " + message + "\n";
            Files.write(LOG_PATH, logEntry.getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            AppPaths.restrictToCurrentUser(LOG_PATH);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
