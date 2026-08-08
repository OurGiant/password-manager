package com.ourgiant.passman.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AppPathsTest {

    /**
     * AclFileAttributeView (the NFSv4 ACL model restrictToCurrentUser tries
     * first) isn't satisfied by POSIX/ext4 filesystems, so this exercises the
     * POSIX 0600 fallback path directly on Linux/macOS CI runners.
     */
    @Test
    @EnabledOnOs({OS.LINUX, OS.MAC})
    void restrictToCurrentUser_onPosixFilesystem_setsOwnerOnlyPermissions() throws Exception {
        Path file = Files.createTempFile("appPathsTest", ".tmp");
        try {
            // Start from wide-open permissions so the test can't pass by accident.
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-rw-rw-"));

            AppPaths.restrictToCurrentUser(file);

            Set<PosixFilePermission> actual = Files.getPosixFilePermissions(file);
            assertEquals(PosixFilePermissions.fromString("rw-------"), actual,
                "expected owner-only (0600) permissions after restrictToCurrentUser");
        } finally {
            Files.deleteIfExists(file);
        }
    }
}
