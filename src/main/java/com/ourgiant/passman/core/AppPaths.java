package com.ourgiant.passman.core;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves a platform-appropriate app data directory and hardens file
 * permissions on the files stored there, shared by {@link DatabaseStore}
 * and {@link AuditLog} so the encrypted DB and the audit log always live
 * in the same, correctly-permissioned place.
 */
public final class AppPaths {

    private static final Logger logger = LoggerFactory.getLogger(AppPaths.class);

    private AppPaths() {}

    public static Path getAppDataDir() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        Path dir;

        if (os.contains("win")) {
            String localAppData = System.getenv("LOCALAPPDATA");
            if (localAppData == null || localAppData.isBlank()) {
                localAppData = Paths.get(System.getProperty("user.home"), "AppData", "Local").toString();
            }
            dir = Paths.get(localAppData, "JavaPassManager");
        } else if (os.contains("mac")) {
            dir = Paths.get(System.getProperty("user.home"), "Library", "Application Support", "JavaPassManager");
        } else {
            String xdgDataHome = System.getenv("XDG_DATA_HOME");
            if (xdgDataHome == null || xdgDataHome.isBlank()) {
                xdgDataHome = Paths.get(System.getProperty("user.home"), ".local", "share").toString();
            }
            dir = Paths.get(xdgDataHome, "JavaPassManager");
        }

        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to create data directory: " + dir, e);
        }

        return dir;
    }

    public static void restrictToCurrentUser(Path path) {
        try {
            AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class);
            if (view == null) {
                logger.warn("ACLs not supported on this filesystem.");
                return;
            }

            UserPrincipalLookupService lookupService = path.getFileSystem().getUserPrincipalLookupService();
            UserPrincipal user = lookupService.lookupPrincipalByName(System.getProperty("user.name"));

            List<AclEntry> acl = new ArrayList<>();
            Set<AclEntryPermission> perms = EnumSet.of(
                    AclEntryPermission.READ_DATA,
                    AclEntryPermission.WRITE_DATA,
                    AclEntryPermission.APPEND_DATA,
                    AclEntryPermission.READ_ATTRIBUTES,
                    AclEntryPermission.WRITE_ATTRIBUTES,
                    AclEntryPermission.READ_ACL,
                    AclEntryPermission.WRITE_ACL,
                    AclEntryPermission.WRITE_OWNER,
                    AclEntryPermission.DELETE
            );

            acl.add(AclEntry.newBuilder()
                    .setType(AclEntryType.ALLOW)
                    .setPrincipal(user)
                    .setPermissions(perms)
                    .build());

            try {
                UserPrincipal system = lookupService.lookupPrincipalByName("SYSTEM");
                acl.add(AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(system)
                        .setPermissions(perms)
                        .build());
            } catch (IOException e) {
                logger.debug("SYSTEM principal not found: {}", e.getMessage());
            }

            try {
                UserPrincipal admins = lookupService.lookupPrincipalByName("Administrators");
                acl.add(AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(admins)
                        .setPermissions(perms)
                        .build());
            } catch (IOException e) {
                logger.debug("Administrators principal not found: {}", e.getMessage());
            }

            view.setAcl(acl);
        } catch (Exception e) {
            logger.warn("Failed to set ACL for {}", path, e);
        }
    }
}
