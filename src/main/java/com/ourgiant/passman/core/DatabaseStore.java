package com.ourgiant.passman.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ourgiant.passman.model.DatabaseWrapper;
import com.ourgiant.passman.model.PasswordEntry;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileSystems;
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
import java.util.Set;

public final class DatabaseStore {

    private static final Path DB_PATH = getDatabaseFilePath();
    public static final String DB_FILE = DB_PATH.toString();

    private DatabaseStore() {}

    private static Path getDatabaseFilePath() {
        String localAppData = System.getenv("LOCALAPPDATA");
        if (localAppData == null || localAppData.isBlank()) {
            localAppData = Paths.get(System.getProperty("user.home"), "AppData", "Local").toString();
        }

        Path dir = Paths.get(localAppData, "JavaPassManager");
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to create data directory: " + dir, e);
        }

        File db_file = (dir.resolve("passwords.enc")).toFile();
        String canonicalPath = "";
        try {
            canonicalPath = db_file.getCanonicalPath();
            if (!canonicalPath.startsWith(FileSystems.getDefault().getSeparator())) {}
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to create database: " + canonicalPath, e);
        }

        return dir.resolve("passwords.enc");
    }

    public static void restrictToCurrentUser(Path path) {
        try {
            AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class);
            if (view == null) {
                System.err.println("ACLs not supported on this filesystem.");
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
                System.err.println("SYSTEM principal not found: " + e);
            }

            try {
                UserPrincipal admins = lookupService.lookupPrincipalByName("Administrators");
                acl.add(AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(admins)
                        .setPermissions(perms)
                        .build());
            } catch (IOException e) {
                System.err.println("Administrators principal not found: " + e);
            }

            view.setAcl(acl);
        } catch (Exception e) {
            System.err.println("Warning: failed to set ACL for " + path + ": " + e);
        }
    }

    public static byte[] loadSalt() throws Exception {
        byte[] salt = CryptoService.generateSalt(32);
        try (FileInputStream fis = new FileInputStream(DB_FILE)) {
            fis.read(salt);
        }
        return salt;
    }

    public static void saveDatabase(byte[] salt, SecretKey masterKey, List<PasswordEntry> passwords, String totpSecret) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.findAndRegisterModules(); // Automatically finds jackson-datatype-jsr310
        DatabaseWrapper wrapper = new DatabaseWrapper();
        wrapper.setPasswords(passwords);
        wrapper.setTotpSecret(totpSecret);

        byte[] jsonData = mapper.writeValueAsBytes(wrapper);

        if (salt == null) {
            salt = loadSalt();
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = CryptoService.generateIv(12);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(CryptoService.GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, masterKey, gcmSpec);

        byte[] encrypted = cipher.doFinal(jsonData);

        try (FileOutputStream fos = new FileOutputStream(DB_FILE)) {
            fos.write(salt);
            fos.write(iv);
            fos.write(encrypted);
        }
    }

    @SuppressWarnings("unchecked")
    public static DatabaseWrapper loadDatabase(SecretKey masterKey) throws Exception {
        final int SALT_LEN = 32;
        final int IV_LEN = 12;           // Standard for GCM
        final int GCM_TAG_LEN_BITS = 128;

        Path path = Paths.get(DB_FILE);
        if (!Files.exists(path)) {
            // no existing database file
            DatabaseWrapper empty = new DatabaseWrapper();
            empty.setPasswords(new ArrayList<>());
            empty.setTotpSecret(null);
            return empty;
        }

        try (FileInputStream fis = new FileInputStream(DB_FILE)) {
            // --- Read salt and IV from file header ---
            byte[] salt = fis.readNBytes(SALT_LEN);
            if (salt.length != SALT_LEN)
                throw new IOException("Corrupted file: missing salt");

            byte[] iv = fis.readNBytes(IV_LEN);
            if (iv.length != IV_LEN)
                throw new IOException("Corrupted file: missing IV");

            // --- Initialize cipher for AES-GCM decryption ---
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LEN_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, masterKey, gcmSpec);

            // --- Decrypt the rest of the file ---
            byte[] encrypted = fis.readAllBytes();
            byte[] decrypted = cipher.doFinal(encrypted);

            // --- Parse JSON into the DatabaseWrapper object ---
            ObjectMapper mapper = new ObjectMapper();
            mapper.findAndRegisterModules();  // e.g. JavaTimeModule if needed
            return mapper.readValue(decrypted, DatabaseWrapper.class);

        } catch (javax.crypto.AEADBadTagException e) {
            throw new SecurityException("Decryption failed: wrong key or tampered file", e);
        }
    }
}
