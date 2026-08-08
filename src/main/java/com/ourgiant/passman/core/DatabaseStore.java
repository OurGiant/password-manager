package com.ourgiant.passman.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ourgiant.passman.model.DatabaseWrapper;
import com.ourgiant.passman.model.PasswordEntry;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public final class DatabaseStore {

    private static final Path DB_PATH = AppPaths.getAppDataDir().resolve("passwords.enc");
    public static final String DB_FILE = DB_PATH.toString();

    private DatabaseStore() {}

    public static byte[] loadSalt() throws Exception {
        byte[] salt = CryptoService.generateSalt(32);
        try (FileInputStream fis = new FileInputStream(DB_FILE)) {
            fis.read(salt);
        }
        return salt;
    }

    public static void saveDatabase(byte[] salt, SecretKey masterKey, List<PasswordEntry> passwords, char[] totpSecret) throws Exception {
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

        AppPaths.restrictToCurrentUser(DB_PATH);
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
