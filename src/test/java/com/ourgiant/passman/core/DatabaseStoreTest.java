package com.ourgiant.passman.core;

import com.ourgiant.passman.model.DatabaseWrapper;
import com.ourgiant.passman.model.PasswordEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DatabaseStoreTest {

    @BeforeEach
    void resetDatabaseFile() throws Exception {
        // DatabaseStore.DB_FILE is shared across tests in this class (resolved once
        // at class-load, redirected under target/test-app-data by the surefire
        // system property in pom.xml — see AppPaths.getAppDataDir()). Reset it
        // before every test so tests don't see each other's state.
        Files.deleteIfExists(Paths.get(DatabaseStore.DB_FILE));
    }

    @Test
    void databaseFile_isRedirectedAwayFromRealUserHome() {
        String override = System.getProperty("passman.appDataDir");
        assertNotNull(override, "test JVM must set passman.appDataDir (see pom.xml surefire config)");
        assertTrue(DatabaseStore.DB_FILE.startsWith(override),
            "DB_FILE should resolve under the test override, not the real user's app data dir");
    }

    @Test
    void loadDatabase_onMissingFile_returnsEmptyWrapper() throws Exception {
        SecretKey key = CryptoService.deriveKey("irrelevant".toCharArray(), CryptoService.generateSalt(32));
        DatabaseWrapper wrapper = DatabaseStore.loadDatabase(key);
        assertNotNull(wrapper.getPasswords());
        assertTrue(wrapper.getPasswords().isEmpty());
        assertNull(wrapper.getTotpSecret());
    }

    @Test
    void saveAndLoad_roundTripsPasswordsAndTotpSecret() throws Exception {
        byte[] salt = CryptoService.generateSalt(32);
        SecretKey key = CryptoService.deriveKey("correct horse battery staple".toCharArray(), salt);

        PasswordEntry entry = new PasswordEntry();
        entry.id = UUID.randomUUID().toString();
        entry.location = "example.com";
        entry.username = "alice";
        entry.encryptedPassword = CryptoService.encryptPassword("s3cret!".toCharArray(), key);
        entry.created = LocalDateTime.now();
        entry.modified = LocalDateTime.now();

        DatabaseStore.saveDatabase(salt, key, List.of(entry), "TOTPSECRETVALUE".toCharArray());

        DatabaseWrapper loaded = DatabaseStore.loadDatabase(key);
        assertEquals(1, loaded.getPasswords().size());
        assertEquals("example.com", loaded.getPasswords().get(0).getLocation());
        assertEquals("alice", loaded.getPasswords().get(0).getUsername());
        assertArrayEquals("TOTPSECRETVALUE".toCharArray(), loaded.getTotpSecret());
        assertEquals("s3cret!", CryptoService.decryptPassword(loaded.getPasswords().get(0).getEncryptedPassword(), key));
    }

    @Test
    void loadDatabase_withWrongKey_throwsSecurityException() throws Exception {
        byte[] salt = CryptoService.generateSalt(32);
        SecretKey rightKey = CryptoService.deriveKey("correct horse battery staple".toCharArray(), salt);
        DatabaseStore.saveDatabase(salt, rightKey, List.of(), "SECRET".toCharArray());

        SecretKey wrongKey = CryptoService.deriveKey("wrong password".toCharArray(), salt);
        assertThrows(SecurityException.class, () -> DatabaseStore.loadDatabase(wrongKey));
    }
}
