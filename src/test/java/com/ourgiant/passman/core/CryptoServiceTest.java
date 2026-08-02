package com.ourgiant.passman.core;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoServiceTest {

    @Test
    void deriveKey_isDeterministicForSamePasswordAndSalt() throws Exception {
        byte[] salt = CryptoService.generateSalt(32);
        SecretKey key1 = CryptoService.deriveKey("correct horse battery staple".toCharArray(), salt);
        SecretKey key2 = CryptoService.deriveKey("correct horse battery staple".toCharArray(), salt);
        assertArrayEquals(key1.getEncoded(), key2.getEncoded());
    }

    @Test
    void deriveKey_differsForDifferentSalt() throws Exception {
        SecretKey key1 = CryptoService.deriveKey("correct horse battery staple".toCharArray(), CryptoService.generateSalt(32));
        SecretKey key2 = CryptoService.deriveKey("correct horse battery staple".toCharArray(), CryptoService.generateSalt(32));
        assertFalse(java.util.Arrays.equals(key1.getEncoded(), key2.getEncoded()));
    }

    @Test
    void encryptDecrypt_roundTripsPlaintext() throws Exception {
        SecretKey key = CryptoService.deriveKey("master password".toCharArray(), CryptoService.generateSalt(32));
        byte[] encrypted = CryptoService.encryptPassword("hunter2!Zq9".toCharArray(), key);
        String decrypted = CryptoService.decryptPassword(encrypted, key);
        assertEquals("hunter2!Zq9", decrypted);
    }

    @Test
    void encrypt_producesDifferentCiphertextEachTimeDueToRandomIv() throws Exception {
        SecretKey key = CryptoService.deriveKey("master password".toCharArray(), CryptoService.generateSalt(32));
        byte[] encrypted1 = CryptoService.encryptPassword("same-plaintext".toCharArray(), key);
        byte[] encrypted2 = CryptoService.encryptPassword("same-plaintext".toCharArray(), key);
        assertNotEquals(java.util.Base64.getEncoder().encodeToString(encrypted1),
            java.util.Base64.getEncoder().encodeToString(encrypted2));
    }

    @Test
    void decrypt_failsWithWrongKey() throws Exception {
        SecretKey rightKey = CryptoService.deriveKey("correct".toCharArray(), CryptoService.generateSalt(32));
        SecretKey wrongKey = CryptoService.deriveKey("wrong".toCharArray(), CryptoService.generateSalt(32));
        byte[] encrypted = CryptoService.encryptPassword("secret-value".toCharArray(), rightKey);
        assertThrows(AEADBadTagException.class, () -> CryptoService.decryptPassword(encrypted, wrongKey));
    }

    @Test
    void decrypt_failsWithTamperedCiphertext() throws Exception {
        SecretKey key = CryptoService.deriveKey("master password".toCharArray(), CryptoService.generateSalt(32));
        byte[] encrypted = CryptoService.encryptPassword("secret-value".toCharArray(), key);
        encrypted[encrypted.length - 1] ^= 0x01; // flip a bit in the auth tag/ciphertext
        assertThrows(AEADBadTagException.class, () -> CryptoService.decryptPassword(encrypted, key));
    }

    @Test
    void constantTimeEquals_charArrays() {
        assertTrue(CryptoService.constantTimeEquals("1234".toCharArray(), "1234".toCharArray()));
        assertFalse(CryptoService.constantTimeEquals("1234".toCharArray(), "5678".toCharArray()));
        assertFalse(CryptoService.constantTimeEquals("1234".toCharArray(), "12345".toCharArray()));
        assertFalse(CryptoService.constantTimeEquals(null, "1234".toCharArray()));
    }

    @Test
    void constantTimeEquals_strings() {
        assertTrue(CryptoService.constantTimeEquals("abc123", "abc123"));
        assertFalse(CryptoService.constantTimeEquals("abc123", "xyz789"));
        assertFalse(CryptoService.constantTimeEquals(null, "abc123"));
    }
}
