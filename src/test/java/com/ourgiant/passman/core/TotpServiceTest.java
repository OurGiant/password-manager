package com.ourgiant.passman.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TotpServiceTest {

    /**
     * RFC 6238 Appendix B test vectors use the ASCII key "12345678901234567890"
     * with 8-digit HOTP output; this app truncates to 6 digits
     * (binary % 10^6), which is exactly the last 6 digits of the published
     * 8-digit vectors since 10^6 divides 10^8. T = floor(unixTime / 30).
     */
    private static final String RFC6238_SECRET =
        TotpService.base32Encode("12345678901234567890".getBytes(StandardCharsets.UTF_8));

    @ParameterizedTest
    @CsvSource({
        "1,           287082",   // unixTime=59
        "37037036,    081804",   // unixTime=1111111109
        "37037037,    050471",   // unixTime=1111111111
        "41152263,    005924",   // unixTime=1234567890
        "66666666,    279037",   // unixTime=2000000000
        "666666666,   353130",   // unixTime=20000000000
    })
    void generateTOTP_matchesRfc6238Vectors(long timeStep, String expectedCode) {
        assertEquals(expectedCode, TotpService.generateTOTP(RFC6238_SECRET, timeStep));
    }

    @Test
    void verifyTOTP_acceptsCurrentWindowCode() {
        String secret = TotpService.generateTOTPSecret();
        String currentCode = TotpService.generateCurrentTOTP(secret);
        assertTrue(TotpService.verifyTOTP(secret, currentCode));
    }

    @Test
    void verifyTOTP_rejectsWrongCode() {
        String secret = TotpService.generateTOTPSecret();
        long currentTime = System.currentTimeMillis() / 1000 / TotpService.TOTP_PERIOD;
        String validCode = TotpService.generateTOTP(secret, currentTime);
        String wrongCode = String.format("%06d", (Integer.parseInt(validCode) + 1) % 1_000_000);
        assertFalse(TotpService.verifyTOTP(secret, wrongCode));
    }

    @Test
    void verifyTOTP_rejectsMalformedInput() {
        String secret = TotpService.generateTOTPSecret();
        assertFalse(TotpService.verifyTOTP(secret, "abc123"));
        assertFalse(TotpService.verifyTOTP(secret, "12345")); // too short
        assertFalse(TotpService.verifyTOTP(secret, ""));
        assertFalse(TotpService.verifyTOTP(secret, null));
        assertFalse(TotpService.verifyTOTP((String) null, "123456"));
    }

    @Test
    void base32_roundTripsArbitraryByteArrays() {
        byte[][] samples = {
            {},
            {0x00},
            {0x01, 0x02, 0x03, 0x04, 0x05},
            {(byte) 0xFF, (byte) 0xFE, (byte) 0xFD},
            "the quick brown fox".getBytes(StandardCharsets.UTF_8),
        };
        for (byte[] sample : samples) {
            String encoded = TotpService.base32Encode(sample);
            byte[] decoded = TotpService.base32Decode(encoded);
            assertArrayEquals(sample, decoded, "round trip failed for " + Arrays.toString(sample));
        }
    }

    @Test
    void generateTOTPSecret_producesValidBase32OfExpectedLength() {
        String secret = TotpService.generateTOTPSecret();
        // 160 bits / 5 bits-per-base32-char = 32 chars
        assertEquals(32, secret.length());
        assertTrue(secret.matches("[A-Z2-7]+"));
    }

    @Test
    void formatSecretKey_insertsSpaceEveryFourChars() {
        assertEquals("ABCD EFGH IJ", TotpService.formatSecretKey("ABCDEFGHIJ"));
    }

    @Test
    void charArrayOverloads_behaveIdenticallyToStringOverloads() {
        char[] secret = TotpService.generateTOTPSecret().toCharArray();
        String currentCode = TotpService.generateCurrentTOTP(secret);

        assertEquals(TotpService.generateCurrentTOTP(new String(secret)), currentCode);
        assertTrue(TotpService.verifyTOTP(secret, currentCode));
        assertArrayEquals(TotpService.base32Decode(new String(secret)), TotpService.base32Decode(secret));
        assertArrayEquals("ABCD EFGH IJ".toCharArray(), TotpService.formatSecretKey("ABCDEFGHIJ".toCharArray()));
    }

    @Test
    void verifyTOTP_charArrayOverload_rejectsNullOrEmptySecret() {
        assertFalse(TotpService.verifyTOTP((char[]) null, "123456"));
        assertFalse(TotpService.verifyTOTP(new char[0], "123456"));
    }

    @Test
    void verifyTOTP_onMalformedInput_neverWritesRawCodeToAuditLog() throws Exception {
        Path logPath = AppPaths.getAppDataDir().resolve("audit.log");
        Files.deleteIfExists(logPath);

        String secret = TotpService.generateTOTPSecret();
        // Near-miss of a real code: 5 correct digits plus one extra, still fails
        // the \d{6} format check but would leak most of a real code if logged raw.
        String nearMissPaste = "1234567";
        assertFalse(TotpService.verifyTOTP(secret, nearMissPaste));

        assertTrue(Files.exists(logPath), "expected an audit log entry for the failed format check");
        String logContents = Files.readString(logPath, StandardCharsets.UTF_8);
        assertFalse(logContents.contains(nearMissPaste),
            "audit log must never contain the raw user-entered TOTP code");
        assertTrue(logContents.contains("Invalid TOTP format"));
    }
}
