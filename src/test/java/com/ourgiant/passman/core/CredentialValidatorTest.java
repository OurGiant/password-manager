package com.ourgiant.passman.core;

import com.ourgiant.passman.core.CredentialValidator.CredentialCheckResult;
import com.ourgiant.passman.core.CredentialValidator.PinStrengthResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialValidatorTest {

    private static final double MIN_PIN_ENTROPY_BITS = 16;

    @Test
    void checkPinStrength_rejectsNonDigitOrWrongLength() {
        assertFalse(CredentialValidator.checkPinStrength("abcd".toCharArray(), MIN_PIN_ENTROPY_BITS).isStrong);
        assertFalse(CredentialValidator.checkPinStrength("123".toCharArray(), MIN_PIN_ENTROPY_BITS).isStrong); // too short
        assertFalse(CredentialValidator.checkPinStrength("1234567890".toCharArray(), MIN_PIN_ENTROPY_BITS).isStrong); // too long
    }

    @Test
    void checkPinStrength_penalizesRepeatingDigits() {
        PinStrengthResult result = CredentialValidator.checkPinStrength("1111".toCharArray(), MIN_PIN_ENTROPY_BITS);
        assertFalse(result.isStrong);
        assertTrue(result.message.contains("repeating"));
    }

    @Test
    void checkPinStrength_penalizesSequentialDigits() {
        PinStrengthResult result = CredentialValidator.checkPinStrength("2345".toCharArray(), MIN_PIN_ENTROPY_BITS);
        assertFalse(result.isStrong);
        assertTrue(result.message.contains("sequences"));
    }

    @Test
    void checkPinStrength_penalizesCommonPins() {
        PinStrengthResult result = CredentialValidator.checkPinStrength("1234".toCharArray(), MIN_PIN_ENTROPY_BITS);
        assertFalse(result.isStrong);
        // 1234 is both sequential and a listed common PIN
        assertTrue(result.message.contains("sequences") || result.message.contains("common"));
    }

    @Test
    void checkPinStrength_acceptsSufficientlyRandomLongerPin() {
        PinStrengthResult result = CredentialValidator.checkPinStrength("60284".toCharArray(), MIN_PIN_ENTROPY_BITS);
        assertTrue(result.isStrong, result.message);
    }

    @Test
    void isStrongPassword_rejectsCommonDictionaryWord() {
        assertFalse(CredentialValidator.isStrongPassword("password".toCharArray()));
    }

    @Test
    void isStrongPassword_rejectsEmptyOrNull() {
        assertFalse(CredentialValidator.isStrongPassword(new char[0]));
        assertFalse(CredentialValidator.isStrongPassword(null));
    }

    @Test
    void isStrongPassword_acceptsLongRandomPassword() {
        assertTrue(CredentialValidator.isStrongPassword("Tr0ub4dor&3xampleZq9!mPx".toCharArray()));
    }

    @Test
    void validateCredentials_rejectsMismatchedPasswords() {
        CredentialCheckResult result = CredentialValidator.validateCredentials(
            "K9#mQ2vL!pX7rT4w".toCharArray(), "different".toCharArray(),
            "60284".toCharArray(), "60284".toCharArray(), MIN_PIN_ENTROPY_BITS);
        assertFalse(result.valid);
        assertTrue(result.message.contains("Passwords do not match"));
    }

    @Test
    void validateCredentials_rejectsWeakPassword() {
        CredentialCheckResult result = CredentialValidator.validateCredentials(
            "password".toCharArray(), "password".toCharArray(),
            "60284".toCharArray(), "60284".toCharArray(), MIN_PIN_ENTROPY_BITS);
        assertFalse(result.valid);
    }

    @Test
    void validateCredentials_rejectsMismatchedPins() {
        CredentialCheckResult result = CredentialValidator.validateCredentials(
            "K9#mQ2vL!pX7rT4w".toCharArray(), "K9#mQ2vL!pX7rT4w".toCharArray(),
            "60284".toCharArray(), "11111".toCharArray(), MIN_PIN_ENTROPY_BITS);
        assertFalse(result.valid);
        assertTrue(result.message.contains("PINs do not match"));
    }

    @Test
    void validateCredentials_rejectsWeakPin() {
        CredentialCheckResult result = CredentialValidator.validateCredentials(
            "K9#mQ2vL!pX7rT4w".toCharArray(), "K9#mQ2vL!pX7rT4w".toCharArray(),
            "1111".toCharArray(), "1111".toCharArray(), MIN_PIN_ENTROPY_BITS);
        assertFalse(result.valid);
        assertTrue(result.message.contains("PIN is too weak"));
    }

    @Test
    void validateCredentials_acceptsStrongMatchingCredentials() {
        CredentialCheckResult result = CredentialValidator.validateCredentials(
            "K9#mQ2vL!pX7rT4w".toCharArray(), "K9#mQ2vL!pX7rT4w".toCharArray(),
            "60284".toCharArray(), "60284".toCharArray(), MIN_PIN_ENTROPY_BITS);
        assertTrue(result.valid, result.message);
    }
}
