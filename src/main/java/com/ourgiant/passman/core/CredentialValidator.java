package com.ourgiant.passman.core;

import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;

public final class CredentialValidator {

    private CredentialValidator() {}

    public static CredentialCheckResult validateCredentials(
            String password, String confirmPassword,
            String pin, String confirmPin,
            double pinMinEntropyBits) {

        // --- Password checks ---
        if (password == null || !password.equals(confirmPassword)) {
            return new CredentialCheckResult(false, "Passwords do not match!");
        }

        if (!isStrongPassword(password)) {
            return new CredentialCheckResult(false,
                "Master password must be at least 8 characters long and include upper, lower, digit, and special character.");
        }

        // --- PIN checks ---
        if (pin == null || !pin.equals(confirmPin)) {
            return new CredentialCheckResult(false, "PINs do not match!");
        }

        PinStrengthResult pinResult = checkPinStrength(pin, pinMinEntropyBits);
        if (!pinResult.isStrong) {
            return new CredentialCheckResult(false, "PIN is too weak: " + pinResult.message);
        }

        // All checks passed
        return new CredentialCheckResult(true, "Credentials are strong.");
    }

    /**
     * Check PIN strength and provide feedback
     */
    public static PinStrengthResult checkPinStrength(String pin, double minEntropyBits) {
        if (pin == null || !pin.matches("\\d{4,9}")) {
            return new PinStrengthResult(false, "PIN must be 4-9 digits.", 0);
        }

        int length = pin.length();
        double entropy = length * Math.log(10) / Math.log(2); // max entropy
        StringBuilder feedback = new StringBuilder();

        // Repeating digits
        if (pin.matches("(\\d)\\1{3,}")) {
            entropy -= 4;
            feedback.append("Avoid repeating digits (e.g., 1111). ");
        }

        // Sequential digits
        boolean hasSequence = false;
        for (int i = 0; i <= pin.length() - 4; i++) {
            int d1 = pin.charAt(i) - '0';
            int d2 = pin.charAt(i + 1) - '0';
            int d3 = pin.charAt(i + 2) - '0';
            int d4 = pin.charAt(i + 3) - '0';
            if ((d2 == d1 + 1 && d3 == d2 + 1 && d4 == d3 + 1) ||
                (d2 == d1 - 1 && d3 == d2 - 1 && d4 == d3 - 1)) {
                hasSequence = true;
                break;
            }
        }
        if (hasSequence) {
            entropy -= 4;
            feedback.append("Avoid sequences of 4 or more digits (e.g., 1234). ");
        }

        // Very common PINs
        String[] common = {"1234","1111","0000","1212","7777"};
        for (String c : common) {
            if (pin.equals(c)) {
                entropy -= 5;
                feedback.append("Avoid very common PINs. ");
                break;
            }
        }

        // Ensure non-negative entropy
        entropy = Math.max(entropy, 0);

        if (entropy < minEntropyBits) {
            if (feedback.length() == 0) feedback.append("PIN is too weak.");
            return new PinStrengthResult(false, feedback.toString(), entropy);
        }

        return new PinStrengthResult(true, "PIN is strong.", entropy);
    }

    public static boolean isStrongPassword(String password) {
        if (password == null || password.isEmpty()) return false;

        Zxcvbn zxcvbn = new Zxcvbn();
        Strength strength = zxcvbn.measure(password);

        // strength score is 0–4; 3+ is considered "strong"
        return strength.getScore() >= 3;
    }

    public static class CredentialCheckResult {
        public final boolean valid;
        public final String message;

        public CredentialCheckResult(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }
    }

    public static class PinStrengthResult {
        public final boolean isStrong;
        public final String message;
        public final double entropyBits;

        public PinStrengthResult(boolean isStrong, String message, double entropyBits) {
            this.isStrong = isStrong;
            this.message = message;
            this.entropyBits = entropyBits;
        }
    }
}
