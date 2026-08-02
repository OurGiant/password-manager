package com.ourgiant.passman.core;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

public final class TotpService {

    public static final int TOTP_DIGITS = 6;
    public static final int TOTP_PERIOD = 30; // seconds

    private TotpService() {}

    public static String generateTOTPSecret() {
        byte[] buffer = new byte[20]; // 160 bits
        new SecureRandom().nextBytes(buffer);
        return base32Encode(buffer);
    }

    public static String base32Encode(byte[] data) {
        String base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        StringBuilder result = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;

        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                result.append(base32Chars.charAt((buffer >> (bitsLeft - 5)) & 0x1F));
                bitsLeft -= 5;
            }
        }

        if (bitsLeft > 0) {
            result.append(base32Chars.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }

        return result.toString();
    }

    public static byte[] base32Decode(String encoded) {
        String base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        encoded = encoded.toUpperCase().replaceAll("[^A-Z2-7]", "");

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        int buffer = 0;
        int bitsLeft = 0;

        for (char c : encoded.toCharArray()) {
            int val = base32Chars.indexOf(c);
            if (val < 0) continue;

            buffer = (buffer << 5) | val;
            bitsLeft += 5;

            if (bitsLeft >= 8) {
                result.write((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }

        return result.toByteArray();
    }

    public static String generateTOTP(String secret, long timeStep) {
        try {
            byte[] key = base32Decode(secret);
            byte[] data = new byte[8];
            long value = timeStep;
            for (int i = 7; i >= 0; i--) {
                data[i] = (byte) value;
                value >>= 8;
            }

            SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signKey);
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24) |
                        ((hash[offset + 1] & 0xFF) << 16) |
                        ((hash[offset + 2] & 0xFF) << 8) |
                        (hash[offset + 3] & 0xFF);

            int otp = binary % (int) Math.pow(10, TOTP_DIGITS);
            return String.format("%0" + TOTP_DIGITS + "d", otp);

        } catch (Exception e) {
            e.printStackTrace();
            AuditLog.log("TOTP generation error: " + e.getMessage());
            return null;
        }
    }

    public static String generateCurrentTOTP(String secret) {
        long currentTime = System.currentTimeMillis() / 1000 / TOTP_PERIOD;
        return generateTOTP(secret, currentTime);
    }

    public static boolean verifyTOTP(String totpSecret, String code) {
        if (totpSecret == null || code == null || code.trim().isEmpty()) {
            return false;
        }

        // Remove any spaces or formatting from input
        code = code.trim().replaceAll("\\s+", "");

        // Verify it's 6 digits
        if (!code.matches("\\d{6}")) {
            AuditLog.log("Invalid TOTP format: " + code);
            return false;
        }

        long currentTime = System.currentTimeMillis() / 1000 / TOTP_PERIOD;

        // Check current and adjacent time windows (allows for clock skew)
        for (int i = -2; i <= 2; i++) {
            String validCode = generateTOTP(totpSecret, currentTime + i);
            if (validCode != null && code.equals(validCode)) {
                AuditLog.log("TOTP verified successfully (window offset: " + i + ")");
                return true;
            }
        }

        // Log what we were expecting vs what we got (for debugging)
        String expectedCurrent = generateTOTP(totpSecret, currentTime);
        AuditLog.log("TOTP verification failed. Expected (current): " + expectedCurrent + ", Got: " + code);

        return false;
    }

    public static String formatSecretKey(String key) {
        // Format key with spaces every 4 characters for readability
        StringBuilder formatted = new StringBuilder();
        for (int i = 0; i < key.length(); i++) {
            if (i > 0 && i % 4 == 0) {
                formatted.append(" ");
            }
            formatted.append(key.charAt(i));
        }
        return formatted.toString();
    }

    public static BufferedImage generateQRCode(String issuer, String account, String secret) throws Exception {
        String algorithm = "SHA1"; // For Google Authenticator compatibility
        int digits = 6;
        int period = 30;

        // Construct the TOTP URI
        String totpUri = String.format(
            "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
            issuer, account, secret, issuer, algorithm, digits, period
        );

        // Generate QR code
        BitMatrix matrix = new MultiFormatWriter().encode(totpUri, BarcodeFormat.QR_CODE, 250, 250);
        return MatrixToImageWriter.toBufferedImage(matrix);
    }
}
