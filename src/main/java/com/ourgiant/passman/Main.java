package com.ourgiant.passman;

import com.ourgiant.passman.core.AppPaths;
import com.ourgiant.passman.gui.PasswordManagerFrame;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

public final class Main {

    private Main() {}

    public static void main(String[] args) {
        // Must be set before the first logger is obtained, so logback.xml's
        // file appender resolves to the app's real data directory.
        System.setProperty("app.data.dir", AppPaths.getAppDataDir().toString());

        Logger logger = LoggerFactory.getLogger(Main.class);

        System.setProperty("awt.useSystemAAFontSettings", "on");
        System.setProperty("swing.aatext", "true");
        // Ensure Java Cryptography Extension (JCE) is available
        try {
            int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
            if (maxKeyLen < 256) {
                JOptionPane.showMessageDialog(null,
                    "Unlimited Strength JCE required for AES-256.\nPlease install JCE Unlimited Strength Jurisdiction Policy Files.",
                    "Cryptography Error", JOptionPane.ERROR_MESSAGE);
                System.exit(1);
            }
        } catch (Exception e) {
            logger.error("Failed to check JCE key length policy", e);
            System.exit(1);
        }

        SwingUtilities.invokeLater(() -> {
            ThemeManager.applyDefaultTheme();
            new PasswordManagerFrame();
        });
    }
}
