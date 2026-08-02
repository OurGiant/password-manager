package com.ourgiant.passman;

import com.ourgiant.passman.gui.PasswordManagerFrame;

import javax.crypto.Cipher;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

public final class Main {

    private Main() {}

    public static void main(String[] args) {
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
            e.printStackTrace();
            System.exit(1);
        }

        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                e.printStackTrace();
            }
            new PasswordManagerFrame();
        });
    }
}
