package com.ourgiant.passman;

import com.formdev.flatlaf.FlatLightLaf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.UIManager;

/** Applies the app's default FlatLaf theme, falling back to the system look and feel if FlatLaf can't be applied. */
public final class ThemeManager {

    private static final Logger logger = LoggerFactory.getLogger(ThemeManager.class);

    private ThemeManager() {}

    public static void applyDefaultTheme() {
        try {
            UIManager.setLookAndFeel(new FlatLightLaf());
        } catch (Exception e) {
            logger.warn("Failed to apply FlatLaf theme, falling back to system look and feel", e);
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception fallbackException) {
                logger.error("Failed to apply system look and feel", fallbackException);
            }
        }
    }
}
