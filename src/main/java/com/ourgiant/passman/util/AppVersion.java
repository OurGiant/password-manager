package com.ourgiant.passman.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/** Resolves the running app's version for display, falling back to "dev" when unset (e.g. running from an IDE, not the packaged jar). */
public final class AppVersion {

    private AppVersion() {
    }

    public static String resolve() {
        String version = AppVersion.class.getPackage() != null
            ? AppVersion.class.getPackage().getImplementationVersion()
            : null;
        if (version == null) {
            version = readFromPropertiesResource();
        }
        return version != null ? version : "dev";
    }

    private static String readFromPropertiesResource() {
        try (InputStream in = AppVersion.class.getResourceAsStream("/version.properties")) {
            if (in != null) {
                Properties props = new Properties();
                props.load(in);
                return props.getProperty("version");
            }
        } catch (IOException ignored) {
            // Falls through to the "dev" default in resolve().
        }
        return null;
    }
}
