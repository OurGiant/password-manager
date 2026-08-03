package com.ourgiant.passman.util;

/**
 * Thrown by an outbound HTTPS fetch for a failure specific enough to show the user something
 * more useful than a generic "couldn't connect" — the message is written to be shown directly
 * in a status label.
 */
public class NetworkFetchException extends RuntimeException {
    public NetworkFetchException(String userFacingMessage, Throwable cause) {
        super(userFacingMessage, cause);
    }
}
