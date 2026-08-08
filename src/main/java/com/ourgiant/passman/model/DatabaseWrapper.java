package com.ourgiant.passman.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class DatabaseWrapper {

    @JsonProperty("passwords")
    private List<PasswordEntry> passwords;

    @JsonProperty("totpSecret")
    private char[] totpSecret;

    // Default constructor required for Jackson
    public DatabaseWrapper() {}

    // Getters and setters
    public List<PasswordEntry> getPasswords() {
        return passwords;
    }

    public void setPasswords(List<PasswordEntry> passwords) {
        this.passwords = passwords;
    }

    public char[] getTotpSecret() {
        return totpSecret;
    }

    public void setTotpSecret(char[] totpSecret) {
        this.totpSecret = totpSecret;
    }
}
