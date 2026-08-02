package com.ourgiant.passman.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.time.LocalDateTime;

public class PasswordEntry implements Serializable {
    private static final long serialVersionUID = 1L;

    @JsonProperty("id")
    public String id;

    @JsonProperty("location")
    public String location;

    @JsonProperty("username")
    public String username;

    @JsonProperty("encryptedPassword")
    public byte[] encryptedPassword;

    @JsonProperty("created")
    public LocalDateTime created;

    @JsonProperty("modified")
    public LocalDateTime modified;

    // Default constructor for Jackson
    public PasswordEntry() {}

    // Getters and setters for Jackson
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getLocation() { return location; }
    public void setLocation(String location) { this.location = location; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public byte[] getEncryptedPassword() { return encryptedPassword; }
    public void setEncryptedPassword(byte[] encryptedPassword) { this.encryptedPassword = encryptedPassword; }

    public LocalDateTime getCreated() { return created; }
    public void setCreated(LocalDateTime created) { this.created = created; }

    public LocalDateTime getModified() { return modified; }
    public void setModified(LocalDateTime modified) { this.modified = modified; }
}
