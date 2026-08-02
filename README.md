# Password Manager

A FIPS-compliant Java Swing desktop password manager with AES-256-GCM encryption, TOTP multi-factor authentication, and an audit log.

## Features

- **AES-256-GCM encryption**: Every stored password and the database file itself are independently encrypted
- **PBKDF2 key derivation**: FIPS 140-2 compliant, 100,000 iterations
- **Master password + PIN authentication**: Two-factor local authentication
- **TOTP MFA**: Time-based one-time passwords for vault access; QR code generated for authenticator app setup
- **Password strength meter**: Real-time strength scoring powered by zxcvbn
- **Auto-lock**: Vault locks automatically after 5 minutes of inactivity, clearing the master key, PIN, and TOTP secret from memory (not just hiding the window)
- **Brute-force protection**: Database is deleted after 3 consecutive failed login attempts; a vault entry is deleted after 3 consecutive failed PIN attempts
- **Audit log**: Access and modification events written to `audit.log`, alongside the encrypted database
- **Clipboard integration**: Copy passwords directly to clipboard (auto-cleared after 30 seconds)

## Prerequisites

- Java 24 or higher
- Java Cryptography Extension (JCE) unlimited strength policy (included by default in Java 9+)

## Build

```bash
mvn clean package
```

Produces `target/password-manager-all.jar`.

## Test

```bash
mvn test
```

## Run

```bash
java -jar target/password-manager-all.jar
```

On first launch the app prompts to create a master password, PIN, and TOTP secret. Subsequent launches require master password + PIN + current TOTP code.

## Project Structure

```
src/main/java/com/ourgiant/passman/
├── Main.java              # Entry point: JCE check, theme setup
├── ThemeManager.java       # FlatLaf theme selection
├── model/                 # Plain data types (PasswordEntry, DatabaseWrapper)
├── core/                  # Swing-free domain logic
│   ├── CryptoService.java        # AES-256-GCM encryption, PBKDF2 key derivation, constant-time comparison
│   ├── TotpService.java          # TOTP generation/verification, base32, QR code
│   ├── CredentialValidator.java  # Password/PIN strength checks
│   ├── DatabaseStore.java        # Encrypted database read/write
│   ├── AuditLog.java             # Security audit trail
│   └── AppPaths.java             # Cross-platform app data directory + file-permission hardening
├── gui/
│   └── PasswordManagerFrame.java # All Swing UI
└── util/
    └── AppVersion.java    # Runtime version resolution
```

`gui/` depends one-way on `core/`/`model/` — no `javax.swing.*` in domain code, so the crypto/TOTP/PIN logic is unit-testable without touching Swing (see `src/test/java/com/ourgiant/passman/core/`).

## Dependencies

- **Jackson**: Password database serialisation
- **zxcvbn**: Password strength estimation
- **ZXing**: QR code generation for TOTP setup
- **FlatLaf**: Application theming
- **SLF4J + Logback**: Application logging (kept separate from the security audit log — see Security Notes)
- **JUnit 5 + Mockito**: Test suite

## Security Notes

- The encrypted database and audit log are stored together in a platform-appropriate location resolved at runtime — `%LOCALAPPDATA%\JavaPassManager` on Windows, `~/Library/Application Support/JavaPassManager` on macOS, `$XDG_DATA_HOME/JavaPassManager` (falling back to `~/.local/share`) on Linux.
- Both files have OS-level file-permission hardening applied (restricting access to the current user, `SYSTEM`, and `Administrators` on platforms that support ACLs) immediately after every write.
- The audit log never contains secret material — master password, PIN, TOTP secret, and entry passwords are never written to it, including on failed-verification paths.
- PIN and TOTP code comparisons use constant-time comparison (`MessageDigest.isEqual`) to avoid timing side-channels.
- Locking the app (manually or via auto-lock) clears the master key, PIN, and TOTP secret from memory, not just the window — they're re-derived fresh on unlock. The master password, PIN, and each entry's password are handled as `char[]` where practical and explicitly zeroed after use, rather than left as unclearable `String`s. (The decrypted entry password shown in the UI is still ultimately held by a Swing `JTextField`/`JPasswordField`'s own internal storage while displayed — a Swing-imposed limit, not something further `char[]` conversion can avoid.)
- There is no password recovery mechanism — losing the master password means losing access.
- The general application log (SLF4J/Logback, console + `logs/app.log` in the same app data directory) is a separate concern from the audit log above; it never receives secret values either.

## License

MIT — see [LICENSE](LICENSE) for details.
