# Password Manager

A FIPS-compliant Java Swing desktop password manager with AES-256-GCM encryption, TOTP multi-factor authentication, and an audit log.

## Features

- **AES-256-GCM encryption**: Every stored password and the database file itself are independently encrypted
- **PBKDF2 key derivation**: FIPS 140-2 compliant, 100,000 iterations
- **Master password + PIN authentication**: Two-factor local authentication
- **TOTP MFA**: Time-based one-time passwords for vault access; QR code generated for authenticator app setup
- **Password strength meter**: Real-time strength scoring powered by zxcvbn
- **Auto-lock**: Vault locks automatically after 5 minutes of inactivity
- **Brute-force protection**: Database is deleted after 3 consecutive failed login attempts
- **Audit log**: All access and modification events written to `audit.log`
- **Clipboard integration**: Copy passwords directly to clipboard

## Prerequisites

- Java 24 or higher
- Java Cryptography Extension (JCE) unlimited strength policy (included by default in Java 9+)

## Build

```bash
mvn clean package
```

Produces `target/password-manager-all.jar`.

## Run

```bash
java -jar target/password-manager-all.jar
```

On first launch the app prompts to create a master password, PIN, and TOTP secret. Subsequent launches require master password + PIN + current TOTP code.

## Project Structure

```
src/main/java/com/ourgiant/passman/
└── PasswordManager.java    # Main application, encryption, TOTP, and UI
```

## Dependencies

- **Jackson**: Password database serialisation
- **zxcvbn**: Password strength estimation
- **ZXing**: QR code generation for TOTP setup

## Security Notes

- The encrypted database is stored locally; the location is resolved at runtime
- There is no password recovery mechanism — losing the master password means losing access
- Audit log is written in plaintext alongside the database

## License

See LICENSE file for details.
