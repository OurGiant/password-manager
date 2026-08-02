---
name: ship-issue
description: The standard workflow for shipping a bug fix or feature to Password Manager — file a GitHub issue, branch off main, implement, verify, bump the patch version, and open a PR. Use whenever picking up a bug fix or feature for this repo.
---

# Shipping a change to Password Manager

Follow `java-swing-ship-issue` (the generic workflow shared across the
Java Swing project family) with these Password Manager specifics:

- **Project path**: `/projects/password-manager` inside the build
  container.
- **Verify**: use this repo's own `.claude/skills/verify/SKILL.md` for
  build/launch mechanics.
- **Security-sensitive by default**: this app handles master passwords,
  PINs, TOTP secrets, and encrypted credentials. Any change touching
  `core/CryptoService`, `core/TotpService`, `core/CredentialValidator`,
  `core/DatabaseStore`, or `core/AuditLog` should come with test coverage
  in the mirrored `src/test/java/com/ourgiant/passman/core/` package, not
  just a manual verification pass — see the existing tests there for the
  established pattern (known-vector tests for crypto/TOTP, negative
  cases for wrong-key/tampered-ciphertext paths).
- **Never log or display secret material**: master password, PIN, TOTP
  secret, and entry passwords must never flow into `AuditLog` or the
  general SLF4J log (`logback.xml`) — both are separate from each other
  and both are separate concerns from actual authentication decisions.
  If a change adds a new log statement anywhere near authentication,
  TOTP, or password handling, double-check what's actually being logged
  before opening the PR (issue #2 in this project's history was exactly
  this mistake).
- CI (`.github/workflows/build.yml`) runs `mvn test` on every PR — wait
  for it to go green per the generic workflow's step 8. It does not yet
  build native installers (jpackage matrix deferred, see issue #12); add
  that as a separate, deliberately-scoped change if the project reaches
  the point of cutting real installer releases.
