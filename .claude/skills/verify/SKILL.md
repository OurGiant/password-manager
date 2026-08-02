---
name: verify
description: How to build, launch, and drive the Password Manager to verify a Swing UI change actually works on this dev setup. Use before trusting the generic verify-java-swing skill's screenshot step; read that skill too for the underlying techniques (modal-dialog deadlock, synthetic MouseEvent dispatch, process safety).
---

# Verifying Password Manager

This is the project-specific companion to the generic `verify-java-swing`
skill (techniques) and `java-swing-project-setup` (build/structure
standard this project follows). Read those first — this file is what to
actually type for *this* project.

## Build here, run there

Maven only exists in the Docker container, not on the host:

```bash
docker exec festive_bardeen bash -c "cd /projects/password-manager && mvn -q package -DskipTests"
```

If `festive_bardeen` doesn't respond, find the current container:
`docker ps -a --format '{{.Names}} {{.Status}} {{.Image}}'` and
`docker start <name>` if stopped — the name can drift across sessions.

`/projects` is bind-mounted from the host's `~/projects`, so the jar lands
at `target/password-manager-all.jar`, visible on the host. The container is
headless (no `DISPLAY`) — run the jar on the **host**, not inside the
container, or it dies at `JFrame` construction with `HeadlessException`.

```bash
java -jar target/password-manager-all.jar
```

Main class: `com.ourgiant.passman.Main`.

## Confirmed: pom.xml bind-mount staleness is real here, not hypothetical

Hit this directly while shipping the standardization sweep: after editing
`pom.xml` on the host (adding the surefire `systemPropertyVariables`
block) and running `mvn test` in the container, the container's copy was
missing the edit entirely (`grep` for the new block came back empty) even
though the host file had it, and Maven ran with the old surefire version
as a result. Confirmed via `md5sum` on both sides that the container's
`pom.xml` was stale. Fixed with:

```bash
docker cp pom.xml festive_bardeen:/projects/password-manager/pom.xml
```

Don't assume a `pom.xml` edit landed in the container just because the
build "ran" — if a build ignores a just-made `pom.xml`/`.java` change,
confirm with `docker exec festive_bardeen md5sum <path>` against the host
file before debugging anything else.

## Driving the UI: reflection + real event dispatch worked well here

`DISPLAY=:1` is a real, working X11 display on this host. Used the
generic skill's reflection + `doClick()` technique successfully to drive
the full login/setup → TOTP verification → save entry → lock → unlock
flow end to end, including the modal `showTOTPSetupDialogWithVerification`
dialog (via `invokeLater` + poll for the dialog + `invokeAndWait` on
dismissal, per the generic skill's modal-dialog section — a plain
`invokeAndWait(button::doClick)` on that button would deadlock).

Screenshot capture (`Robot.createScreenCapture`) has not actually been
tried on this host yet — all verification so far used reflection into
live component state (`JLabel.getText()`, `DefaultTableModel` contents,
field values) instead, which was sufficient. Don't assume it's black
(the aws-idp-saml-ui/kiro-control-panel Wayland finding) or that it works
(the doc-scrubber X11 finding) until someone actually checks here.

## First-run state location

On this Linux host, the app's data directory resolves to
`~/.local/share/JavaPassManager` (XDG), containing `passwords.enc`,
`audit.log`, and `logs/app.log` (the general SLF4J log, separate from the
audit trail). Delete that directory to reset to a fresh "Setup Password
Manager" first-run state. `AppPaths.getAppDataDir()` also honors a
`passman.appDataDir` system property (used by the test suite to avoid
touching this real location) — pass `-Dpassman.appDataDir=<path>` to
redirect a manual verification run too, if you don't want to touch your
real vault while testing.
