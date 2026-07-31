# Agent guide

This repository is **mostly generated**. Before editing anything, check whether the
file starts with `// @oagen-ignore-file`.

- **No marker → generated.** Do not edit. Change `src/android/` in
  `workos/oagen-emitters` and regenerate. CI blocks PRs that edit generated files.
- **Marker present → hand-maintained.** Edit in place; regeneration will not touch it.

Hand-maintained set: `WorkOSClient.kt`, `Configuration.kt`, `RequestOptions.kt`,
`Page.kt`, `WorkOSException.kt`, everything in `internal/` and `helpers/`, plus
`src/test/kotlin/com/workos/android/support/` and `TransportBehaviorTest.kt`.

Checks: `./script/ci` (ktlint + tests).

`gradle.properties` is committed here and its heap settings are load-bearing — the
compiler OOMs without them. See the comment in that file.
