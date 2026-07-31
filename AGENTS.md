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

## Always run `./script/ci` after regenerating

`oagen generate` invokes the emitter's `formatCommand` (`./gradlew ktlintFormat`),
but it is **best-effort in two ways**:

1. It is swallowed on failure (`; true`), so a missing JDK formats nothing silently.
2. oagen only formats files the run actually *wrote* — `formatTargetFiles` returns
   early when the written-file list is empty. So once unformatted output lands on
   disk, a subsequent identical generation writes nothing and therefore re-formats
   nothing. The unformatted state is sticky.

`./script/ci` runs `ktlintFormat` unconditionally, which is why it comes first
there. **`generate` then `script/ci`** is idempotent — verified byte-identical
across two full cycles. `generate` alone is not.
