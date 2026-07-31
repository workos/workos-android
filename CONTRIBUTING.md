# Contributing

## Generated code

Most of this repository is generated from the WorkOS OpenAPI spec by
[oagen](https://github.com/workos/oagen). A CI check (`block-generated-edits`)
closes PRs that modify generated files.

To change generated output, change the emitter — `src/android/` in
`workos/oagen-emitters` — and regenerate. Never patch the output here.

Hand-maintained files carry `// @oagen-ignore-file` on the first line. Those are
edited here, in place, and regeneration leaves them untouched.

## Running checks

```bash
./script/ci
```

## Commits and releases

Conventional commits; releases are cut by release-please.
