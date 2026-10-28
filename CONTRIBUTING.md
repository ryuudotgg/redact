# Contributing

## Setup

`redact` is a Rust library that CLIProxyAPI loads as a plugin, with a Bun workspace for the end to end tests and the release scripts. `rust-toolchain.toml` pins the Rust version, so `rustup` installs it on the first `cargo` command. From the root:

```
bun install
cargo test
```

The end to end tests run a real CLIProxyAPI. They take the binary from `CPA_BIN`, or from `cliproxyapi` or `cli-proxy-api` on your `PATH`. To fetch the version CI uses, pinned in `.cpa-version` and checked against `scripts/cpa.sha256`:

```
scripts/install-cpa.sh .cpa
export CPA_BIN="$PWD/.cpa/cli-proxy-api"
```

To move to a new CLIProxyAPI release, change `.cpa-version` and replace `scripts/cpa.sha256` with the digests GitHub lists for that release's `darwin_aarch64`, `linux_amd64` and `linux_aarch64` archives.

## Build

```
cargo build
cargo build --release
```

Both write `target/<profile>/libredact.dylib` on macOS and `libredact.so` on Linux. CLIProxyAPI reads the plugin id from the file name, so to load a build by hand, copy it into the plugins directory as `<os>/<arch>/redact.dylib` and enable `plugins.configs.redact`. Dependencies build with optimizations even in the dev profile, so `cargo test` and the end to end tests run the regex engine at release speed.

## Checks

From the root:

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
bun run check
bun run typecheck
cargo build && bun run e2e
```

`cargo test` runs the unit tests, the corpus tests and the round trips through redaction, restore and every stream format, in well under a second. `bun run e2e` starts CLIProxyAPI with the plugin in front of a mock provider and checks what the provider receives and what the client gets back, for Claude Messages, OpenAI Responses over HTTP and WebSocket, OpenAI Chat Completions and Gemini. `bun run check` runs oxlint, oxfmt and [Stanza](https://github.com/ryuudotgg/stanza) on the TypeScript, and `bun run typecheck` runs TypeScript without emitting files. Stanza reads only TypeScript, so Rust and shell function bodies follow the same shape by hand: one blank line between steps, none inside a step.

CI runs all of them on Ubuntu, and everything except the lint and format checks on macOS.

## Corpus

`tests/corpus/clean.txt` holds lines of ordinary code, config and tool output, one per line, that must reach the model unchanged. When `redact` replaces something it should not, add the line there and make the test pass.

The positive cases in `src/corpus.rs` build fake keys at run time from a seed. Never commit a real key, or a fake one in a real provider format: GitHub push protection blocks the push, and the next person to read the file cannot tell which kind it is.

## Throughput

```
cargo test --release -- --ignored --nocapture
```

This times redaction of a 2 MiB Claude Code session, the size of a long conversation near the context limit, once with every secret new and once replayed.

## Gitleaks Rules

`rules/gitleaks.toml` is the Gitleaks default config, pinned to a release. To update it, download the file from the new tag, refresh `rules/LICENSE` from the same tag, and run `cargo test`. `every_embedded_rule_compiles` fails if a new rule uses RE2 syntax the translator in `src/rules.rs` does not handle.

```
curl -fsSL https://raw.githubusercontent.com/gitleaks/gitleaks/<tag>/config/gitleaks.toml -o rules/gitleaks.toml
```

## Releases

### Notes

A pull request that changes something a user of the plugin would notice adds one Markdown note in `.tegami/`. Tests, CI and refactors need no note.

Name the file `.tegami/<date>-<topic>.md`, with the date the note was written as `YYYY-MM-DD` and the topic in lowercase words joined by hyphens, such as `.tegami/2026-10-28-url-passwords.md`. The date keeps a release's entries in the order they were written.

A note names the package and its bump, then gives each change a `###` heading and one paragraph:

```md
---
packages:
  redact: patch
---

### 🐛 Passwords in connection strings are redacted

`postgres://app:<password>@host` URLs reach the provider with the password replaced. Before, a password inside a URL went through as written.
```

Start each heading with the emoji of its category, a space, then the title:

| Emoji | Category | Use it for                                                                |
| ----- | -------- | ------------------------------------------------------------------------- |
| 🚨    | Heads up | A change users must act on, such as a breaking change or a removed option |
| ✨    | New      | A new capability                                                          |
| 🎨    | Improved | Existing behaviour that works better or faster                            |
| 🐛    | Fixed    | A bug fix                                                                 |

The title says what changed for the user in a few words, in sentence case with no trailing period. The body is one plain paragraph in the present tense, saying what the user notices now, and what happened before when that helps. A note holds no other heading, list, table, code block or second paragraph.

### Checking notes

```
bun run tegami version --dry-run
```

This checks every note in `.tegami/` and prints the section the Release workflow would write to `CHANGELOG.md`, changing no file.

### Shipping

Running the Release workflow opens a version pull request that bumps `Cargo.toml` and writes `CHANGELOG.md`. Merging it starts the Publish workflow, which builds the library on macOS arm64, Linux x64 and Linux arm64, runs the end to end tests against each build, then tags `v<version>` and creates the GitHub Release with the archives and `SHA256SUMS`. Nothing goes to crates.io.

### Bumps

Under 1.0, the bump follows the change, not the pull request's Conventional Commit type. A new capability or a breaking change is a minor. Extending or correcting existing behaviour is a patch.
