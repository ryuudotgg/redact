<h1 align="center">redact</h1>

<p align="center">
  A CLIProxyAPI plugin that keeps secrets out of the requests your coding agents send.
</p>

<p align="center">
  <a href="https://github.com/ryuudotgg/redact/releases/latest">Releases</a>
  ·
  <a href="https://github.com/ryuudotgg/redact/issues">Issues</a>
</p>

<p align="center">
  <a href="LICENSE.md"><img src="https://img.shields.io/github/license/ryuudotgg/redact?style=for-the-badge&labelColor=000000" alt="MIT License"></a>
  <a href="https://github.com/ryuudotgg/redact/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ryuudotgg/redact/ci.yml?branch=main&style=for-the-badge&labelColor=000000&label=CI" alt="CI"></a>
</p>

## ✨ What is redact?

Coding agents read `.env` files, print tokens in shell output and paste keys into commands, and everything they read goes to the model provider. `redact` runs inside [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) and swaps each secret in a request for a placeholder before the request leaves your machine. When the model writes a placeholder back, in a reply, a shell command or a file edit, `redact` puts the real value back in. The provider never sees the key, and the agent works as if it had.

What the provider sees when an agent runs `cat .env`:

```diff
 NODE_ENV=production
-GITHUB_TOKEN=ghp_9fK2mQx7LpVbN4...
+GITHUB_TOKEN=redact-3a7f9c21d0b4
-DATABASE_URL=postgres://app:hunter2pass@db.internal:5432/app
+DATABASE_URL=postgres://app:redact-81b0c4e9d2f7@db.internal:5432/app
```

It catches:

- every key format the [Gitleaks](https://github.com/gitleaks/gitleaks) rules know, including AWS, GitHub, Stripe, OpenAI and Anthropic keys
- values assigned to names like `DB_PASSWORD`, `apiKey` or `x-api-key`, in `.env` files, YAML, JSON, shell commands and string literals
- `Authorization` header values and passwords inside connection strings
- any value it already caught, wherever that value shows up again

It leaves code alone. `const apiKey = process.env.OPENAI_API_KEY`, `os.environ["KEY"]`, `password: z.string()` and `${DB_PASSWORD}` reach the model as written, and so do commit hashes, UUIDs and lockfile integrity hashes.

## 🚀 Getting Started

`redact` needs CLIProxyAPI 8 with plugin support. The release builds have it. The `no-plugin` builds do not.

Take the archive for your machine from the [latest release](https://github.com/ryuudotgg/redact/releases/latest), check it against `SHA256SUMS`, and extract it into your plugins directory. With Homebrew on a Mac:

```bash
cd "$(brew --prefix)/var/cliproxyapi/plugins"
curl -fsSLO https://github.com/ryuudotgg/redact/releases/latest/download/redact-darwin-arm64.tar.gz
curl -fsSL https://github.com/ryuudotgg/redact/releases/latest/download/SHA256SUMS | shasum -a 256 -c --ignore-missing
tar -xzf redact-darwin-arm64.tar.gz
```

| Asset                        | Platform               |
| ---------------------------- | ---------------------- |
| `redact-darwin-arm64.tar.gz` | macOS on Apple silicon |
| `redact-linux-x64.tar.gz`    | Linux x64 with glibc   |
| `redact-linux-arm64.tar.gz`  | Linux arm64 with glibc |

Then turn it on in CLIProxyAPI's config:

```yaml
plugins:
  enabled: true
  dir: "/opt/homebrew/var/cliproxyapi/plugins"
  configs:
    redact:
      enabled: true
```

CLIProxyAPI reloads its config when the file changes, and logs `redact is ready` once the plugin is up.

### Configuration

Every key is optional, and the defaults are what most setups want.

| Key              | Default            | What it does                                                                                        |
| ---------------- | ------------------ | --------------------------------------------------------------------------------------------------- |
| `rules_file`     | the embedded rules | Absolute path to a Gitleaks rules file that replaces the embedded rules.                            |
| `disabled_rules` | `[]`               | Gitleaks rule ids to turn off, such as `generic-api-key`.                                           |
| `allow`          | `[]`               | Regular expressions matching values that are never replaced.                                        |
| `notice`         | `true`             | Tell the model, in the system prompt, how to use placeholders. Only requests that carry one get it. |

A config `redact` cannot use never turns it off. A broken first config falls back to the embedded rules, a broken reload keeps the previous config, and both log the reason.

> [!IMPORTANT]
> Keep `upstream.codex.response-steering` off, which is the default. With steering on, CLIProxyAPI sends follow-up Codex messages upstream without running plugins, so `redact` never sees them.

## 🔍 How It Works

A placeholder is `redact-` followed by 12 hex digits of an HMAC of the value, keyed by a secret that `redact` generates when CLIProxyAPI starts. The same value gets the same placeholder for the life of the process, so provider prompt caches stay warm across turns. Real values live in memory and never touch the disk.

On the way out, `redact` scans every string in the request except signed thinking and reasoning blocks and base64 data. Inside a tool's input or output nothing is skipped, and a value stored under a key such as `password` or `apiKey` is replaced whole. It rewrites only the bytes of the secrets it replaces, so it leaves a request without secrets exactly as it was, and tool call arguments stay valid JSON.

On the way back, it restores placeholders in replies, tool calls and streamed deltas for Claude Messages, OpenAI Chat Completions, OpenAI Responses (Codex too, over WebSocket) and Gemini. A placeholder split across two stream chunks is held back until it is whole. Thinking blocks keep their placeholders, because the provider verifies their signatures.

When a JSON request fails to parse, `redact` rejects it instead of sending it. A body that is not JSON, such as a multipart image edit, cannot be rewritten safely, so `redact` scans it as text and rejects it if it holds a secret. When restoring a response fails, the client gets the placeholder, which leaks nothing.

`redact` is written in Rust because CLIProxyAPI loads plugins into its own process. A Go plugin would add a second Go runtime to a Go host, and a crash would take down every agent behind the proxy. In `redact`, a panic fails only the request that caused it.

> [!NOTE]
> `redact` covers only traffic through CLIProxyAPI, and a key an agent prints still shows in your terminal and its transcripts. It keeps keys from the provider, not from the agent: if a prompt injection gets the model to put a placeholder in a command, the command runs with the real key, as it would without `redact`. A random string with no known format, assigned to a name that does not sound secret, gets through, and so does a password made only of letters. Placeholders change when CLIProxyAPI restarts, which costs each conversation one prompt cache miss. Every client of the same CLIProxyAPI shares one set of placeholders, so on a proxy you share with people you do not trust, anyone who learns one of your placeholders can get its value back.

## 🤝 Contributing

To build from source and run the checks, see [CONTRIBUTING.md](CONTRIBUTING.md). Report bugs on [GitHub Issues](https://github.com/ryuudotgg/redact/issues).

## 👥 Authors

- Ryuu ([@ryuudotgg](https://github.com/ryuudotgg))
  - `redact` builds on ideas from [szxypi/cpa-plugin-privacyfilter](https://github.com/szxypi/cpa-plugin-privacyfilter): reversible placeholders, holding split placeholders back in streams, and rewriting only the changed bytes. That plugin is a fork of [rheodev/cpa-plugin-privacyfilter](https://github.com/rheodev/cpa-plugin-privacyfilter), which adapted [packyme/privacy-filter](https://github.com/packyme/privacy-filter) to CLIProxyAPI.
  - Secret detection runs the [Gitleaks](https://github.com/gitleaks/gitleaks) rule set.

## 📄 License

This project is licensed under the MIT License, see [LICENSE.md](LICENSE.md) for details. The embedded Gitleaks rules are MIT licensed by Zachary Rice, see [rules/LICENSE](rules/LICENSE).
