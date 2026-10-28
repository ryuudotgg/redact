## 0.1.0

_October 28, 2026_

### ✨ New

- **Secrets stay out of your requests** ([#1](https://github.com/ryuudotgg/redact/pull/1))\
  `redact` is a CLIProxyAPI plugin that swaps API keys, tokens and passwords in each request for placeholders such as `redact-3a7f9c21d0b4` before the request reaches the provider, then puts the real values back into the response, streamed or not, so coding agents keep using them in commands, files and tool calls.
