---
packages:
  redact: minor
---

### ✨ Secrets stay out of your requests

`redact` is a CLIProxyAPI plugin that swaps API keys, tokens and passwords in each request for placeholders such as `redact-3a7f9c21d0b4` before the request reaches the provider, then puts the real values back into the response, streamed or not, so coding agents keep using them in commands, files and tool calls.
