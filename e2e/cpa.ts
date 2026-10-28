import { copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

export interface Recorded {
  path: string;
  raw: string;
  body: any;
}

type Reply = (request: Recorded) => Response;

export interface Proxy {
  url: string;
  upstream: Recorded[];
  reply(next: Reply): void;
  logs(): string;
  stop(): Promise<void>;
}

export const clientKey = "e2e-client-key";

const platform = {
  os: process.platform === "darwin" ? "darwin" : "linux",
  arch: process.arch === "arm64" ? "arm64" : "amd64",
  extension: process.platform === "darwin" ? "dylib" : "so",
};

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

export function fakeToken(): string {
  const random = crypto.getRandomValues(new Uint8Array(36));
  return ["gh", "p_", ...Array.from(random, (byte) => alphabet[byte % alphabet.length])].join("");
}

export const noticeExample = "redact-0123456789ab";

export function placeholderIn(text: string): string {
  const found = [...text.matchAll(/redact-[0-9a-f]{12}/g)]
    .map(([match]) => match)
    .find((match) => match !== noticeExample);

  if (!found) throw new Error(`no placeholder in ${text.slice(0, 200)}`);

  return found;
}

export function sse(events: object[]): Response {
  const body = events
    .map(
      (event) => `event: ${(event as { type: string }).type}\ndata: ${JSON.stringify(event)}\n\n`,
    )
    .join("");

  return new Response(body, { headers: { "content-type": "text/event-stream" } });
}

export async function start(): Promise<Proxy> {
  const dir = await mkdtemp(join(tmpdir(), "redact-e2e-"));
  const upstream: Recorded[] = [];
  const replies: Reply[] = [];

  const mock = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const raw = await request.text();
      const recorded = {
        path: new URL(request.url).pathname,
        raw,
        body: raw ? JSON.parse(raw) : null,
      };

      upstream.push(recorded);

      const reply = replies.shift();
      return reply ? reply(recorded) : new Response("no reply scripted", { status: 500 });
    },
  });

  const plugins = join(dir, "plugins", platform.os, platform.arch);
  await mkdir(plugins, { recursive: true });
  await copyFile(library(), join(plugins, `redact.${platform.extension}`));

  const port = freePort();
  await writeFile(join(dir, "config.yaml"), config(port, listening(mock), dir));

  let output = "";
  const cpa = Bun.spawn([cpaBinary(), "-config", join(dir, "config.yaml")], {
    cwd: dir,
    stdout: "pipe",
    stderr: "pipe",
  });

  for (const stream of [cpa.stdout, cpa.stderr])
    void (async () => {
      for await (const chunk of stream) output += new TextDecoder().decode(chunk);
    })();

  const url = `http://127.0.0.1:${port}`;
  await ready(url, () => output);

  return {
    url,
    upstream,
    reply: (next) => replies.push(next),
    logs: () => output,
    async stop() {
      cpa.kill();
      await cpa.exited;
      await mock.stop(true);
      await rm(dir, { recursive: true, force: true });
    },
  };
}

function library(): string {
  const name = `libredact.${platform.extension}`;
  return resolve(
    process.env.REDACT_LIBRARY ?? join(import.meta.dir, "..", "target", "debug", name),
  );
}

function cpaBinary(): string {
  const binary = process.env.CPA_BIN ?? Bun.which("cliproxyapi") ?? Bun.which("cli-proxy-api");
  if (!binary) throw new Error("set CPA_BIN to a CLIProxyAPI binary, or put cliproxyapi on PATH");
  return binary;
}

function freePort(): number {
  const probe = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response() });
  const port = listening(probe);
  void probe.stop(true);

  return port;
}

function listening(server: { port?: number }): number {
  if (server.port === undefined) throw new Error("the server is not listening on a port");
  return server.port;
}

async function ready(url: string, logs: () => string): Promise<void> {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const models = await fetch(`${url}/v1/models`, {
      headers: { authorization: `Bearer ${clientKey}` },
    }).catch(() => null);

    if (models?.ok && logs().includes("redact is ready")) return;

    await Bun.sleep(100);
  }

  throw new Error(`CLIProxyAPI did not become ready:\n${logs()}`);
}

function config(port: number, mockPort: number, dir: string): string {
  const mock = `http://127.0.0.1:${mockPort}`;
  return `config-version: 8
server:
  host: 127.0.0.1
  port: ${port}
access:
  api-keys:
    - "${clientKey}"
oauth:
  auth-dir: "${join(dir, "auth")}"
routing:
  retry:
    request-retry: 0
api-keys:
  claude:
    - name: mock-claude
      base-url: "${mock}"
      models:
        - name: mock-claude
          alias: mock-claude
      keys:
        - api-key: "upstream-key"
  codex:
    - name: mock-codex
      base-url: "${mock}"
      models:
        - name: mock-codex
          alias: mock-codex
      keys:
        - api-key: "upstream-key"
  gemini:
    - name: mock-gemini
      base-url: "${mock}"
      models:
        - name: mock-gemini
          alias: mock-gemini
      keys:
        - api-key: "upstream-key"
  openai-compatibility:
    - name: mock-openai
      base-url: "${mock}/v1"
      models:
        - name: mock-chat
          alias: mock-chat
      keys:
        - api-key: "upstream-key"
plugins:
  enabled: true
  dir: "${join(dir, "plugins")}"
  configs:
    redact:
      enabled: true
`;
}
