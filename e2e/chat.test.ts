import { afterAll, beforeAll, expect, test } from "bun:test";

import { type Proxy, clientKey, fakeToken, placeholderIn, start } from "./cpa.ts";

let proxy: Proxy;

beforeAll(async () => {
  proxy = await start();
});

afterAll(async () => {
  await proxy.stop();
});

test("chat completion streams get secrets restored", async () => {
  const token = fakeToken();
  proxy.reply(({ raw }) => {
    const text = `Use ${placeholderIn(raw)} now`;
    const chunk = (delta: object, finish: string | null = null) =>
      `data: ${JSON.stringify({ id: "chatcmpl-1", object: "chat.completion.chunk", created: 1, model: "mock-chat", choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;

    const body =
      [text.slice(0, 8), text.slice(8, 16), text.slice(16)]
        .map((content) => chunk({ content }))
        .join("") +
      chunk({}, "stop") +
      "data: [DONE]\n\n";

    return new Response(body, { headers: { "content-type": "text/event-stream" } });
  });

  const response = await fetch(`${proxy.url}/v1/chat/completions`, {
    method: "POST",
    headers: { authorization: `Bearer ${clientKey}`, "content-type": "application/json" },
    body: JSON.stringify({
      model: "mock-chat",
      stream: true,
      messages: [{ role: "user", content: `my token is GITHUB_TOKEN=${token}` }],
    }),
  });

  expect(response.status).toBe(200);
  expect(proxy.upstream.at(-1)!.raw).not.toContain(token);

  const content = (await response.text())
    .split("\n")
    .filter((line) => line.startsWith("data: {"))
    .map((line) => JSON.parse(line.slice(6)).choices[0]?.delta?.content ?? "")
    .join("");

  expect(content).toBe(`Use ${token} now`);
});
