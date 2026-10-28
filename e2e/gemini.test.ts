import { afterAll, beforeAll, expect, test } from "bun:test";

import { type Proxy, clientKey, fakeToken, placeholderIn, start } from "./cpa.ts";

let proxy: Proxy;

beforeAll(async () => {
  proxy = await start();
});

afterAll(async () => {
  await proxy.stop();
});

test("Gemini streams get secrets restored", async () => {
  const token = fakeToken();
  proxy.reply(({ raw }) => {
    const text = `Token ${placeholderIn(raw)} works`;
    const chunk = (part: string, finishReason?: string) =>
      `data: ${JSON.stringify({ candidates: [{ index: 0, content: { role: "model", parts: [{ text: part }] }, ...(finishReason ? { finishReason } : {}) }] })}\r\n\r\n`;

    const body =
      chunk(text.slice(0, 10)) + chunk(text.slice(10, 19)) + chunk(text.slice(19), "STOP");

    return new Response(body, { headers: { "content-type": "text/event-stream" } });
  });

  const response = await fetch(
    `${proxy.url}/v1beta/models/mock-gemini:streamGenerateContent?alt=sse`,
    {
      method: "POST",
      headers: { "x-goog-api-key": clientKey, "content-type": "application/json" },
      body: JSON.stringify({
        contents: [{ role: "user", parts: [{ text: `export GITHUB_TOKEN=${token}` }] }],
      }),
    },
  );

  expect(response.status).toBe(200);
  expect(proxy.upstream.at(-1)!.raw).not.toContain(token);

  const text = (await response.text())
    .split("\n")
    .filter((line) => line.startsWith("data: {"))
    .flatMap((line) => JSON.parse(line.slice(6)).candidates[0].content.parts)
    .map((part: { text?: string }) => part.text ?? "")
    .join("");

  expect(text).toBe(`Token ${token} works`);
});
