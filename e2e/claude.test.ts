import { afterAll, beforeAll, expect, test } from "bun:test";

import {
  type Proxy,
  clientKey,
  fakeToken,
  noticeExample,
  placeholderIn,
  sse,
  start,
} from "./cpa.ts";

let proxy: Proxy;

beforeAll(async () => {
  proxy = await start();
});

afterAll(async () => {
  await proxy.stop();
});

function messages(body: object): Promise<Response> {
  return fetch(`${proxy.url}/v1/messages`, {
    method: "POST",
    headers: {
      "x-api-key": clientKey,
      "anthropic-version": "2023-06-01",
      "content-type": "application/json",
    },
    body: JSON.stringify({ model: "mock-claude", max_tokens: 64, ...body }),
  });
}

function toolResult(content: string): object[] {
  return [
    { role: "user", content: "read my env" },
    {
      role: "assistant",
      content: [{ type: "tool_use", id: "toolu_01", name: "bash", input: { command: "cat .env" } }],
    },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_01", content }] },
  ];
}

test("upstream never sees the key, and the client gets it back", async () => {
  const token = fakeToken();
  proxy.reply(({ raw }) => {
    const reference = placeholderIn(raw);
    return Response.json({
      id: "msg_01",
      type: "message",
      role: "assistant",
      model: "mock-claude",
      content: [
        { type: "text", text: `It is ${reference}` },
        {
          type: "tool_use",
          id: "toolu_02",
          name: "bash",
          input: { command: `gh auth login --with-token ${reference}` },
        },
      ],
      stop_reason: "tool_use",
      usage: { input_tokens: 1, output_tokens: 1 },
    });
  });

  const response = await messages({
    messages: toolResult(`NODE_ENV=production\nGITHUB_TOKEN=${token}\n`),
  });

  const sent = proxy.upstream.at(-1)!;

  expect(response.status).toBe(200);
  expect(sent.raw).not.toContain(token);
  expect(JSON.stringify(sent.body.system)).toContain(noticeExample);

  const reply = (await response.json()) as {
    content: [{ text: string }, { input: { command: string } }];
  };

  expect(reply.content[0].text).toBe(`It is ${token}`);
  expect(reply.content[1].input.command).toBe(`gh auth login --with-token ${token}`);
});

test("placeholders split across stream deltas are restored", async () => {
  const token = fakeToken();
  proxy.reply(({ raw }) => {
    const text = `Token: ${placeholderIn(raw)} done`;
    const pieces = [text.slice(0, 9), text.slice(9, 15), text.slice(15, 24), text.slice(24)];
    return sse([
      {
        type: "message_start",
        message: {
          id: "msg_02",
          type: "message",
          role: "assistant",
          model: "mock-claude",
          content: [],
          usage: { input_tokens: 1, output_tokens: 0 },
        },
      },
      { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } },
      ...pieces.map((piece) => ({
        type: "content_block_delta",
        index: 0,
        delta: { type: "text_delta", text: piece },
      })),
      { type: "content_block_stop", index: 0 },
      { type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 4 } },
      { type: "message_stop" },
    ]);
  });

  const response = await messages({
    stream: true,
    messages: toolResult(`export GITHUB_TOKEN=${token}`),
  });

  const text = (await response.text())
    .split("\n")
    .filter((line) => line.startsWith("data: "))
    .map((line) => JSON.parse(line.slice(6)))
    .filter((event) => event.delta?.type === "text_delta")
    .map((event) => event.delta.text)
    .join("");

  expect(text).toBe(`Token: ${token} done`);
});

test("requests without secrets reach upstream unchanged", async () => {
  const body = {
    messages: [{ role: "user", content: "const apiKey = process.env.OPENAI_API_KEY;" }],
  };

  proxy.reply(() =>
    Response.json({
      id: "msg_03",
      type: "message",
      role: "assistant",
      model: "mock-claude",
      content: [],
      stop_reason: "end_turn",
      usage: { input_tokens: 1, output_tokens: 1 },
    }),
  );

  await messages(body);
  const sent = proxy.upstream.at(-1)!.raw;

  expect(sent).toContain(JSON.stringify(body.messages[0]!.content));
  expect(sent).not.toContain("redact-");
});
