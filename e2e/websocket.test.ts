import { afterAll, beforeAll, expect, test } from "bun:test";

import { type Proxy, clientKey, fakeToken, placeholderIn, start } from "./cpa.ts";

let proxy: Proxy;

beforeAll(async () => {
  proxy = await start();
});

afterAll(async () => {
  await proxy.stop();
});

test("Codex over WebSocket gets secrets restored", async () => {
  const token = fakeToken();
  proxy.reply(({ raw }) => {
    const text = `Logged in with ${placeholderIn(raw)}.`;
    const item = {
      id: "msg_1",
      type: "message",
      role: "assistant",
      status: "completed",
      content: [{ type: "output_text", text, annotations: [] }],
    };

    const response = {
      id: "resp_1",
      object: "response",
      status: "completed",
      model: "mock-codex",
      output: [item],
    };

    const events = [
      { type: "response.created", response: { ...response, status: "in_progress", output: [] } },
      ...[text.slice(0, 20), text.slice(20, 27), text.slice(27)].map((delta) => ({
        type: "response.output_text.delta",
        item_id: "msg_1",
        output_index: 0,
        content_index: 0,
        delta,
      })),
      {
        type: "response.output_text.done",
        item_id: "msg_1",
        output_index: 0,
        content_index: 0,
        text,
      },
      { type: "response.output_item.done", output_index: 0, item },
      { type: "response.completed", response },
    ];

    const body = events
      .map(
        (event, index) =>
          `event: ${event.type}\ndata: ${JSON.stringify({ ...event, sequence_number: index })}\n\n`,
      )
      .join("");

    return new Response(body, { headers: { "content-type": "text/event-stream" } });
  });

  const socket = new WebSocket(`${proxy.url.replace("http", "ws")}/v1/responses`, {
    headers: { authorization: `Bearer ${clientKey}` },
  });

  const events: {
    type: string;
    delta?: string;
    response?: { output: { content: { text: string }[] }[] };
  }[] = [];

  await new Promise<void>((resolve, reject) => {
    socket.addEventListener("open", () => {
      socket.send(
        JSON.stringify({
          type: "response.create",
          model: "mock-codex",
          input: [
            {
              type: "message",
              role: "user",
              content: [{ type: "input_text", text: `GITHUB_TOKEN=${token}` }],
            },
          ],
        }),
      );
    });

    socket.addEventListener("message", (message) => {
      const event = JSON.parse(String(message.data));
      events.push(event);
      if (event.type === "response.completed" || event.type === "error") resolve();
    });

    socket.addEventListener("error", () => reject(new Error("the WebSocket failed")));
  });

  socket.close();

  expect(proxy.upstream.at(-1)!.raw).not.toContain(token);
  const deltas = events
    .filter((event) => event.type === "response.output_text.delta")
    .map((event) => event.delta)
    .join("");

  const completed = events.find((event) => event.type === "response.completed");

  expect(deltas).toBe(`Logged in with ${token}.`);
  expect(completed?.response?.output[0]?.content[0]?.text).toBe(`Logged in with ${token}.`);
});
