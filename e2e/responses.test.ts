import { afterAll, beforeAll, expect, test } from "bun:test";

import { type Proxy, clientKey, fakeToken, placeholderIn, start } from "./cpa.ts";

let proxy: Proxy;

beforeAll(async () => {
  proxy = await start();
});

afterAll(async () => {
  await proxy.stop();
});

function frames(events: object[]): Response {
  const body = events
    .map(
      (event, index) =>
        `event: ${(event as { type: string }).type}\ndata: ${JSON.stringify({ ...event, sequence_number: index })}\n\n`,
    )
    .join("");

  return new Response(body, { headers: { "content-type": "text/event-stream" } });
}

test("Codex streams get secrets restored in text and tool arguments", async () => {
  const token = fakeToken();
  proxy.reply(({ raw }) => {
    const reference = placeholderIn(raw);
    const text = `Logged in with ${reference}.`;
    const args = JSON.stringify({ command: ["gh", "auth", "login", "--with-token", reference] });
    const item = {
      id: "msg_1",
      type: "message",
      role: "assistant",
      status: "completed",
      content: [{ type: "output_text", text, annotations: [] }],
    };

    const call = {
      id: "fc_1",
      type: "function_call",
      status: "completed",
      call_id: "call_1",
      name: "shell",
      arguments: args,
    };

    const response = {
      id: "resp_1",
      object: "response",
      status: "completed",
      model: "mock-codex",
      output: [item, call],
    };

    return frames([
      { type: "response.created", response: { ...response, status: "in_progress", output: [] } },
      {
        type: "response.output_item.added",
        output_index: 0,
        item: { ...item, status: "in_progress", content: [] },
      },
      ...[text.slice(0, 20), text.slice(20, 26), text.slice(26)].map((delta) => ({
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
      {
        type: "response.output_item.added",
        output_index: 1,
        item: { ...call, status: "in_progress", arguments: "" },
      },
      ...[args.slice(0, 50), args.slice(50, 60), args.slice(60)].map((delta) => ({
        type: "response.function_call_arguments.delta",
        item_id: "fc_1",
        output_index: 1,
        delta,
      })),
      {
        type: "response.function_call_arguments.done",
        item_id: "fc_1",
        output_index: 1,
        arguments: args,
      },
      { type: "response.output_item.done", output_index: 1, item: call },
      { type: "response.completed", response },
    ]);
  });

  const response = await fetch(`${proxy.url}/v1/responses`, {
    method: "POST",
    headers: { authorization: `Bearer ${clientKey}`, "content-type": "application/json" },
    body: JSON.stringify({
      model: "mock-codex",
      stream: true,
      input: [
        { type: "message", role: "user", content: [{ type: "input_text", text: "log in to gh" }] },
        {
          type: "function_call",
          call_id: "call_0",
          name: "shell",
          arguments: JSON.stringify({ command: ["cat", ".env"] }),
        },
        { type: "function_call_output", call_id: "call_0", output: `GITHUB_TOKEN=${token}\n` },
      ],
    }),
  });

  expect(response.status).toBe(200);
  expect(proxy.upstream.at(-1)!.raw).not.toContain(token);

  const events = (await response.text())
    .split("\n")
    .filter((line) => line.startsWith("data: "))
    .map((line) => JSON.parse(line.slice(6)));

  const deltas = events
    .filter((event) => event.type === "response.output_text.delta")
    .map((event) => event.delta)
    .join("");

  const args = events
    .filter((event) => event.type === "response.function_call_arguments.delta")
    .map((event) => event.delta)
    .join("");

  const completed = events.find((event) => event.type === "response.completed");

  expect(deltas).toBe(`Logged in with ${token}.`);
  expect(JSON.parse(args).command).toEqual(["gh", "auth", "login", "--with-token", token]);
  expect(JSON.parse(completed.response.output[1].arguments).command.at(-1)).toBe(token);
});
