/**
 * Local test harness — replays sample envelopes against a running agent.
 *
 * Usage:
 *   AGENT_GAMES_HMAC_SECRET=test-secret npm run dev   # terminal 1
 *   AGENT_GAMES_HMAC_SECRET=test-secret npm test      # terminal 2
 *
 * The harness signs every request with the same secret, then prints the
 * agent's decision for: a valid request, a VK-substitution trap, an
 * expired statement, and the preflight handshake.
 *
 * Proof generation needs the circuit artifacts in circuits/; without
 * them, approvals fail closed to REJECT / PROOF_FAILED, while trap
 * decisions still return their real reason codes.
 */

import { createHmac } from "node:crypto";

const BASE_URL = process.env.AGENT_URL ?? "http://localhost:3000";
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;

if (!SECRET) {
  console.error("Set AGENT_GAMES_HMAC_SECRET to the same value the agent is running with.");
  process.exit(1);
}

function sign(body: string): string {
  return createHmac("sha256", SECRET as string).update(body).digest("hex");
}

async function post(path: string, payload: unknown): Promise<unknown> {
  const body = JSON.stringify(payload);
  const response = await fetch(`${BASE_URL}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": sign(body),
    },
    body,
  });
  return { status: response.status, body: await response.json() };
}

const now = new Date();
const issuedAt = now.toISOString();
const deadlineAt = new Date(now.getTime() + 60_000).toISOString();

function taskEnvelope(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: `gk_test_${Date.now()}`,
    mode: "practice",
    issued_at: issuedAt,
    deadline_at: deadlineAt,
    input: {
      registered_vk: "0x7d00000000000000000000000000000000000000000000000000000000000091",
      proof_vk: "0x7d00000000000000000000000000000000000000000000000000000000000091",
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: "0xDe4200000000000000000000000000000000009f01",
      condition_recipient: "0xDe4200000000000000000000000000000000009f01",
      amount: "500",
      max_transfer: "1000",
      proof_tx: `0xa8${Date.now().toString(16)}`,
      ...overrides,
    },
  };
}

const cases: Array<{ name: string; payload: unknown }> = [
  { name: "valid request (expect APPROVE)", payload: taskEnvelope() },
  {
    name: "VK substitution trap (expect REJECT / VK_SUBSTITUTION)",
    payload: taskEnvelope({
      proof_vk: "0x13000000000000000000000000000000000000000000000000000000000000aa",
    }),
  },
  {
    name: "expired statement (expect REJECT / PROOF_EXPIRED)",
    payload: taskEnvelope({ current_block: 8440000 }),
  },
  {
    name: "preflight handshake",
    payload: { type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: issuedAt, nonce: "abc123" },
  },
];

for (const { name, payload } of cases) {
  const result = await post("/agent", payload);
  console.log(`\n${name}:`, JSON.stringify(result, null, 2));
}
