/**
 * Vercel serverless entry point for the Proof Gatekeeper agent.
 *
 * Same protocol as src/server.ts (POST /agent, HMAC-SHA256 over the raw
 * body, deterministic decision, Groth16 proof for APPROVE, fail closed),
 * packaged as a Vercel Node function. Kurier submission is skipped here:
 * Vercel hobby functions time out at 10s and the platform re-verifies
 * the returned proof itself.
 *
 * Required env vars (Vercel dashboard):
 *   AGENT_GAMES_HMAC_SECRET — platform-issued secret (Rotate Secret)
 *   CIRCUIT_WASM_PATH       — e.g. ./circuits/gatekeeper.wasm
 *   CIRCUIT_ZKEY_PATH       — e.g. ./circuits/gatekeeper_final.zkey
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { evaluateGatekeeper } from "../dist/gatekeeper.js";
import { generateDecisionProof } from "../dist/proof.js";

export const config = {
  api: {
    bodyParser: false,
  },
};

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET ?? "";

// Proof references already answered — a proof_tx must never be spent twice.
// In-memory only; Vercel may run several instances, so the platform's own
// reuse tracking is the backstop.
const usedProofs = new Set();

function sign(body) {
  return createHmac("sha256", SECRET).update(body).digest("hex");
}

function verifySignature(rawBody, signature) {
  if (!signature || !SECRET) return false;
  const expected = createHmac("sha256", SECRET).update(rawBody).digest();
  let provided;
  try {
    provided = Buffer.from(signature, "hex");
  } catch {
    return false;
  }
  if (provided.length !== expected.length) return false;
  return timingSafeEqual(provided, expected);
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json",
    "x-agent-games-signature": sign(body),
  });
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export default async function handler(req, res) {
  if (req.method === "GET") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, service: "agent-games-proof-gatekeeper" }));
    return;
  }
  if (req.method !== "POST") {
    sendJson(res, 405, { error: "method_not_allowed" });
    return;
  }
  if (!SECRET) {
    console.error("Missing AGENT_GAMES_HMAC_SECRET");
    sendJson(res, 500, { error: "server_misconfigured" });
    return;
  }

  const rawBody = await readRawBody(req);
  const signature = req.headers["x-agent-games-signature"];
  if (!verifySignature(rawBody, Array.isArray(signature) ? signature[0] : signature)) {
    sendJson(res, 401, { error: "invalid_signature" });
    return;
  }

  let envelope;
  try {
    envelope = JSON.parse(rawBody.toString("utf8"));
  } catch {
    sendJson(res, 400, { error: "invalid_json" });
    return;
  }

  if (envelope.type === "agent-games.preflight.v1") {
    sendJson(res, 200, { ok: true, protocolVersion: "v1" });
    return;
  }

  if (envelope.type !== "agent-games.proof-gatekeeper.v1") {
    sendJson(res, 400, { error: "unknown_envelope_type" });
    return;
  }

  const task = envelope;
  if (!task.input || typeof task.input !== "object") {
    sendJson(res, 400, { error: "missing_input" });
    return;
  }

  const decision = evaluateGatekeeper(task, usedProofs);
  const proofTx = task.input.proof_tx ?? "";
  if (proofTx) usedProofs.add(proofTx.toLowerCase());

  let finalDecision = decision.decision;
  let finalReason = decision.reason_code;
  let proof = null;
  let publicSignals = [];

  if (decision.decision === "APPROVE") {
    try {
      const generated = await Promise.race([
        generateDecisionProof(task, decision.decision),
        new Promise((_resolve, reject) =>
          setTimeout(() => reject(new Error("proof timeout")), 8_000),
        ),
      ]);
      proof = generated.proof;
      publicSignals = generated.publicSignals;
    } catch (error) {
      console.error(`[task ${task.task_id}] proof generation failed:`, error);
      finalDecision = "REJECT";
      finalReason = "PROOF_FAILED";
      proof = null;
      publicSignals = [];
    }
  }

  sendJson(res, 200, {
    decision: finalDecision,
    reason_code: finalReason,
    proof_tx: proofTx,
    proof,
    public_signals: publicSignals,
  });
}
