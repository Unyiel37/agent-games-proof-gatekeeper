/**
 * Proof Gatekeeper agent — public HTTPS endpoint for zkVerify Agent Games.
 *
 * Protocol (Proof Gatekeeper):
 *  - POST /agent accepts a signed JSON task envelope.
 *  - Every inbound request is authenticated first: HMAC-SHA256 over the
 *    RAW request body, compared against the `x-agent-games-signature`
 *    header with the platform-issued secret (AGENT_GAMES_HMAC_SECRET).
 *  - Preflight requests ({ type: "agent-games.preflight.v1" }) are
 *    answered with { ok: true, protocolVersion: "v1" }, signed.
 *  - Task requests ({ type: "agent-games.proof-gatekeeper.v1" }) are
 *    decided by deterministic rules (see gatekeeper.ts). For an APPROVE,
 *    a Groth16 proof is generated and answered with { decision,
 *    reason_code, proof_tx, proof, public_signals } — signed over the
 *    raw response body. REJECT answers carry the reason code and the
 *    echoed proof_tx.
 *  - Fail closed: any error, timeout, or uncertainty is a REJECT.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { evaluateGatekeeper, type GatekeeperTask } from "./gatekeeper.js";
import { generateDecisionProof, submitProofToKurier } from "./proof.js";

const PORT = Number(process.env.PORT ?? 3000);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET;

if (!HMAC_SECRET) {
  console.error(
    "Missing AGENT_GAMES_HMAC_SECRET. Copy the one-time secret from the Agent Games dashboard (Rotate Secret) into your environment and restart.",
  );
  process.exit(1);
}

const SECRET = HMAC_SECRET as string;

// Proof references already answered — a proof_tx must never be spent twice.
// In-memory only; use durable storage (Redis/DB) when running multi-instance.
const usedProofs = new Set<string>();

function sign(body: string): string {
  return createHmac("sha256", SECRET).update(body).digest("hex");
}

function verifySignature(rawBody: Buffer, signature: string | undefined): boolean {
  if (!signature) return false;
  const expected = createHmac("sha256", SECRET).update(rawBody).digest();
  let provided: Buffer;
  try {
    provided = Buffer.from(signature, "hex");
  } catch {
    return false;
  }
  if (provided.length !== expected.length) return false;
  return timingSafeEqual(provided, expected);
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json",
    "x-agent-games-signature": sign(body),
  });
  res.end(body);
}

function readRawBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function handleAgent(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const rawBody = await readRawBody(req);
  const signature = req.headers["x-agent-games-signature"];
  if (!verifySignature(rawBody, Array.isArray(signature) ? signature[0] : signature)) {
    sendJson(res, 401, { error: "invalid_signature" });
    return;
  }

  let envelope: Record<string, unknown>;
  try {
    envelope = JSON.parse(rawBody.toString("utf8")) as Record<string, unknown>;
  } catch {
    sendJson(res, 400, { error: "invalid_json" });
    return;
  }

  // Preflight handshake — must pass before the platform marks the agent active.
  if (envelope.type === "agent-games.preflight.v1") {
    sendJson(res, 200, { ok: true, protocolVersion: "v1" });
    return;
  }

  if (envelope.type !== "agent-games.proof-gatekeeper.v1") {
    sendJson(res, 400, { error: "unknown_envelope_type" });
    return;
  }

  const task = envelope as unknown as GatekeeperTask;
  if (!task.input || typeof task.input !== "object") {
    sendJson(res, 400, { error: "missing_input" });
    return;
  }

  const startedAt = Date.now();
  const decision = evaluateGatekeeper(task, usedProofs);
  const proofTx = task.input.proof_tx ?? "";

  // Record the proof reference before proving, so a retried task cannot
  // spend the same reference twice.
  if (proofTx) usedProofs.add(proofTx.toLowerCase());

  let finalDecision = decision.decision;
  let finalReason = decision.reason_code;
  let proof: unknown = null;
  let publicSignals: string[] = [];

  if (decision.decision === "APPROVE") {
    try {
      const generated = await Promise.race([
        generateDecisionProof(task, decision.decision),
        new Promise<never>((_resolve, reject) =>
          setTimeout(() => reject(new Error("proof timeout")), 40_000),
        ),
      ]);
      proof = generated.proof;
      publicSignals = generated.publicSignals;

      // Submit the proof to zkVerify and wait for finality when configured,
      // staying inside the platform's 60 second response deadline.
      // A submission failure never flips the decision — the locally
      // generated proof is returned either way for the platform to verify.
      const remainingMs = 50_000 - (Date.now() - startedAt);
      if (remainingMs > 5_000) {
        try {
          const status = await submitProofToKurier(generated, remainingMs);
          if (status) console.log(`[task ${task.task_id}] kurier status: ${status}`);
        } catch (error) {
          console.error(`[task ${task.task_id}] kurier submission failed:`, error);
        }
      }
    } catch (error) {
      // Fail closed on proof errors: never approve without a proof.
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

const server = createServer((req, res) => {
  if (req.method === "GET" && (req.url === "/health" || req.url === "/")) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({ ok: true, service: "agent-games-proof-gatekeeper" }),
    );
    return;
  }
  if (req.method === "POST" && req.url === "/agent") {
    handleAgent(req, res).catch((error) => {
      console.error("handler error:", error);
      if (!res.headersSent) sendJson(res, 500, { error: "internal_error" });
    });
    return;
  }
  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not_found" }));
});

server.listen(PORT, () => {
  console.log(`Proof Gatekeeper agent listening on port ${PORT} (POST /agent)`);
});
