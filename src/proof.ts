/**
 * Groth16 proof generation (snarkjs) and zkVerify submission (Kurier).
 *
 * For an APPROVE decision, the agent generates its decision proof locally
 * with the gatekeeper circuit artifacts (circuits/gatekeeper.wasm,
 * circuits/gatekeeper_final.zkey) and, when a Kurier API key is configured,
 * submits the proof to zkVerify and waits for a Finalized result before
 * treating it as confirmed. REJECT decisions carry the reason code and
 * the echoed proof_tx, as in the guide's example response.
 */

import * as snarkjs from "snarkjs";
import { buildCircuitInput, type Decision, type GatekeeperTask } from "./gatekeeper.js";

export interface GeneratedProof {
  proof: unknown;
  publicSignals: string[];
}

const WASM_PATH = process.env.CIRCUIT_WASM_PATH ?? "./circuits/gatekeeper.wasm";
const ZKEY_PATH = process.env.CIRCUIT_ZKEY_PATH ?? "./circuits/gatekeeper_final.zkey";

/** Registered verification-key hash for the Proof Gatekeeper circuit. */
export const REGISTERED_VK_HASH =
  process.env.REGISTERED_VK_HASH ??
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

export async function generateDecisionProof(
  task: GatekeeperTask,
  decision: Decision,
): Promise<GeneratedProof> {
  const circuitInput = buildCircuitInput(task, decision);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput,
    WASM_PATH,
    ZKEY_PATH,
  );
  return { proof, publicSignals: publicSignals.map(String) };
}

export interface KurierJob {
  jobId?: string;
  status?: string;
  [key: string]: unknown;
}

const KURIER_API_URL = "https://api.kurier.xyz/api/v1";

function kurierApiKey(): string | undefined {
  return process.env.KURIER_API_KEY || undefined;
}

/**
 * Submit a Groth16 proof to zkVerify through Kurier and wait until the
 * job reaches Finalized (or the timeout elapses). Returns the final job
 * status, or null when Kurier is not configured.
 *
 * The status endpoint can be overridden with KURIER_STATUS_URL if the
 * Kurier API reference uses a different path.
 */
export async function submitProofToKurier(
  generated: GeneratedProof,
  timeoutMs = 30_000,
): Promise<string | null> {
  const apiKey = kurierApiKey();
  if (!apiKey) {
    console.warn(
      "[kurier] KURIER_API_KEY is not set — skipping on-chain submission; returning local proof only.",
    );
    return null;
  }

  const response = await fetch(`${KURIER_API_URL}/submit-proof/${apiKey}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      proofType: "groth16",
      vkRegistered: true,
      proofOptions: { library: "snarkjs", curve: "bn128" },
      proofData: {
        proof: generated.proof,
        publicSignals: generated.publicSignals,
        vk: REGISTERED_VK_HASH,
      },
    }),
    signal: AbortSignal.timeout(10_000),
  });

  if (!response.ok) {
    throw new Error(`Kurier submission failed: HTTP ${response.status}`);
  }

  const job = (await response.json()) as KurierJob;
  const jobId = job.jobId ?? job.id;
  if (!jobId || typeof jobId !== "string") {
    return "Submitted";
  }

  const statusUrl =
    process.env.KURIER_STATUS_URL ?? `${KURIER_API_URL}/job/${jobId}`;
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    await new Promise((resolve) => setTimeout(resolve, 3_000));
    const statusResponse = await fetch(statusUrl, {
      signal: AbortSignal.timeout(10_000),
    });
    if (!statusResponse.ok) continue;
    const statusJob = (await statusResponse.json()) as KurierJob;
    const status = statusJob.status;
    if (status === "Finalized") return "Finalized";
    if (status === "Failed" || status === "Error") return status;
  }
  return "Submitted";
}
