/**
 * Proof Gatekeeper — deterministic decision logic.
 *
 * The agent APPROVES a transfer request only when EVERY check on the
 * security checklist passes. Anything else is a REJECT, fail closed.
 *
 * Task envelope (agent-games.proof-gatekeeper.v1):
 *   input.registered_vk       verification key registered for the condition
 *   input.proof_vk            verification key the submitted proof used
 *   input.minimum             minimum balance the statement requires
 *   input.public_balance      balance proven by the statement
 *   input.expiry_block        block after which the statement expires
 *   input.current_block       block the statement was evaluated at
 *   input.recipient           recipient of the transfer
 *   input.condition_recipient recipient the condition requires
 *   input.amount              transfer amount
 *   input.max_transfer        maximum allowed transfer
 *   input.proof_tx            reference of the submitted proof
 */

export interface GatekeeperInput {
  registered_vk: string;
  proof_vk: string;
  minimum: string;
  public_balance: string;
  expiry_block: number;
  current_block: number;
  recipient: string;
  condition_recipient: string;
  amount: string;
  max_transfer: string;
  proof_tx: string;
}

export interface GatekeeperTask {
  type: string;
  task_id: string;
  mode?: string;
  issued_at?: string;
  deadline_at?: string;
  input: GatekeeperInput;
}

export type Decision = "APPROVE" | "REJECT";

export type ReasonCode =
  | "ALL_CHECKS_PASSED"
  | "VK_SUBSTITUTION"
  | "INSUFFICIENT_BALANCE"
  | "PROOF_EXPIRED"
  | "RECIPIENT_MISMATCH"
  | "AMOUNT_EXCEEDS_LIMIT"
  | "PROOF_REUSED"
  | "TASK_EXPIRED"
  | "INTERNAL_TIMEOUT"
  | "PROOF_FAILED";

export interface DecisionResult {
  decision: Decision;
  reason_code: ReasonCode;
  failedChecks: string[];
}

function sameAddress(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/**
 * Evaluate the task against the security checklist.
 * `usedProofs` tracks proof_tx values already answered, so a proof
 * reference can never be spent twice. Returns the first failing
 * reason code (checks run in checklist order).
 */
export function evaluateGatekeeper(
  task: GatekeeperTask,
  usedProofs: ReadonlySet<string>,
): DecisionResult {
  const input = task.input;
  const failedChecks: string[] = [];

  // 1. The task must still be inside its deadline.
  if (task.deadline_at && Date.now() > Date.parse(task.deadline_at)) {
    failedChecks.push("deadline");
    return { decision: "REJECT", reason_code: "TASK_EXPIRED", failedChecks };
  }

  // 2. The proof must use the verification key registered for this condition.
  if (!sameAddress(input.proof_vk, input.registered_vk)) {
    failedChecks.push("vk");
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", failedChecks };
  }

  // 3. Public inputs must prove the required threshold.
  if (BigInt(input.public_balance) < BigInt(input.minimum)) {
    failedChecks.push("balance");
    return { decision: "REJECT", reason_code: "INSUFFICIENT_BALANCE", failedChecks };
  }

  // 4. The statement must not be expired at the evaluation block.
  if (input.current_block > input.expiry_block) {
    failedChecks.push("expiry");
    return { decision: "REJECT", reason_code: "PROOF_EXPIRED", failedChecks };
  }

  // 5. The recipient must be exactly the one the condition requires.
  if (!sameAddress(input.recipient, input.condition_recipient)) {
    failedChecks.push("recipient");
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", failedChecks };
  }

  // 6. The amount must not exceed the allowed maximum.
  if (BigInt(input.amount) > BigInt(input.max_transfer)) {
    failedChecks.push("amount");
    return { decision: "REJECT", reason_code: "AMOUNT_EXCEEDS_LIMIT", failedChecks };
  }

  // 7. A proof reference must never be reused for another task.
  if (usedProofs.has(input.proof_tx.toLowerCase())) {
    failedChecks.push("reuse");
    return { decision: "REJECT", reason_code: "PROOF_REUSED", failedChecks };
  }

  return { decision: "APPROVE", reason_code: "ALL_CHECKS_PASSED", failedChecks };
}

import { createHash } from "node:crypto";

const FIELD_PRIME = BigInt("2188824287183927522224640577328159286182216822726122852853824775429379122115");

function toFieldElement(value: string): string {
  if (/^(0x[0-9a-fA-F]+|[0-9]+)$/.test(value)) { return (BigInt(value) % FIELD_PRIME).toString(); }
  const digest = createHash("sha256").update(value, "utf8").digest("hex");
  return (BigInt(`0x${digest}`) % FIELD_PRIME).toString();
}

/**
 * Build the public inputs for the gatekeeper Groth16 circuit.
 *
 * The circuit proves that the returned decision follows the rules above
 * for the exact statement in the task. Signal names must match the
 * published gatekeeper circuit — if the circuit source uses different
 * names, update this mapping (and only this mapping) to match it.
 */
export function buildCircuitInput(
  task: GatekeeperTask,
  decision: Decision,
): Record<string, unknown> {
  const input = task.input;
  return {
    // Public inputs — the platform re-verifies the proof against these.
    registeredVkHash: input.registered_vk,
    proofVkHash: input.proof_vk,
    minimum: input.minimum,
    publicBalance: input.public_balance,
    expiryBlock: input.expiry_block,
    currentBlock: input.current_block,
    recipient: input.recipient,
    conditionRecipient: input.condition_recipient,
    amount: input.amount,
    maxTransfer: input.max_transfer,
    // 1 = APPROVE, 0 = REJECT
    decision: decision === "APPROVE" ? "1" : "0",
    taskId: toFieldElement(task.task_id),
    salt: toFieldElement(`${task.task_id}:${input.proof_tx}`),
  };
}
