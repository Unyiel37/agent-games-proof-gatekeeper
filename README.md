# agent-games-proof-gatekeeper

Proof Gatekeeper agent for [zkVerify Agent Games](https://agentgames.zkverify.io) — a verifiable AI agent that judges proof-backed payment requests and returns a Groth16 zero-knowledge proof of every approval.

Registered for Agent Games as **BOSQU99-GATEKEEPER** (handle `@bosqu99`, GitHub `Unyiel37`).

## How it works

1. The Agent Games task service POSTs a signed JSON envelope to `POST /agent`.
2. The agent verifies the HMAC-SHA256 signature over the **raw** request body (`x-agent-games-signature`) before parsing anything.
3. Deterministic rules decide `APPROVE` or `REJECT` — the agent approves only when every check passes:
   - the proof's verification key matches the registered key (otherwise `VK_SUBSTITUTION`)
   - the proven public balance meets the required minimum
   - the statement has not expired at the evaluation block
   - the recipient is exactly the one the condition requires
   - the amount does not exceed the maximum transfer
   - the proof reference has not been used before
   - the task is still inside its deadline
4. For approvals, a Groth16 proof is generated locally with `snarkjs` and the gatekeeper circuit, submitted to zkVerify via Kurier when configured, and returned with its public signals.
5. Every response is signed with `x-agent-games-signature` over the raw response body.
6. Any error, timeout, or uncertainty fails closed to `REJECT`.

## Scoring (Proof Gatekeeper)

+12 correct decision · −6 approving a trap · −3 rejecting a valid request · −2 timeout/offline · −2 proof fails to verify — plus a reliability bonus, over 8 daily rounds.

## Setup

```bash
npm install
npm run build
```

### Environment

Copy `.env.example` to `.env` and fill it in:

| Variable | Description |
| --- | --- |
| `PORT` | HTTP port (default `3000`) |
| `AGENT_GAMES_HMAC_SECRET` | One-time secret from the Agent Games dashboard (Rotate Secret). Required. |
| `KURIER_API_KEY` | Kurier mainnet API key for zkVerify submission. Optional — without it, the agent returns the locally generated proof without an on-chain submission. |
| `KURIER_STATUS_URL` | Optional override for the Kurier job-status endpoint. |
| `CIRCUIT_WASM_PATH` | Path to `gatekeeper.wasm` (default `./circuits/gatekeeper.wasm`) |
| `CIRCUIT_ZKEY_PATH` | Path to `gatekeeper_final.zkey` (default `./circuits/gatekeeper_final.zkey`) |
| `REGISTERED_VK_HASH` | Gatekeeper verification-key hash registered on zkVerify mainnet (default `0x6b79…77b0`) |

Never commit `.env` or any secret. See `.env.example`.

### Circuit artifacts

Place `gatekeeper.wasm` and `gatekeeper_final.zkey` in `circuits/` (download them from the artifacts section of the official Agent Games build guide). They are proving keys and are intentionally not committed to this repo.

## Run

```bash
npm start          # production: node dist/server.js
npm run dev        # development: tsx watch src/server.ts
```

Health check: `GET /health`.

## Test locally

```bash
AGENT_GAMES_HMAC_SECRET=test-secret npm run dev   # terminal 1
AGENT_GAMES_HMAC_SECRET=test-secret npm test      # terminal 2
```

The harness replays a valid request, a VK-substitution trap, an expired statement, and the preflight handshake. Proof generation needs the circuit artifacts in `circuits/`; without them, approvals fail closed to `REJECT / PROOF_FAILED`, while trap decisions still return their real reason codes.

## Deploy

Deploy behind HTTPS (e.g. Fly.io, Render, Railway) and register the full handler path as the endpoint — `https://<host>/agent`, not the bare domain. Then, on the Agent Games dashboard: rotate the agent secret, set it as `AGENT_GAMES_HMAC_SECRET`, restart, and run preflight — it must pass before the platform marks the agent active.

## Security

- Secrets come from environment variables only; `.env` is git-ignored.
- HMAC is verified over the raw body before any parsing.
- Deterministic code makes the final call — no model output decides an approval.
- Timeouts and errors fail closed to `REJECT`.
- Responses are signed over the raw response body.
