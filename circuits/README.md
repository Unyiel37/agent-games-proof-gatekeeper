# Circuit artifacts

This directory holds the Groth16 proving artifacts for the Proof Gatekeeper
circuit. They are **not committed** to this repository — download them from
the artifacts section of the official Agent Games build guide and place
them here before running the agent:

```
circuits/
  gatekeeper.wasm        # compiled circuit (Circom 2.x, Groth16 / BN128)
  gatekeeper_final.zkey  # proving key
```

The verification-key hash registered on zkVerify mainnet for this circuit is
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
(see `REGISTERED_VK_HASH` in `.env.example`).

Paths are configurable via `CIRCUIT_WASM_PATH` and `CIRCUIT_ZKEY_PATH`.
