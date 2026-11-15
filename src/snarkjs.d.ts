/**
 * Minimal TypeScript declarations for snarkjs.
 *
 * snarkjs ships without bundled type definitions, so this file describes
 * the small part of its API this project uses (Groth16 fullProve).
 * If a future snarkjs release ships its own types, this file can be
 * deleted.
 */

declare module "snarkjs" {
  export const groth16: {
    fullProve: (
      input: unknown,
      wasmFile: string,
      zkeyFilePath: string,
    ) => Promise<{ proof: unknown; publicSignals: string[] }>;
  };
}
