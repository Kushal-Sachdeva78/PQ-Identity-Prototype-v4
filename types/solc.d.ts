declare module "solc" {
  export interface SolcCompileOutput {
    errors?: Array<{
      severity: string;
      formattedMessage: string;
      type: string;
    }>;
    contracts?: Record<
      string,
      Record<
        string,
        {
          abi: unknown[];
          evm: { bytecode: { object: string } };
        }
      >
    >;
  }
  export function compile(input: string): string;
  export function version(): string;
  const solc: { compile: typeof compile; version: typeof version };
  export default solc;
}
