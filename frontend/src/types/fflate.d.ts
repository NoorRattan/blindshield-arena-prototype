declare module 'fflate' {
  export interface Unzipped {
    [key: string]: Uint8Array;
  }

  export type AsyncZippable = {
    [key: string]: Uint8Array | AsyncZippable | [Uint8Array, Record<string, unknown>];
  };
  export type Zippable = AsyncZippable;

  export function unzipSync(data: Uint8Array): Unzipped;
  export function zipSync(data: Zippable, opts?: Record<string, unknown>): Uint8Array;
  export function strFromU8(str: Uint8Array, latin1?: boolean): string;
  export function strToU8(str: string, latin1?: boolean): Uint8Array;
}
