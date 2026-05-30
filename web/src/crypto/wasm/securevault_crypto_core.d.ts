/* tslint:disable */
/* eslint-disable */

export class WasmKdfParams {
    free(): void;
    [Symbol.dispose](): void;
    constructor(iterations: number, memory_kib: number, parallelism: number);
}

export function wasm_decrypt_entry(vault_key_b64: string, encrypted_data: string, iv: string): string;

export function wasm_decrypt_field(vault_key_b64: string, ciphertext: string): string;

export function wasm_derive_auth_hash(password: string, salt_str: string, p: WasmKdfParams): string;

export function wasm_derive_kek(password: string, salt_b64: string, p: WasmKdfParams): string;

export function wasm_encrypt_entry(vault_key_b64: string, plaintext_json: string): string;

export function wasm_encrypt_field(vault_key_b64: string, plaintext: string): string;

export function wasm_generate_salt(): string;

export function wasm_generate_vault_key(): string;

export function wasm_unwrap_vault_key(kek_b64: string, wrapped_b64: string): string;

export function wasm_wrap_vault_key(kek_b64: string, vault_key_b64: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasmkdfparams_free: (a: number, b: number) => void;
    readonly wasm_decrypt_entry: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly wasm_decrypt_field: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly wasm_derive_auth_hash: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly wasm_derive_kek: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly wasm_encrypt_entry: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly wasm_encrypt_field: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly wasm_generate_salt: () => [number, number, number, number];
    readonly wasm_generate_vault_key: () => [number, number];
    readonly wasm_unwrap_vault_key: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly wasm_wrap_vault_key: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly wasmkdfparams_new: (a: number, b: number, c: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
