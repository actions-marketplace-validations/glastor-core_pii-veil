/* tslint:disable */
/* eslint-disable */

/**
 * Stateful engine holding a persistent vault for multi-turn chats or streaming chunks.
 */
export class WasmVeil {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Exports the current vault as a JSON string.
     */
    export_vault_json(): string;
    constructor(mode?: string | null);
    /**
     * Redacts text using the persistent vault.
     */
    redact(text: string): string;
    /**
     * Resets the persistent vault.
     */
    reset_vault(): void;
    /**
     * Restores text back using the current persistent vault.
     */
    restore(text: string): string;
}

/**
 * Redacts sensitive PII and secrets in `text`.
 *
 * Returns an object: `{ text: string, spans_found: number, vault_json: string, entries: Array<VaultEntry> }`.
 */
export function redact(text: string, mode?: string | null): any;

/**
 * Restores sanitized text back to original values using the serialized JSON vault.
 */
export function restore(sanitized_text: string, vault_json: string): string;

/**
 * Scans text for PII/secrets without modifying it.
 * Returns an array of detected spans.
 */
export function scan(text: string): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasmveil_free: (a: number, b: number) => void;
    readonly redact: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly restore: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly scan: (a: number, b: number) => [number, number, number];
    readonly wasmveil_export_vault_json: (a: number) => [number, number, number, number];
    readonly wasmveil_new: (a: number, b: number) => number;
    readonly wasmveil_redact: (a: number, b: number, c: number) => [number, number];
    readonly wasmveil_reset_vault: (a: number) => void;
    readonly wasmveil_restore: (a: number, b: number, c: number) => [number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
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
