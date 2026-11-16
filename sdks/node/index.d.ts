export type RedactionModeType = 'placeholder' | 'synthetic' | 'mask';

export interface VeilOptions {
  mode?: RedactionModeType;
  binPath?: string;
  proxyUrl?: string;
}

export interface RedactResult {
  sanitized: string;
  matches: string[];
  vault: Vault;
}

export declare class Vault {
  constructor();
  set(placeholder: string, realValue: string): void;
  get(placeholder: string): string | undefined;
  restore(text: string): string;
  clear(): void;
  readonly size: number;
}

export declare class StreamingRestorer {
  constructor(vault: Vault);
  push(chunk: string): string;
  finish(): string;
}

export declare class Veil {
  constructor(options?: VeilOptions);
  mode: RedactionModeType;
  binPath: string;
  proxyUrl: string;
  vault: Vault;

  redact(text: string): RedactResult;
  restore(text: string): string;
  createStreamingRestorer(): StreamingRestorer;
  restoreStream(asyncChunkIterable: AsyncIterable<string>): AsyncGenerator<string, void, unknown>;
}

export declare const RedactionMode: {
  readonly PLACEHOLDER: 'placeholder';
  readonly SYNTHETIC: 'synthetic';
  readonly MASK: 'mask';
};
